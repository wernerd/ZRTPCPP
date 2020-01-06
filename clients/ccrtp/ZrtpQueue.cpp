/*
  Copyright (C) 2006-2009 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <string>
#include <cstdio>
#include <memory>

#include <ZrtpQueue.h>
#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpStateClass.h>
#include <libzrtpcpp/ZrtpUserCallback.h>
#include <zrtp/libzrtpcpp/ZIDCacheFile.h>
#include <common/ZrtpTimeoutProvider.h>
#include "../logging/ZrtpLogging.h"

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"
static zrtp::ZrtpTimeoutProvider *staticTimeoutProvider = nullptr;

NAMESPACE_COMMONCPP
using namespace GnuZrtpCodes;

    std::shared_ptr<ZIDCache> ZrtpQueue::zrtpCache = nullptr;

// Specific initialization for ccrtp: use _one_ ZRTP cache file for _all_ sessions, even
// for conference calls. This simplifies handling of cache data.
// If another app likes to have different cache files (or even open the same file several times ? )
// then just change the cache initialization at his point.
    static std::shared_ptr<ZIDCache>
    initCache(const char *zidFilename, std::shared_ptr<ZIDCache> cache) {
        std::string fname;
        if (!zidFilename) {
            char *home = getenv("HOME");
            std::string baseDir = (home) ? (std::string(home) + std::string("/."))
                                         : std::string(".");
            fname = baseDir + std::string("GNUZRTP.zid");
            zidFilename = fname.c_str();
        }

        // Check if a cache is available.
        // If yes and it has the same filename -> use it
        // otherwise close file and open new cache file
        if (cache) {
            if (cache->getFileName() == zidFilename) {
                return cache;
            }
            cache->close();
            if (cache->open((char *)zidFilename) < 0) {
                return std::shared_ptr<ZIDCache>();
            }
            return cache;
        }

        auto zf = std::make_shared<ZIDCacheFile>();
        if (zf->open((char *)zidFilename) < 0) {
            return std::shared_ptr<ZIDCache>();
        }
        return zf;
    }

ZrtpQueue::ZrtpQueue(uint32 size, RTPApplication& app) :
        AVPQueue(size,app), clientIdString(clientId)
{
    init();
}

ZrtpQueue::ZrtpQueue(uint32 ssrc, uint32 size, RTPApplication& app) :
        AVPQueue(ssrc,size,app), clientIdString(clientId)
{
    init();
}

void ZrtpQueue::init()
{
    zrtpUserCallback = nullptr;
    enableZrtp = false;
    started = false;
    mitmMode = false;
    enableParanoidMode = false;
    zrtpEngine = nullptr;
    senderZrtpSeqNo = 1;

    clientIdString = clientId;
    peerSSRC = 0;
}

ZrtpQueue::~ZrtpQueue() {

    endQueue();
    stopZrtp();

    if (zrtpUserCallback != nullptr) {
        delete zrtpUserCallback;
        zrtpUserCallback = nullptr;
    }
}

int32_t
ZrtpQueue::initialize(const char *zidFilename, bool autoEnable, std::shared_ptr<ZrtpConfigure>& config)
{
    int32_t ret = 1;

    synchEnter();

    std::shared_ptr<ZrtpConfigure> configOwn;

    if (!config) {
        auto zf = initCache(zidFilename, zrtpCache);
        if (!zf) {
            return -1;
        }
        if (!zrtpCache) {
            zrtpCache = zf;
        }

        configOwn = std::make_shared<ZrtpConfigure>();
        configOwn->setZidCache(zf);
        configOwn->setStandardConfig();
    }
    else {
        configOwn = config;
    }

    enableZrtp = autoEnable;

    configOwn->setParanoidMode(enableParanoidMode);

    if (staticTimeoutProvider == nullptr) {
        staticTimeoutProvider = new zrtp::ZrtpTimeoutProvider();
    }
    const uint8_t* ownZidFromCache = configOwn->getZidCache()->getZid();

    zrtpEngine = new ZRtp((uint8_t*)ownZidFromCache, *(ZrtpCallback*)this, clientIdString, configOwn, mitmMode, signSas);

    synchLeave();
    return ret;
}

void ZrtpQueue::startZrtp() {
    if (zrtpEngine != nullptr) {
        zrtpEngine->startZrtpEngine();
        zrtpUnprotect = 0;
        started = true;
    }
}

void ZrtpQueue::stopZrtp() {
    if (zrtpEngine != nullptr) {
        if (zrtpUnprotect < 50 && !zrtpEngine->isMultiStream())
            zrtpEngine->setRs2Valid();
        delete zrtpEngine;
        zrtpEngine = nullptr;
        started = false;
    }
}

/*
 * The takeInDataPacket implementation for ZRTPQueue.
 */
size_t
ZrtpQueue::takeInDataPacket()
{
    InetHostAddress network_address;
    tpport_t transport_port;

    // Reduce this to int32_t: the call function uses an ioctl(..., FIONREAD, &num) where num in of size_t
    // and returns this num. Somehow this is wrong: I assume the Linux kernel (and maybe others) expects
    // a 4 bytes int (int32_t) instead of an 8-byte size_t (on 64bit CPUs). Fortunately the case cuts of
    // the upper part
    auto nextSize = static_cast<int32_t>(getNextDataPacketSize());
    auto buffer = new unsigned char[nextSize];
    auto rtn = recvData(buffer, nextSize, network_address, transport_port);
    if ( rtn > getMaxRecvPacketSize() ){
        delete[] buffer;
        return 0;
    }

    IncomingZRTPPkt* packet = nullptr;
    // check if this could be a real RTP/SRTP packet.
    if ((*buffer & 0xf0U) != 0x10) {
        return (rtpDataPacket(buffer, rtn, network_address, transport_port));
    }

    // We assume all other packets are ZRTP packets here. Process
    // if ZRTP processing is enabled. Because valid RTP packets are
    // already handled we delete any packets here after processing.
    if (enableZrtp && zrtpEngine != nullptr) {
        // Fixed header length + smallest ZRTP packet (includes CRC)
        if (rtn < (int32)(12 + sizeof(HelloAckPacket_t))) // data too small, dismiss
            return 0;

        // Get CRC value into crc (see above how to compute the offset)
        uint16_t temp = rtn - CRC_SIZE;
        uint32_t crc = *(uint32_t*)(buffer + temp);
        crc = ntohl(crc);

        if (!zrtpCheckCksum(buffer, temp, crc)) {
            delete[] buffer;
            if (zrtpUserCallback != nullptr)
                zrtpUserCallback->showMessage(Warning, WarningCRCmismatch);
            return 0;
        }

        packet = new IncomingZRTPPkt(buffer,rtn);

        uint32 magic = packet->getZrtpMagic();

        // Check if it is really a ZRTP packet, if not delete it and return 0
        if (magic != ZRTP_MAGIC || zrtpEngine == nullptr) {
            delete packet;
            return 0;
        }
        // cover the case if the other party sends _only_ ZRTP packets at the
        // beginning of a session. Start ZRTP in this case as well.
        if (!started) {
            startZrtp();
         }
        // this now points beyond the undefined and length field.
        // We need them, thus adjust
        auto* extHeader =
                const_cast<unsigned char*>(packet->getHdrExtContent());
        extHeader -= 4;

        // store peer's SSRC, used when creating the CryptoContext
        peerSSRC = packet->getSSRC();
        zrtpEngine->processZrtpMessage(extHeader, peerSSRC, rtn);
    }
    delete packet;
    return 0;
}

size_t
ZrtpQueue::rtpDataPacket(unsigned char* buffer, int32 rtn, InetHostAddress network_address, tpport_t transport_port)
{
     // Special handling of padding to take care of encrypted content.
    // In case of SRTP the padding length field is also encrypted, thus
    // it gives a wrong length. Check and clear padding bit before
    // creating the RTPPacket. Will be set and re-computed after a possible
    // SRTP decryption.
    uint8 padSet = (*buffer & 0x20U);
    if (padSet) {
        *buffer = *buffer & ~0x20U;          // clear padding bit
    }
    //  build a packet. It will link itself to its source
    auto* packet = new IncomingRTPPkt(buffer, rtn);

    // Generic header validity check.
    if ( !packet->isHeaderValid() ) {
        delete packet;
        return 0;
    }

    // Look for a CryptoContext for this packet's SSRC
    CryptoContext* pcc = getInQueueCryptoContext(packet->getSSRC());

    // If no crypto context is available for this SSRC but we are already in
    // Secure state then create a CryptoContext for this SSRC.
    // Assumption: every SSRC stream sent via this connection is secured
    // _and_ uses the same crypto parameters.
    if (pcc == nullptr) {
        pcc = getInQueueCryptoContext(0);
        if (pcc != nullptr) {
            pcc = pcc->newCryptoContextForSSRC(packet->getSSRC(), 0, 0L);
            if (pcc != nullptr) {
                pcc->deriveSrtpKeys(0);
                setInQueueCryptoContext(pcc);
            }
        }
    }
    // If no crypto context: then either ZRTP is off or in early state
    // If crypto context is available then unprotect data here. If an error
    // occurs report the error and discard the packet.
    if (pcc != nullptr) {
        int32 ret;
        if ((ret = packet->unprotect(pcc)) < 0) {
            if (!onSRTPPacketError(*packet, ret)) {
                delete packet;
                return 0;
            }
        }
        if (started && zrtpEngine->inState(WaitConfAck)) {
            zrtpEngine->conf2AckSecure();
        }
    }

    // virtual for profile-specific validation and processing.
    if (!onRTPPacketRecv(*packet) ) {
        delete packet;
        return 0;
    }
    if (padSet) {
        packet->reComputePayLength(true);
    }
    // get time of arrival
    struct timeval recvtime{};
    gettimeofday(&recvtime,nullptr);

    bool source_created;
    SyncSourceLink* sourceLink =
            getSourceBySSRC(packet->getSSRC(),source_created);
    SyncSource* s = sourceLink->getSource();
    if ( source_created ) {
        // Set data transport address.
        setDataTransportPort(*s,transport_port);
        // Network address is assumed to be the same as the control one
        setNetworkAddress(*s,network_address);
        sourceLink->initStats();
        // First packet arrival time.
        sourceLink->setInitialDataTime(recvtime);
        sourceLink->setProbation(getMinValidPacketSequence());
        if ( sourceLink->getHello() )
            onNewSyncSource(*s);
    }
    else if ( 0 == s->getDataTransportPort() ) {
        // Test if RTCP packets had been received but this is the
        // first data packet from this source.
        setDataTransportPort(*s,transport_port);
    }

    // Before inserting in the queue,
    // 1) check for collisions and loops. If the packet cannot be
    //    assigned to a source, it will be rejected.
    // 2) check the source is a sufficiently well known source
    // TODO: also check CSRC identifiers.
    if (checkSSRCInIncomingRTPPkt(*sourceLink, source_created,
        network_address, transport_port) &&
        recordReception(*sourceLink,*packet,recvtime) ) {
        // now the packet link is linked in the queues
        auto* packetLink = new IncomingRTPPktLink(packet, sourceLink, recvtime,
                                       packet->getTimestamp() - sourceLink->getInitialDataTimestamp(),
                                       nullptr,nullptr,nullptr,nullptr);
        insertRecvPacket(packetLink);
    } else {
        // must be discarded due to collision or loop or
        // invalid source
        delete packet;
        return 0;
    }
    // Start the ZRTP engine after we got a at least one RTP packet and
    // sent some as well or we are in multi-stream mode.
    if (!started && enableZrtp) {
        startZrtp();
    }
    return rtn;
}

bool
ZrtpQueue::onSRTPPacketError(IncomingRTPPkt& pkt, int32 errorCode)
{
    if (errorCode == -1) {
        sendInfo(Warning, WarningSRTPauthError);
    }
    else {
        sendInfo(Warning, WarningSRTPreplayError);
    }
    return false;
}


void
ZrtpQueue::putData(uint32 stamp, const unsigned char* data, size_t len)
{
    OutgoingDataQueue::putData(stamp, data, len);
}


void
ZrtpQueue::sendImmediate(uint32 stamp, const unsigned char* data, size_t len)
{
    OutgoingDataQueue::sendImmediate(stamp, data, len);
}


/*
 * Here the callback methods required by the ZRTP implementation
 */
int32_t ZrtpQueue::sendDataZRTP(const unsigned char *data, int32_t length) {

    auto* packet = new OutgoingZRTPPkt(data, length);

    packet->setSSRC(getLocalSSRC());

    packet->setSeqNum(senderZrtpSeqNo++);

    /*
     * Compute the ZRTP CRC over the full ZRTP packet. Thus include
     * the fixed packet header into the calculation.
     */
    uint16_t temp = packet->getRawPacketSize() - CRC_SIZE;
    auto* pt = packet->getRawPacket();
    uint32_t crc = zrtpGenerateCksum(pt, temp);
    // convert and store CRC in crc field of ZRTP packet.
    crc = zrtpEndCksum(crc);

    // advance pointer to CRC storage
    pt += temp;
    *(uint32_t*)pt = htonl(crc);

    dispatchImmediate(packet);
    delete packet;

    return 1;
}

bool ZrtpQueue::srtpSecretsReady(SrtpSecret_t* secrets, EnableSecurity part)
{
    CryptoContext* recvCryptoContext;
    CryptoContext* senderCryptoContext;
    CryptoContextCtrl* recvCryptoContextCtrl;
    CryptoContextCtrl* senderCryptoContextCtrl;

    int cipher = SrtpEncryptionNull;
    int authn = SrtpAuthenticationNull;
    int authKeyLen = 0;

    if (secrets->authAlgorithm == Sha1) {
        authn = SrtpAuthenticationSha1Hmac;
        authKeyLen = 20;
    }

    if (secrets->authAlgorithm == Skein) {
        authn = SrtpAuthenticationSkeinHmac;
        authKeyLen = 32;
    }

    if (secrets->symEncAlgorithm == Aes)
        cipher = SrtpEncryptionAESCM;

    if (secrets->symEncAlgorithm == TwoFish)
        cipher = SrtpEncryptionTWOCM;

    if (part == ForSender) {
        // To encrypt packets: intiator uses initiator keys,
        // responder uses responder keys
        // Create a "half baked" crypto context first and store it. This is
        // the main crypto context for the sending part of the connection.
        if (secrets->role == Initiator) {
            senderCryptoContext = new CryptoContext(
                    0,
                    0,
                    0L,                                      // keyderivation << 48,
                    cipher,                                  // encryption algo
                    authn,                                   // authtentication algo
                    (unsigned char*)secrets->keyInitiator,   // Master Key
                    secrets->initKeyLen / 8,                 // Master Key length
                    (unsigned char*)secrets->saltInitiator,  // Master Salt
                    secrets->initSaltLen / 8,                // Master Salt length
                    secrets->initKeyLen / 8,                 // encryption keyl
                    authKeyLen,                              // authentication key len
                    secrets->initSaltLen / 8,                // session salt len
                    secrets->srtpAuthTagLen / 8);            // authentication tag lenA
            senderCryptoContextCtrl = new CryptoContextCtrl(0,
                  cipher,                                    // encryption algo
                  authn,                                     // authtication algo
                  (unsigned char*)secrets->keyInitiator,     // Master Key
                  secrets->initKeyLen / 8,                   // Master Key length
                  (unsigned char*)secrets->saltInitiator,    // Master Salt
                  secrets->initSaltLen / 8,                  // Master Salt length
                  secrets->initKeyLen / 8,                   // encryption keyl
                  authKeyLen,                                // authentication key len
                  secrets->initSaltLen / 8,                  // session salt len
                  secrets->srtpAuthTagLen / 8);              // authentication tag len
        }
        else {
            senderCryptoContext = new CryptoContext(
                    0,
                    0,
                    0L,                                      // keyderivation << 48,
                    cipher,                                  // encryption algo
                    authn,                                   // authtentication algo
                    (unsigned char*)secrets->keyResponder,   // Master Key
                    secrets->respKeyLen / 8,                 // Master Key length
                    (unsigned char*)secrets->saltResponder,  // Master Salt
                    secrets->respSaltLen / 8,                // Master Salt length
                    secrets->respKeyLen / 8,                 // encryption keyl
                    authKeyLen,                              // authentication key len
                    secrets->respSaltLen / 8,                // session salt len
                    secrets->srtpAuthTagLen / 8);            // authentication tag len
            senderCryptoContextCtrl = new CryptoContextCtrl(0,
                  cipher,                                    // encryption algo
                  authn,                                     // authtication algo
                  (unsigned char*)secrets->keyResponder,     // Master Key
                  secrets->respKeyLen / 8,                   // Master Key length
                  (unsigned char*)secrets->saltResponder,    // Master Salt
                  secrets->respSaltLen / 8,                  // Master Salt length
                  secrets->respKeyLen / 8,                   // encryption keyl
                  authKeyLen,                                // authentication key len
                  secrets->respSaltLen / 8,                  // session salt len
                  secrets->srtpAuthTagLen / 8);              // authentication tag len
        }
        // Insert the Crypto templates (SSRC == 0) into the queue. When we send
        // the first RTP or RTCP packet the real crypto context will be created.
        // Refer to putData(), sendImmediate() in ccrtp's outqueue.cpp and
        // takeinControlPacket() in ccrtp's control.cpp.
        //
         setOutQueueCryptoContext(senderCryptoContext);
         setOutQueueCryptoContextCtrl(senderCryptoContextCtrl);
    }
    if (part == ForReceiver) {
        // To decrypt packets: intiator uses responder keys,
        // responder initiator keys
        // See comment above.
        if (secrets->role == Initiator) {
            recvCryptoContext = new CryptoContext(
                    0,
                    0,
                    0L,                                      // keyderivation << 48,
                    cipher,                                  // encryption algo
                    authn,                                   // authtentication algo
                    (unsigned char*)secrets->keyResponder,   // Master Key
                    secrets->respKeyLen / 8,                 // Master Key length
                    (unsigned char*)secrets->saltResponder,  // Master Salt
                    secrets->respSaltLen / 8,                // Master Salt length
                    secrets->respKeyLen / 8,                 // encryption keyl
                    authKeyLen,                              // authentication key len
                    secrets->respSaltLen / 8,                // session salt len
                    secrets->srtpAuthTagLen / 8);            // authentication tag len
            recvCryptoContextCtrl = new CryptoContextCtrl(0,
                  cipher,                                    // encryption algo
                  authn,                                     // authtication algo
                  (unsigned char*)secrets->keyResponder,     // Master Key
                  secrets->respKeyLen / 8,                   // Master Key length
                  (unsigned char*)secrets->saltResponder,    // Master Salt
                  secrets->respSaltLen / 8,                  // Master Salt length
                  secrets->respKeyLen / 8,                   // encryption keyl
                  authKeyLen,                                // authentication key len
                  secrets->respSaltLen / 8,                  // session salt len
                  secrets->srtpAuthTagLen / 8);              // authentication tag len

        }
        else {
            recvCryptoContext = new CryptoContext(
                    0,
                    0,
                    0L,                                      // keyderivation << 48,
                    cipher,                                  // encryption algo
                    authn,                                   // authtentication algo
                    (unsigned char*)secrets->keyInitiator,   // Master Key
                    secrets->initKeyLen / 8,                 // Master Key length
                    (unsigned char*)secrets->saltInitiator,  // Master Salt
                    secrets->initSaltLen / 8,                // Master Salt length
                    secrets->initKeyLen / 8,                 // encryption keyl
                    authKeyLen,                              // authentication key len
                    secrets->initSaltLen / 8,                // session salt len
                    secrets->srtpAuthTagLen / 8);            // authentication tag len
            recvCryptoContextCtrl = new CryptoContextCtrl(0,
                  cipher,                                    // encryption algo
                  authn,                                     // authtication algo
                  (unsigned char*)secrets->keyInitiator,     // Master Key
                  secrets->initKeyLen / 8,                   // Master Key length
                  (unsigned char*)secrets->saltInitiator,    // Master Salt
                  secrets->initSaltLen / 8,                  // Master Salt length
                  secrets->initKeyLen / 8,                   // encryption keyl
                  authKeyLen,                                // authentication key len
                  secrets->initSaltLen / 8,                  // session salt len
                  secrets->srtpAuthTagLen / 8);              // authentication tag len
        }
        // Insert the Crypto templates (SSRC == 0) into the queue. When we receive
        // the first RTP or RTCP packet the real crypto context will be created.
        // Refer to rtpDataPacket() above and takeinControlPacket in ccrtp's control.cpp.
        //
        setInQueueCryptoContext(recvCryptoContext);
        setInQueueCryptoContextCtrl(recvCryptoContextCtrl);
    }
    return true;
}

void ZrtpQueue::srtpSecretsOn(std::string c, std::string s, bool verified)
{

  if (zrtpUserCallback != nullptr) {
    zrtpUserCallback->secureOn(c);
    if (!s.empty()) {
        zrtpUserCallback->showSAS(s, verified);
    }
  }
}

void ZrtpQueue::srtpSecretsOff(EnableSecurity part) {
    if (part == ForSender) {
        removeOutQueueCryptoContext(nullptr);
        removeOutQueueCryptoContextCtrl(nullptr);
    }
    if (part == ForReceiver) {
        removeInQueueCryptoContext(nullptr);
        removeInQueueCryptoContextCtrl(nullptr);
    }
    if (zrtpUserCallback != nullptr) {
        zrtpUserCallback->secureOff();
    }
}

int32_t ZrtpQueue::activateTimer(int32_t time) {
    if (staticTimeoutProvider != nullptr) {
        if (timeoutId != -1) {
            LOGGER(ERROR_LOG, "Duplicate timeout detected, old timeout removed: ", timeoutId)
            staticTimeoutProvider->removeTimer(timeoutId);
        }
        timeoutId = staticTimeoutProvider->addTimer(time, 0x776469,
                [this](uint64_t) {
                    timeoutId = -1;
                    if (zrtpEngine != nullptr) {
                        zrtpEngine->processTimeout();
                    }
                });
    }
    return 1;
}

int32_t ZrtpQueue::cancelTimer() {
    if (staticTimeoutProvider != nullptr && timeoutId >= 0) {
        staticTimeoutProvider->removeTimer(timeoutId);
        timeoutId = -1;
    }
    return 1;
}

void ZrtpQueue::handleGoClear()
{
    fprintf(stderr, "Need to process a GoClear message!");
}

void ZrtpQueue::sendInfo(MessageSeverity severity, int32_t subCode) {
    if (zrtpUserCallback != nullptr) {
        zrtpUserCallback->showMessage(severity, subCode);
    }
}

void ZrtpQueue::zrtpNegotiationFailed(MessageSeverity severity, int32_t subCode) {
    if (zrtpUserCallback != nullptr) {
        zrtpUserCallback->zrtpNegotiationFailed(severity, subCode);
    }
}

void ZrtpQueue::zrtpNotSuppOther() {
    if (zrtpUserCallback != nullptr) {
        zrtpUserCallback->zrtpNotSuppOther();
    }
}

void ZrtpQueue::synchEnter() {
    syncLock.lock();
}

void ZrtpQueue::synchLeave() {
    syncLock.unlock();
}

void ZrtpQueue::zrtpAskEnrollment(GnuZrtpCodes::InfoEnrollment  info) {
    if (zrtpUserCallback != nullptr) {
        zrtpUserCallback->zrtpAskEnrollment(info);
    }
}

void ZrtpQueue::zrtpInformEnrollment(GnuZrtpCodes::InfoEnrollment  info) {
    if (zrtpUserCallback != nullptr) {
        zrtpUserCallback->zrtpInformEnrollment(info);
    }
}

void ZrtpQueue::signSAS(uint8_t* sasHash) {
    if (zrtpUserCallback != nullptr) {
        zrtpUserCallback->signSAS(sasHash);
    }
}

bool ZrtpQueue::checkSASSignature(uint8_t* sasHash) {
    if (zrtpUserCallback != nullptr) {
        return zrtpUserCallback->checkSASSignature(sasHash);
    }
    return false;
}

void ZrtpQueue::setEnableZrtp(bool onOff)   {
    enableZrtp = onOff;
}

bool ZrtpQueue::isEnableZrtp() {
    return enableZrtp;
}

void ZrtpQueue::SASVerified() {
    if (zrtpEngine != nullptr)
        zrtpEngine->SASVerified();
}

void ZrtpQueue::resetSASVerified() {
    if (zrtpEngine != nullptr)
        zrtpEngine->resetSASVerified();
}

void ZrtpQueue::goClearOk()    {  }

void ZrtpQueue::requestGoClear()  { }

void ZrtpQueue::setAuxSecret(uint8* data, int32_t length)  {
    if (zrtpEngine != nullptr)
        zrtpEngine->setAuxSecret(data, length);
}

void ZrtpQueue::setUserCallback(ZrtpUserCallback* ucb) {
    zrtpUserCallback = ucb;
}

void ZrtpQueue::setClientId(std::string id) {
    clientIdString = std::move(id);
}

std::string ZrtpQueue::getHelloHash(int32_t index)  {
    if (zrtpEngine != nullptr)
        return zrtpEngine->getHelloHash(index);
    else
        return std::string();
}

std::string ZrtpQueue::getPeerHelloHash()  {
    if (zrtpEngine != nullptr)
        return zrtpEngine->getPeerHelloHash();
    else
        return std::string();
}

std::string ZrtpQueue::getMultiStrParams(ZRtp ** zrtpMaster)  {
    if (zrtpEngine != nullptr)
        return zrtpEngine->getMultiStrParams(zrtpMaster);
    else
        return std::string();
}

void ZrtpQueue::setMultiStrParams(std::string parameters, ZRtp* zrtpMaster)  {
    if (zrtpEngine != nullptr)
        zrtpEngine->setMultiStrParams(std::move(parameters), zrtpMaster);
}

bool ZrtpQueue::isMultiStream()  {
    if (zrtpEngine != nullptr)
        return zrtpEngine->isMultiStream();
    return false;
}

bool ZrtpQueue::isMultiStreamAvailable()  {
    if (zrtpEngine != nullptr)
        return zrtpEngine->isMultiStreamAvailable();
    return false;
}

void ZrtpQueue::acceptEnrollment(bool accepted) {
    if (zrtpEngine != nullptr)
        zrtpEngine->acceptEnrollment(accepted);
}

std::string ZrtpQueue::getSasType() {
    if (zrtpEngine != nullptr)
        return zrtpEngine->getSasType();
    else
        return std::string();
}

uint8_t const * ZrtpQueue::getSasHash() {
    if (zrtpEngine != nullptr)
        return zrtpEngine->getSasHash();
    else
        return nullptr;
}

bool ZrtpQueue::sendSASRelayPacket(uint8_t* sh, std::string const &render) {

    if (zrtpEngine != nullptr)
        return zrtpEngine->sendSASRelayPacket(sh, render);
    else
        return false;
}

bool ZrtpQueue::isMitmMode() {
    return mitmMode;
}

void ZrtpQueue::setMitmMode(bool mitm) {
    this->mitmMode = mitm;
}

bool ZrtpQueue::isEnrollmentMode() {
    if (zrtpEngine != nullptr)
        return zrtpEngine->isEnrollmentMode();
    else
        return false;
}

void ZrtpQueue::setEnrollmentMode(bool enrollmentMode) {
    if (zrtpEngine != nullptr)
        zrtpEngine->setEnrollmentMode(enrollmentMode);
}

void ZrtpQueue::setParanoidMode(bool yesNo) {
        enableParanoidMode = yesNo;
}

bool ZrtpQueue::isParanoidMode() {
        return enableParanoidMode;
}

bool ZrtpQueue::isPeerEnrolled() {
    if (zrtpEngine != nullptr)
        return zrtpEngine->isPeerEnrolled();
    else
        return false;
}

void ZrtpQueue::setSignSas(bool sasSignMode) {
    signSas = sasSignMode;
}

bool ZrtpQueue::setSignatureData(uint8* data, int32 length) {
    if (zrtpEngine != nullptr)
        return zrtpEngine->setSignatureData(data, length);
    return false;
}

const uint8* ZrtpQueue::getSignatureData() {
    if (zrtpEngine != nullptr)
        return zrtpEngine->getSignatureData();
    return nullptr;
}

int32 ZrtpQueue::getSignatureLength() {
    if (zrtpEngine != nullptr)
        return zrtpEngine->getSignatureLength();
    return 0;
}

int32 ZrtpQueue::getPeerZid(uint8* data) {
    if (data == nullptr)
        return 0;

    if (zrtpEngine != nullptr)
        return zrtpEngine->getPeerZid(data);

    return 0;
}

int32_t ZrtpQueue::getNumberSupportedVersions() {
    return ZRtp::getNumberSupportedVersions();
}

int32_t ZrtpQueue::getCurrentProtocolVersion() {
    if (zrtpEngine != nullptr)
        return zrtpEngine->getCurrentProtocolVersion();

    return 0;
}


IncomingZRTPPkt::IncomingZRTPPkt(const unsigned char* const block, size_t len) :
        IncomingRTPPkt(block,len) {
}

uint32 IncomingZRTPPkt::getZrtpMagic() const {
     return ntohl(getHeader()->timestamp);
}

uint32 IncomingZRTPPkt::getSSRC() const {
     return ntohl(getHeader()->sources[0]);
}

OutgoingZRTPPkt::OutgoingZRTPPkt(unsigned char const * hdrext, uint32 hdrextlen) :
        OutgoingRTPPkt(nullptr, 0, hdrext, hdrextlen, nullptr ,0, 0, nullptr)
{
    getHeader()->version = 0;
    getHeader()->timestamp = htonl(ZRTP_MAGIC);
}

END_NAMESPACE

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */


#pragma clang diagnostic pop