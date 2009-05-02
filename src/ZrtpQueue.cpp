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
#include <stdio.h>

#include <libzrtpcpp/ZrtpQueue.h>
#include <libzrtpcpp/ZIDFile.h>
#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpStateClass.h>
#include <libzrtpcpp/ZrtpUserCallback.h>

static TimeoutProvider<std::string, ost::ZrtpQueue*>* staticTimeoutProvider = NULL;

using namespace GnuZrtpCodes;

#ifdef  CCXX_NAMESPACES
namespace ost {
#endif

ZrtpQueue::ZrtpQueue(uint32 size, RTPApplication& app) :
        AVPQueue(size,app)
{
    init();
}

ZrtpQueue::ZrtpQueue(uint32 ssrc, uint32 size, RTPApplication& app) :
        AVPQueue(ssrc,size,app)
{
    init();
}

void ZrtpQueue::init()
{
    zrtpUserCallback = NULL;
    enableZrtp = false;
    started = false;
    zrtpEngine = NULL;
    senderZrtpSeqNo = 1;

    clientIdString = clientId;
    peerSSRC = 0;
}

ZrtpQueue::~ZrtpQueue() {

    endQueue();
    stopZrtp();

    if (zrtpUserCallback != NULL) {
        delete zrtpUserCallback;
        zrtpUserCallback = NULL;
    }
}

int32_t
ZrtpQueue::initialize(const char *zidFilename, bool autoEnable)
{
    int32_t ret = 1;

    synchEnter();

    enableZrtp = autoEnable;

    if (staticTimeoutProvider == NULL) {
        staticTimeoutProvider = new TimeoutProvider<std::string, ZrtpQueue*>();
        staticTimeoutProvider->start();
    }
    ZIDFile* zf = ZIDFile::getInstance();
    if (!zf->isOpen()) {
        std::string fname;
        if (zidFilename == NULL) {
            char *home = getenv("HOME");
            std::string baseDir = (home != NULL) ? (std::string(home) + std::string("/."))
                                                    : std::string(".");
            fname = baseDir + std::string("GNUccRTP.zid");
            zidFilename = fname.c_str();
        }
        if (zf->open((char *)zidFilename) < 0) {
            enableZrtp = false;
            ret = -1;
        }
    }
    if (ret > 0) {
        const uint8_t* ownZid = zf->getZid();
        zrtpEngine = new ZRtp((uint8_t*)ownZid, (ZrtpCallback*)this, clientIdString);
    }
    synchLeave();
    return ret;
}

void ZrtpQueue::startZrtp() {
    if (zrtpEngine != NULL) {
        zrtpEngine->startZrtpEngine();
        started = true;
    }
}

void ZrtpQueue::stopZrtp() {
    if (zrtpEngine != NULL) {
        delete zrtpEngine;
        zrtpEngine = NULL;
        started = false;
    }
}

/*
 * The takeInDataPacket implementation for ZRTPQueue.
 */
size_t
ZrtpQueue::takeInDataPacket(void)
{
    InetHostAddress network_address;
    tpport_t transport_port;

    uint32 nextSize = (uint32)getNextDataPacketSize();
    unsigned char* buffer = new unsigned char[nextSize];
    int32 rtn = (int32)recvData(buffer, nextSize, network_address, transport_port);
    if ( (rtn < 0) || ((uint32)rtn > getMaxRecvPacketSize()) ){
        delete buffer;
        return 0;
    }

    IncomingZRTPPkt* packet = NULL;
    // check if this could be a real RTP/SRTP packet.
    if ((*buffer & 0xf0) != 0x10) {

        //  Could be real RTP, build a packet.
        IncomingRTPPkt* pkt = new IncomingRTPPkt(buffer,rtn);

        // Generic header validity check. If valid perform standard RTP handling
        if (pkt->isHeaderValid()) {
            return (rtpDataPacket(pkt, rtn, network_address, transport_port));
        }
        delete pkt;
        return 0;
    }

    // We assume all other packets are ZRTP packets here. Process
    // if ZRTP processing is enabled. Because valid RTP packets are
    // already handled we delete any packets here after processing.
    if (enableZrtp) {
        // Get CRC value into crc (see above how to compute the offset)
        uint16_t temp = rtn - CRC_SIZE;
        uint32_t crc = *(uint32_t*)(buffer + temp);
        crc = ntohl(crc);

        if (!zrtpCheckCksum(buffer, temp, crc)) {
            delete buffer;
            zrtpUserCallback->showMessage(Warning, WarningCRCmismatch);
            return 0;
        }

        packet = new IncomingZRTPPkt(buffer,rtn);

        uint32 magic = packet->getZrtpMagic();

        // Check if it is really a ZRTP packet, if not delete it and return 0
        if (magic != ZRTP_MAGIC || zrtpEngine == NULL) {
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
        unsigned char* extHeader =
                const_cast<unsigned char*>(packet->getHdrExtContent());
        extHeader -= 4;

        // store peer's SSRC, used when creating the CryptoContext
        peerSSRC = packet->getSSRC();
        zrtpEngine->processZrtpMessage(extHeader, peerSSRC);
    }
    delete packet;
    return 0;
}

size_t
ZrtpQueue::rtpDataPacket(IncomingRTPPkt* packet, int32 rtn, 
                         InetHostAddress network_address, 
                         tpport_t transport_port)
{
    // Look for a CryptoContext for this packet's SSRC
    CryptoContext* pcc = getInQueueCryptoContext(packet->getSSRC());

    // If no crypto context is available for this SSRC but we are already in
    // Secure state then create a CryptoContext for this SSRC.
    // Assumption: every SSRC stream sent via this connection is secured 
    // _and_ uses the same crypto parameters.
    if (pcc == NULL) {
        pcc = getInQueueCryptoContext(0);
        if (pcc != NULL) {
            pcc = pcc->newCryptoContextForSSRC(packet->getSSRC(), 0, 0L);
            if (pcc != NULL) {
                pcc->deriveSrtpKeys(0);
                setInQueueCryptoContext(pcc);
            }
        }
    }
    // If no crypto context: then either ZRTP is off or in early state
    // If crypto context is available then unprotect data here. If an error
    // occurs report the error and discard the packet.
    if (pcc != NULL) {
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

    // get time of arrival
    struct timeval recvtime;
    gettimeofday(&recvtime,NULL);

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
        IncomingRTPPktLink* packetLink =
                new IncomingRTPPktLink(packet,
                                       sourceLink,
                                       recvtime,
                                       packet->getTimestamp() -
                                               sourceLink->getInitialDataTimestamp(),
                                       NULL,NULL,NULL,NULL);
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

    OutgoingZRTPPkt* packet = new OutgoingZRTPPkt(data, length);

    packet->setSSRC(getLocalSSRC());

    packet->setSeqNum(senderZrtpSeqNo++);

    /*
     * Compute the ZRTP CRC over the full ZRTP packet. Thus include
     * the fixed packet header into the calculation.
     */
    uint16_t temp = packet->getRawPacketSize() - CRC_SIZE;
    uint8_t* pt = (uint8_t*)packet->getRawPacket();
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
    CryptoContext* pcc;
    CryptoContext* recvCryptoContext;
    CryptoContext* senderCryptoContext;

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
                    SrtpEncryptionAESCM,                     // encryption algo
                    SrtpAuthenticationSha1Hmac,              // authtentication algo
                    (unsigned char*)secrets->keyInitiator,   // Master Key
                    secrets->initKeyLen / 8,                 // Master Key length
                    (unsigned char*)secrets->saltInitiator,  // Master Salt
                    secrets->initSaltLen / 8,                // Master Salt length
                    secrets->initKeyLen / 8,                 // encryption keyl
                    20,                                      // authentication key len
                    secrets->initSaltLen / 8,                // session salt len
                    secrets->srtpAuthTagLen / 8);            // authentication tag lenA
        }
        else {
            senderCryptoContext = new CryptoContext(
                    0,
                    0,
                    0L,                                      // keyderivation << 48,
                    SrtpEncryptionAESCM,                     // encryption algo
                    SrtpAuthenticationSha1Hmac,              // authtentication algo
                    (unsigned char*)secrets->keyResponder,   // Master Key
                    secrets->respKeyLen / 8,                 // Master Key length
                    (unsigned char*)secrets->saltResponder,  // Master Salt
                    secrets->respSaltLen / 8,                // Master Salt length
                    secrets->respKeyLen / 8,                 // encryption keyl
                    20,                                      // authentication key len
                    secrets->respSaltLen / 8,                // session salt len
                    secrets->srtpAuthTagLen / 8);            // authentication tag len
        }
        if (senderCryptoContext == NULL) {
            return false;
        }
        // Create a SRTP crypto context for real SSRC sender stream. 
        // Note: key derivation can be done at this time only if the
        // key derivation rate is 0 (disabled). For ZRTP this is the 
        // case: the key derivation is defined as 2^48 
        // which is effectively 0.
        pcc = senderCryptoContext->newCryptoContextForSSRC(getLocalSSRC(), 0, 0L);
        if (pcc == NULL) {
            return false;
        }
        pcc->deriveSrtpKeys(0L);
        setOutQueueCryptoContext(pcc);
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
                    SrtpEncryptionAESCM,                     // encryption algo
                    SrtpAuthenticationSha1Hmac,              // authtication algo
                    (unsigned char*)secrets->keyResponder,   // Master Key
                    secrets->respKeyLen / 8,                 // Master Key length
                    (unsigned char*)secrets->saltResponder,  // Master Salt
                    secrets->respSaltLen / 8,                // Master Salt length
                    secrets->respKeyLen / 8,                 // encryption keyl
                    20,                                      // authentication key len
                    secrets->respSaltLen / 8,                // session salt len
                    secrets->srtpAuthTagLen / 8);            // authentication tag len
        }
        else {
            recvCryptoContext = new CryptoContext(
                    0,
                    0,
                    0L,                                      // keyderivation << 48,
                    SrtpEncryptionAESCM,                     // encryption algo
                    SrtpAuthenticationSha1Hmac,              // authtication algo
                    (unsigned char*)secrets->keyInitiator,   // Master Key
                    secrets->initKeyLen / 8,                 // Master Key length
                    (unsigned char*)secrets->saltInitiator,  // Master Salt
                    secrets->initSaltLen / 8,                // Master Salt length
                    secrets->initKeyLen / 8,                 // encryption keyl
                    20,                                      // authentication key len
                    secrets->initSaltLen / 8,                // session salt len
                    secrets->srtpAuthTagLen / 8);            // authentication tag len
        }
        if (recvCryptoContext == NULL) {
            return false;
        }
        // Create a SRTP crypto context for real SSRC input stream.
        // If the sender didn't provide a SSRC just insert the template
        // into the queue. After we received the first packet the real
        // crypto context will be created.
        //
        // Note: key derivation can be done at this time only if the
        // key derivation rate is 0 (disabled). For ZRTP this is the 
        // case: the key derivation is defined as 2^48 
        // which is effectively 0.
        if (peerSSRC != 0) {
            pcc = recvCryptoContext->newCryptoContextForSSRC(peerSSRC, 0, 0L);
            if (pcc == NULL) {
                return false;
            }
            pcc->deriveSrtpKeys(0L);
            setInQueueCryptoContext(pcc);
        }
        else {
            setInQueueCryptoContext(recvCryptoContext);
        }
    }
    return true;
}

void ZrtpQueue::srtpSecretsOn(std::string c, std::string s, bool verified)
{

  if (zrtpUserCallback != NULL) {
    zrtpUserCallback->secureOn(c);
    if (!s.empty()) {
        zrtpUserCallback->showSAS(s, verified);
    }
  }
}

void ZrtpQueue::srtpSecretsOff(EnableSecurity part) {
    if (part == ForSender) {
        removeOutQueueCryptoContext(NULL);
    }
    if (part == ForReceiver) {
        removeInQueueCryptoContext(NULL);
    }
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->secureOff();
    }
}

int32_t ZrtpQueue::activateTimer(int32_t time) {
    std::string s("ZRTP");
    if (staticTimeoutProvider != NULL) {
        staticTimeoutProvider->requestTimeout(time, this, s);
    }
    return 1;
}

int32_t ZrtpQueue::cancelTimer() {
    std::string s("ZRTP");
    if (staticTimeoutProvider != NULL) {
        staticTimeoutProvider->cancelRequest(this, s);
    }
    return 1;
}

void ZrtpQueue::handleTimeout(const std::string &c) {
    if (zrtpEngine != NULL) {
        zrtpEngine->processTimeout();
    }
}

void ZrtpQueue::handleGoClear()
{
    fprintf(stderr, "Need to process a GoClear message!");
}

void ZrtpQueue::sendInfo(MessageSeverity severity, int32_t subCode) {
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->showMessage(severity, subCode);
    }
}

void ZrtpQueue::zrtpNegotiationFailed(MessageSeverity severity, int32_t subCode) {
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->zrtpNegotiationFailed(severity, subCode);
    }
}

void ZrtpQueue::zrtpNotSuppOther() {
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->zrtpNotSuppOther();
    }
}

void ZrtpQueue::synchEnter() {
    synchLock.enter();
}

void ZrtpQueue::synchLeave() {
    synchLock.leave();
}

void ZrtpQueue::zrtpAskEnrollment(std::string info) {
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->zrtpAskEnrollment(info);
    }
}

void ZrtpQueue::zrtpInformEnrollment(std::string info) {
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->zrtpInformEnrollment(info);
    }
}

void ZrtpQueue::signSAS(std::string sas) {
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->signSAS(sas);
    }
}

bool ZrtpQueue::checkSASSignature(std::string sas) {
    if (zrtpUserCallback != NULL) {
        return zrtpUserCallback->checkSASSignature(sas);
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
    if (zrtpEngine != NULL)
        zrtpEngine->SASVerified();
}

void ZrtpQueue::resetSASVerified() {
    if (zrtpEngine != NULL)
        zrtpEngine->resetSASVerified();
}

void ZrtpQueue::goClearOk()    {  }

void ZrtpQueue::requestGoClear()  { }

void ZrtpQueue::setAuxSecret(uint8* data, int32_t length)  {
    if (zrtpEngine != NULL)
        zrtpEngine->setAuxSecret(data, length);
}

void ZrtpQueue::setPbxSecret(uint8* data, int32 length)  {
    if (zrtpEngine != NULL)
        zrtpEngine->setPbxSecret(data, length);
}

void ZrtpQueue::setUserCallback(ZrtpUserCallback* ucb) {
    zrtpUserCallback = ucb;
}

void ZrtpQueue::setClientId(std::string id) {
    clientIdString = id;
}

std::string ZrtpQueue::getHelloHash()  {
    if (zrtpEngine != NULL)
        return zrtpEngine->getHelloHash();
    else
        return std::string();
}

std::string ZrtpQueue::getMultiStrParams()  {
    if (zrtpEngine != NULL)
        return zrtpEngine->getMultiStrParams();
    else
        return std::string();
}

void ZrtpQueue::setMultiStrParams(std::string parameters)  {
    if (zrtpEngine != NULL)
        zrtpEngine->setMultiStrParams(parameters);
}

bool ZrtpQueue::isMultiStream()  {
    if (zrtpEngine != NULL)
        return zrtpEngine->isMultiStream();
    return false;
}

void ZrtpQueue::acceptEnrollment(bool accepted) {
    if (zrtpEngine != NULL)
        zrtpEngine->acceptEnrollment(accepted);
}

bool ZrtpQueue::setSignatureData(uint8* data, int32 length) {
    if (zrtpEngine != NULL) 
        return zrtpEngine->setSignatureData(data, length);
    return 0;
}

int32 ZrtpQueue::getSignatureData(uint8* data) {
    if (zrtpEngine != NULL) 
        return zrtpEngine->getSignatureData(data);
    return 0;
}

int32 ZrtpQueue::getSignatureLength() {
    if (zrtpEngine != NULL) 
        return zrtpEngine->getSignatureLength();
    return 0;
}

void ZrtpQueue::setPBXEnrollment(bool yesNo) {
    if (zrtpEngine != NULL) 
	zrtpEngine->setPBXEnrollment(yesNo);
}


int32 ZrtpQueue::getZid(uint8* data) {
    if (data == NULL)
        return 0;

    if (zrtpEngine != NULL)
        return zrtpEngine->getZid(data);

    return 0;
}

IncomingZRTPPkt::IncomingZRTPPkt(const unsigned char* const block, size_t len) :
        IncomingRTPPkt(block,len) {
}

uint32 IncomingZRTPPkt::getZrtpMagic() const {
     return ntohl(getHeader()->timestamp);
}

uint32 IncomingZRTPPkt::getSSRC() const	{
     return ntohl(getHeader()->sources[0]);
}

OutgoingZRTPPkt::OutgoingZRTPPkt(
    const unsigned char* const hdrext, uint32 hdrextlen) :
        OutgoingRTPPkt(NULL, 0, hdrext, hdrextlen, NULL ,0, 0, NULL)
{
    getHeader()->version = 0;
    getHeader()->timestamp = htonl(ZRTP_MAGIC);
}


#ifdef  CCXX_NAMESPACES
}
#endif

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */

