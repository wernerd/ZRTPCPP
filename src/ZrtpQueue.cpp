/*
  Copyright (C) 2006, 2007 Werner Dittmann

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Boston, MA 02111.
*/

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <string>
#include <libzrtpcpp/TimeoutProvider.h>

#include <libzrtpcpp/ZrtpQueue.h>
#include <libzrtpcpp/ZIDFile.h>
#include <libzrtpcpp/ZrtpStateClass.h>
#include <libzrtpcpp/ZrtpUserCallback.h>



static TimeoutProvider<std::string, ost::ZrtpQueue*>* staticTimeoutProvider = NULL;

#ifdef  CCXX_NAMESPACES
namespace ost {
#endif

int32_t
ZrtpQueue::initialize(const char *zidFilename)
{
    if (staticTimeoutProvider == NULL) {
        staticTimeoutProvider = new TimeoutProvider<std::string, ZrtpQueue*>();
        staticTimeoutProvider->start();
    }
    std::string fname;
    if (zidFilename == NULL) {
        char *home = getenv("HOME");

        std::string baseDir = (home != NULL) ? (std::string(home) + std::string("/."))
                                             : std::string(".");
        fname = baseDir + std::string("GNUccRTP.zid");
        zidFilename = fname.c_str();
    }
    ZIDFile *zf = ZIDFile::getInstance();
    if (zf->open((char *)zidFilename) < 0) {
        enableZrtp = false;
        return -1;
    }
    return 1;
}

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
    enableZrtp = true;
    secureParts = 0;
    zrtpEngine = NULL;

    senderCryptoContext = NULL;

    recvCryptoContext = NULL;

    senderZrtpSeqNo = 1;

    clientIdString = clientId;
}

ZrtpQueue::~ZrtpQueue() {

    cancelTimer();
    stop();

    if (zrtpUserCallback != NULL) {
        delete zrtpUserCallback;
        zrtpUserCallback = NULL;
    }

    if (recvCryptoContext != NULL) {
        delete recvCryptoContext;
        recvCryptoContext = NULL;
    }

    if (senderCryptoContext != NULL) {
        delete senderCryptoContext;
        senderCryptoContext = NULL;
    }
}

void ZrtpQueue::start() {
    ZIDFile *zid = ZIDFile::getInstance();
    const uint8_t* ownZid = zid->getZid();

    if (zrtpEngine == NULL) {
        zrtpEngine = new ZRtp((uint8_t*)ownZid, (ZrtpCallback*)this);
        zrtpEngine->setClientId(clientIdString);
        zrtpEngine->startZrtpEngine();
    }
}

void ZrtpQueue::stop() {
    endQueue();
    if (zrtpEngine != NULL) {
        zrtpEngine->stopZrtp();
        delete zrtpEngine;
        zrtpEngine = NULL;
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

        //  Could be real RTP, build a packet. It will link itself to its source
        IncomingRTPPkt* pkt = new IncomingRTPPkt(buffer,rtn);

        // Generic header validity check.
        if (pkt->isHeaderValid()) {
            return (rtpDataPacket(pkt, rtn, network_address, transport_port));
        }
        delete buffer;
        return 0;
    }

    if (enableZrtp) {
        // TODO: cchek ZRTP CRC (see also send data )
#if 0
        // Get CRC value into crc (see above how to compute the offset)
        uint16_t temp = getLength();
        uint32_t crc = *(uint32_t*)(((uint8_t*)zrtpHeader) + (temp * 4));
        crc = ntohl(crc);

        return zrtpCheckCksum((uint8_t*)zrtpHeader, temp * 4, crc);
#endif
        packet = new IncomingZRTPPkt(buffer,rtn);
        uint32 magic = packet->getZrtpMagic();

        // Check if it is a ZRTP packet, if not delete it and return 0
        if (magic != ZRTP_MAGIC || zrtpEngine != NULL) {
            delete packet;
            return 0;
        }
        unsigned char* extHeader =
                const_cast<unsigned char*>(packet->getHdrExtContent());
        // this now points beyond the undefined and length field.
        // We need them, thus adjust
        extHeader -= 4;

        // first check for GoClear packet. If this was a GoClear don't 
        // process any further. 
        if (zrtpEngine->handleGoClear(extHeader)) {
            delete packet;
            return 0;
        }
        zrtpEngine->processZrtpMessage(extHeader);
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
    if (pcc == NULL && zrtpEngine && zrtpEngine->checkState(SecureState)) {
        pcc = recvCryptoContext->newCryptoContextForSSRC(packet->getSSRC(), 0, 0L);
        pcc->deriveSrtpKeys(packet->getSeqNum());
        setInQueueCryptoContext(pcc);
    }

    // If no crypto context: then either ZRTP is off or in early state
    // If crypto context: then unprotect data here
    if (pcc != NULL) {
        int32 ret;
        if ((ret = packet->unprotect(pcc)) < 0) {
            if (!onSRTPPacketError(*packet, ret)) {
                delete packet;
                return 0;
            }
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
    // Start the ZRTP engine only after we got a at least one RTP packet and
    // sent some as well
    if (enableZrtp && zrtpEngine == NULL && getSendPacketCount() >= 3) {
        start();
    }
    return rtn;
}


bool
ZrtpQueue::onSRTPPacketError(IncomingRTPPkt& pkt, int32 errorCode)
{
    if (errorCode == -1) {
        sendInfo(Error, "Dropping packet because of authentication error!");
    }
    else {
        sendInfo(Error, "Dropping packet because replay check failed!");
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
     * The compute the ZRTP CRC over the full ZRTP packet. Thus include
     * the fiexed packet header into the calculation. This header has a
     * size of 3 words.
     */
    uint16_t temp = length + (3 * ZRTP_WORD_SIZE);
    uint32_t crc = zrtpGenerateCksum((uint8_t*)packet, temp);
    // convert and store CRC in crc field of ZRTP packet.
    crc = zrtpEndCksum(crc);
    *(uint32_t*)(((uint8_t*)packet) + temp) = htonl(crc);

    dispatchImmediate(packet);
    delete packet;

    return 1;
}

#if 0
int32_t ZrtpQueue::sendDataSRTP(const unsigned char *dataHeader, int32_t lengthHeader,
                                            char *dataContent, int32_t lengthContent)
{
    CryptoContext* pcc = getOutQueueCryptoContext(senderZrtpSsrc);
    OutgoingRTPPkt* packet = new OutgoingRTPPkt(NULL, 0, dataHeader, lengthHeader,
            (uint8*)dataContent, lengthContent, 0, pcc);

    packet->setSSRC(senderZrtpSsrc);
    packet->setPayloadType(13);

    // TODO Remove Zfone hacks after Zfone fixed its seq.no handling
    if (zrtpEngine->Zfone) {
        senderZrtpSeqNo = getCurrentSeqNum();
    }
    packet->setSeqNum(senderZrtpSeqNo++);

    if (zrtpEngine->Zfone) {
        setNextSeqNum(senderZrtpSeqNo);
    }
    packet->setTimestamp(time(NULL));

    // packet->enableZrtpChecksum();
    packet->protect(senderZrtpSsrc, pcc);
    // packet->computeZrtpChecksum();

    dispatchImmediate(packet);
    delete packet;
    return 1;
}
#endif

void ZrtpQueue::srtpSecretsReady(SrtpSecret_t* secrets, EnableSecurity part)
{
    CryptoContext* pcc;

    if (part == ForSender) {
        // To encrypt packets: intiator uses initiator keys,
        // responder uses responders keys
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

        // Create crypto context for ZRTP SSRC sender stream
//        pcc = senderCryptoContext->newCryptoContextForSSRC(senderZrtpSsrc, 0, 0L);
//        pcc->deriveSrtpKeys(senderZrtpSeqNo);
//        setOutQueueCryptoContext(pcc);

        // create a crypto context for real SSRC sender stream. 
        // Note: key derivation can be done at this time only if the
        // key derivation rate is 0 (disabled) or greater 2^16. For 
        // ZRTP this is the case: the key derivation is defined as 2^48 
        // which is effectively 0.
        pcc = senderCryptoContext->newCryptoContextForSSRC(getLocalSSRC(), 0, 0L);
        pcc->deriveSrtpKeys(0L);
        setOutQueueCryptoContext(pcc);

        secureParts++;
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
        // Create crypto context for ZRTP SSRC receiving stream
//        pcc = recvCryptoContext->newCryptoContextForSSRC(recvZrtpSsrc, 0, 0L);
//        pcc->deriveSrtpKeys(recvZrtpSeqNo);
//        setInQueueCryptoContext(pcc);

        secureParts++;
    }
}

void ZrtpQueue::srtpSecretsOn(const char* c, const char* s)
{

  if (c != NULL && zrtpUserCallback != NULL) {
    zrtpUserCallback->secureOn(c);
  }
  if (s != NULL && zrtpUserCallback != NULL) {
    zrtpUserCallback->showSAS(s);
  }
}

void ZrtpQueue::srtpSecretsOff(EnableSecurity part)
{
    if (part == ForSender) {
        removeOutQueueCryptoContext(NULL);
    }
    if (part == ForReceiver) {
        removeInQueueCryptoContext(NULL);
    }
    secureParts = 0;
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->secureOff();
    }
}


int32_t
ZrtpQueue::activateTimer(int32_t time)
{
    std::string s("ZRTP");
    staticTimeoutProvider->requestTimeout(time, this, s);
    return 1;
}

int32_t
ZrtpQueue::cancelTimer()
{
    std::string s("ZRTP");
    staticTimeoutProvider->cancelRequest(this, s);
    return 1;
}

void ZrtpQueue::handleGoClear()
{
    fprintf(stderr, "Need to process a GoClear message!");
}

void ZrtpQueue::sendInfo(MessageSeverity severity, char* msg) {
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->showMessage(severity, msg);
    }
    else {
        fprintf(stderr, "Severity: %d - %s\n", severity, msg);
    }
}

void ZrtpQueue::zrtpNegotiationFailed(MessageSeverity severity, char* msg) {
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->zrtpNegotiationFailed(severity, msg);
    }
    else {
        fprintf(stderr, "Severity: %d - %s\n", severity, msg);
    }
}

void ZrtpQueue::zrtpNotSuppOther() {
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->zrtpNotSuppOther();
    }
    else {
        fprintf(stderr, "The other (remote) peer does not support ZRTP\n");
    }
}


IncomingZRTPPkt::IncomingZRTPPkt(const unsigned char* const block, size_t len) :
        IncomingRTPPkt(block,len)
{
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
