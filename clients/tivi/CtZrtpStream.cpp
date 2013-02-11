/*
 * Tivi client glue code for ZRTP.
 * Copyright (c) 2012 Slient Circle LLC.  All rights reserved.
 *
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <stdint.h>

#include <common/osSpecifics.h>

#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpStateClass.h>
#include <libzrtpcpp/ZrtpCrc32.h>
#include <srtp/CryptoContext.h>
#include <srtp/CryptoContextCtrl.h>
#include <srtp/SrtpHandler.h>

#include <CtZrtpStream.h>
#include <CtZrtpCallback.h>
#include <TiviTimeoutProvider.h>
#include <cryptcommon/aes.h>
#include <cryptcommon/ZrtpRandom.h>

static TimeoutProvider<std::string, CtZrtpStream*>* staticTimeoutProvider = NULL;

static std::map<int32_t, std::string*> infoMap;
static std::map<int32_t, std::string*> warningMap;
static std::map<int32_t, std::string*> severeMap;
static std::map<int32_t, std::string*> zrtpMap;
static std::map<int32_t, std::string*> enrollMap;
static int initialized = 0;

using namespace GnuZrtpCodes;

CtZrtpStream::CtZrtpStream():
    index(CtZrtpSession::AudioStream), type(CtZrtpSession::NoStream), zrtpEngine(NULL),
    ownSSRC(0), enableZrtp(0), started(false), isStopped(false), session(NULL), tiviState(CtZrtpSession::eLookingPeer),
    prevTiviState(CtZrtpSession::eLookingPeer), recvSrtp(NULL), recvSrtcp(NULL), sendSrtp(NULL), sendSrtcp(NULL),
    zrtpUserCallback(NULL), zrtpSendCallback(NULL), senderZrtpSeqNo(0), peerSSRC(0), protect(0), unprotect(0),
    unprotectFailed(0), zrtpHashMatch(false), sasVerified(false), helloReceived(false), sdesActive(false), sdes(NULL),
    supressCounter(0), srtpErrorBurst(0)
{
    synchLock = new CMutexClass();

    // TODO: do we need mutex or can tivi do it
    if (staticTimeoutProvider == NULL) {
        staticTimeoutProvider = new TimeoutProvider<std::string, CtZrtpStream*>();
        staticTimeoutProvider->Event(&staticTimeoutProvider);  // Event argument is dummy, not used
    }
    initStrings();
    senderZrtpSeqNo = 4711;     // TODO: get 15 bit random number
}

void CtZrtpStream::setUserCallback(CtZrtpCb* ucb) {
    zrtpUserCallback = ucb;
}

void CtZrtpStream::setSendCallback(CtZrtpSendCb* scb) {
    zrtpSendCallback = scb;
}

CtZrtpStream::~CtZrtpStream() {
    stopStream();
    delete synchLock;
    synchLock = NULL;
}

void CtZrtpStream::stopStream() {

    index = CtZrtpSession::AudioStream;
    type = CtZrtpSession::NoStream;
    tiviState = CtZrtpSession::eLookingPeer;
    prevTiviState = CtZrtpSession::eLookingPeer;
    ownSSRC = 0;
    enableZrtp = 0;
    started = false;
    isStopped = false;
    peerSSRC = 0;
    protect = 0;
    senderZrtpSeqNo =  4711;     // TODO: get 15 bit random number
    unprotect = 0;
    unprotectFailed = 0;
    zrtpHashMatch= false;
    sasVerified = false;
    supressCounter = 0;
    srtpErrorBurst = 0;
    helloReceived = false;

    peerHelloHash.clear();

    delete zrtpEngine;
    zrtpEngine = NULL;

    delete recvSrtp;
    recvSrtp = NULL;

    delete recvSrtcp;
    recvSrtcp = NULL;

    delete sendSrtp;
    sendSrtp = NULL;

    delete sendSrtcp;
    sendSrtcp = NULL;

    delete sdes;
    sdes = NULL;

    // Don't delete the next classes, we don't own them.
    zrtpUserCallback = NULL;
    zrtpSendCallback = NULL;
    session = NULL;
}

bool CtZrtpStream::processOutgoingRtp(uint8_t *buffer, size_t length, size_t *newLength) {
    bool rc = true;
    if (sendSrtp == NULL) {                 // ZRTP/SRTP inactive
        *newLength = length;
        // Check if ZRTP engine is started and check states to determine if we should send the RTP packet.
        // Do not send in states: CommitSent, WaitDHPart2, WaitConfirm1, WaitConfirm2, WaitConfAck
        if (started && (zrtpEngine->inState(CommitSent) || zrtpEngine->inState(WaitDHPart2) || zrtpEngine->inState(WaitConfirm1) ||
            zrtpEngine->inState(WaitConfirm2) || zrtpEngine->inState(WaitConfAck))) {
            ZrtpRandom::addEntropy(buffer, length);
            return false;
        }
        if (sdesActive && sdes != NULL) {   // SDES stream available, let SDES protect if necessary
            rc = sdes->outgoingRtp(buffer, length, newLength);
            if (*sdesTempBuffer != 0)       // clear SDES crypto string if not already done
                memset(sdesTempBuffer, 0, maxSdesString);
        }
        return rc;
    }
    // At this point ZRTP/SRTP is active
    if (sdesActive && sdes != NULL) {       // We still have a SDES - other client did not send zrtp-hash thus we protect twice
        rc = sdes->outgoingRtp(buffer, length, newLength);
        if (*sdesTempBuffer != 0)           // clear SDES crypto string if not already done
            memset(sdesTempBuffer, 0, maxSdesString);
        if (!rc) {
            return rc;
        }
    }
    rc = SrtpHandler::protect(sendSrtp, buffer, length, newLength);
    if (rc) {
        protect++;
    }
    return rc;
}

int32_t CtZrtpStream::processIncomingRtp(uint8_t *buffer, size_t length, size_t *newLength) {
    int32_t rc = 0;
    // check if this could be a real RTP/SRTP packet.
    if ((*buffer & 0xc0) == 0x80) {             // A real RTP, check if we are in secure mode
        if (supressCounter < supressWarn)
            supressCounter++;
        if (recvSrtp == NULL) {                 // no ZRTP/SRTP available
            if (!sdesActive || sdes == NULL) {  // no SDES stream available, just set length and return
                *newLength = length;
                return 1;
            }
            rc = sdes->incomingRtp(buffer, length, newLength);
            if (*sdesTempBuffer != 0)           // clear SDES crypto string if not already done
                memset(sdesTempBuffer, 0, maxSdesString);

            if (rc == 1) {                       // SDES unprotect success
                srtpErrorBurst = 0;
                return 1;
            }
        }
        else {
            // At this point we have an active ZRTP/SRTP context, unprotect with ZRTP/SRTP first
            rc = SrtpHandler::unprotect(recvSrtp, buffer, length, newLength);
            if (rc == 1) {
                unprotect++;
                // Got a good SRTP, check state, WaitConfAck is a Responder state
                // in this case simulate a conf2Ack, refer to RFC 6189, chapter 4.6, last paragraph
                if (zrtpEngine->inState(WaitConfAck)) {
                    zrtpEngine->conf2AckSecure();
                }
                if (sdesActive && sdes != NULL) {    // We still have a SDES - other client did not send matching zrtp-hash
                    rc = sdes->incomingRtp(buffer, length, newLength);
                }
                if (rc == 1) {                       // if rc is still one: either no SDES or SDES incoming sucess
                    srtpErrorBurst = 0;
                    return 1;
                }
            }
        }
        // We come to this point only if we have some problems during SRTP unprotect
        if (supressCounter > supressWarn && srtpErrorBurst >= srtpErrorBurstThreshold) {
            srtpErrorBurst++;
            if (rc == -1) {
                sendInfo(Warning, WarningSRTPauthError);
            }
            else {
                sendInfo(Warning, WarningSRTPreplayError);
            }
            unprotectFailed++;
        }
        return 0;
    }

    // At this point we assume the packet is not an RTP packet. Check if it is a ZRTP packet.
    // Process it if ZRTP processing is started. In any case, let the application drop
    // the packet.
    if (started) {
        // Fixed header length + smallest ZRTP packet (includes CRC)
        if (length < (12 + sizeof(HelloAckPacket_t))) // data too small, dismiss
            return 0;

        uint32_t magic = *(uint32_t*)(buffer + 4);
        magic = zrtpNtohl(magic);

        // Check if it is really a ZRTP packet, return, no further processing
        if (magic != ZRTP_MAGIC) {
            return 0;
        }
        // Get CRC value into crc (see above how to compute the offset)
        uint16_t temp = length - CRC_SIZE;
        uint32_t crc = *(uint32_t*)(buffer + temp);
        crc = zrtpNtohl(crc);
        if (!zrtpCheckCksum(buffer, temp, crc)) {
            sendInfo(Warning, WarningCRCmismatch);
            return 0;
        }
        // this now points beyond to the plain ZRTP message.
        unsigned char* zrtpMsg = (buffer + 12);

        // store peer's SSRC in host order, used when creating the CryptoContext
        peerSSRC = *(uint32_t*)(buffer + 8);
        peerSSRC = zrtpNtohl(peerSSRC);
        zrtpEngine->processZrtpMessage(zrtpMsg, peerSSRC, length);
    }
    return 0;
}

int CtZrtpStream::getSignalingHelloHash(char *hHash) {

    if (hHash == NULL)
        return 0;

    std::string hash;
    std::string hexString;
    size_t hexStringStart;

    // The Tivi client requires the 64 char hex string only, thus
    // split the string that we get from ZRTP engine that contains
    // the version info as well (which is the right way to do because
    // the engine knows which version of the ZRTP protocol it uses.)
    hash = zrtpEngine->getHelloHash();
    hexStringStart = hash.find_last_of(' ');
    hexString = hash.substr(hexStringStart+1);

    // Copy the hex string and terminate with nul
    int maxLen = hexString.length() > 64 ? 64 : hexString.length();
    memcpy(hHash, hexString.c_str(), maxLen);
    hHash[maxLen] = '\0';
    return maxLen;
}


void CtZrtpStream::setSignalingHelloHash(const char *hHash) {
    synchEnter();
    peerHelloHash.assign(hHash);

    std::string ph = zrtpEngine->getPeerHelloHash();
    if (ph.empty()) {
        synchLeave();
        return;
    }
    size_t hexStringStart = ph.find_last_of(' ');
    std::string hexString = ph.substr(hexStringStart+1);

    if (hexString.compare(peerHelloHash) == 0) {
        zrtpHashMatch = true;
        // We have a matching zrtp-hash. If ZRTP/SRTP is active we may need to release
        // an existig SDES stream.
        if (sdes != NULL && sendSrtp != NULL && recvSrtp != NULL) {
            sdesActive = false;
        }
    }
    else {
        if (zrtpUserCallback != NULL)
            zrtpUserCallback->onZrtpWarning(session, (char*)"ZRTP_EVENT_WRONG_SIGNALING_HASH", index);
    }
    synchLeave();
}

int CtZrtpStream::isSecure() {
    return tiviState == CtZrtpSession::eSecure || tiviState == CtZrtpSession::eSecureMitm ||
           tiviState == CtZrtpSession::eSecureMitmVia || tiviState == CtZrtpSession::eSecureSdes;
}


#define T_ZRTP_LB(_K,_V)                                \
        if(iLen+1 == sizeof(_K) && strncmp(key, _K, iLen) == 0){  \
            return snprintf(p, maxLen, "%s", _V);}

#define T_ZRTP_F(_K,_FV)                                                \
        if(iLen+1 == sizeof(_K) && strncmp(key,_K, iLen) == 0){              \
            return snprintf(p, maxLen, "%d", (!!(info->secretsCached & _FV)) << (!!(info->secretsMatchedDH & _FV)));}


int CtZrtpStream::getInfo(const char *key, char *p, int maxLen) {

    if ((sdes == NULL && !started) || isStopped || !isSecure())
        return 0;

    memset(p, 0, maxLen);
    const ZRtp::zrtpInfo *info = NULL;
    ZRtp::zrtpInfo tmpInfo;

    int iLen = strlen(key);

    // Compute Hello-hash info string
    const char *strng = NULL;
    if (peerHelloHash.empty()) {
        strng = "None";
    }
    else if (zrtpHashMatch) {
        strng = "Good";
    }
    else {
        strng = !sdes || helloReceived ? "Bad" : "No hello";
    }
    T_ZRTP_LB("sdp_hash", strng);

    if (recvSrtp != NULL || sendSrtp != NULL) {
        info = zrtpEngine->getDetailInfo();

        T_ZRTP_LB("lbClient",  zrtpEngine->getPeerClientId().c_str());
        T_ZRTP_LB("lbVersion", zrtpEngine->getPeerProtcolVersion().c_str());

        if (iLen == 1 && key[0] == 'v') {
            return sprintf(p, "%d", sasVerified);
        }
        if(strncmp("sc_secure", key, iLen) == 0) {
            int v = (zrtpHashMatch && sasVerified && !peerHelloHash.empty() && tiviState == CtZrtpSession::eSecure);

            if (v && (info->secretsCached & ZRtp::Rs1) == 0  && !sasVerified)
                v = 0;
            if (v && (info->secretsMatched & ZRtp::Rs1) == 0 && !sasVerified)
                v = 0;
            return sprintf(p, "%d" ,v);
        }
    }
    else if (sdesActive && sdes != NULL) {
        T_ZRTP_LB("lbClient",      (const char*)"SDES");
        T_ZRTP_LB("lbVersion",     (const char*)"");

        tmpInfo.secretsMatched = 0;
        tmpInfo.secretsCached = 0;
        tmpInfo.hash = (const char*)"";
        if (sdes->getHmacTypeMix() == ZrtpSdesStream::MIX_NONE) {
            tmpInfo.pubKey = (const char*)"SIP SDES";
        }
        else {
            if (sdes->getCryptoMixAttribute(mixAlgoName, sizeof(mixAlgoName)) > 0)
                tmpInfo.hash = mixAlgoName;
            tmpInfo.pubKey = (const char*)"SIP SDES-MIX";
        }
        tmpInfo.cipher = sdes->getCipher();
        tmpInfo.authLength = sdes->getAuthAlgo();
        info = &tmpInfo;
    }
    T_ZRTP_F("rs1",ZRtp::Rs1);
    T_ZRTP_F("rs2",ZRtp::Rs2);
    T_ZRTP_F("aux",ZRtp::Aux);
    T_ZRTP_F("pbx",ZRtp::Pbx);

    T_ZRTP_LB("lbChiper",      info->cipher);
    T_ZRTP_LB("lbAuthTag",     info->authLength);
    T_ZRTP_LB("lbHash",        info->hash);
    T_ZRTP_LB("lbKeyExchange", info->pubKey);

    return 0;
}

int CtZrtpStream::enrollAccepted(char *p) {
    zrtpEngine->acceptEnrollment(true);

    uint8_t peerZid[IDENTIFIER_LEN];
    std::string name;

    zrtpEngine->getPeerZid(peerZid);
    int32_t nmLen = getZidCacheInstance()->getPeerName(peerZid, &name);

    if (nmLen == 0)
        getZidCacheInstance()->putPeerName(peerZid, std::string(p));
    return CtZrtpSession::ok;
}

int CtZrtpStream::enrollDenied() {
    zrtpEngine->acceptEnrollment(false);

    uint8_t peerZid[IDENTIFIER_LEN];
    std::string name;

    zrtpEngine->getPeerZid(peerZid);
    int32_t nmLen = getZidCacheInstance()->getPeerName(peerZid, &name);

    if (nmLen == 0)
        getZidCacheInstance()->putPeerName(peerZid, std::string(""));
    return CtZrtpSession::ok;
}


bool CtZrtpStream::createSdes(char *cryptoString, size_t *maxLen, const ZrtpSdesStream::sdesSuites sdesSuite) {
    if (isSecure())         // don't take action if we are already secure
        return false;

    if (sdes == NULL)
        sdes = new ZrtpSdesStream(sdesSuite);

    if (sdes == NULL || !sdes->createSdes(cryptoString, maxLen, true)) {
        sdesActive = false;
        delete sdes;
        sdes = NULL;
        return false;
    }
    sdesActive = true;
    return true;
}

bool CtZrtpStream::parseSdes(char *recvCryptoStr, size_t recvLength, char *sendCryptoStr, size_t *sendLength, bool sipInvite) {
    if (isSecure())         // don't take action if we are already secure
        return false;

    // The ZrtpSdesStream determines its suite by parsing the crypto string.
    if (sdes == NULL)
        sdes = new ZrtpSdesStream();

    if (sdes == NULL || !sdes->parseSdes(recvCryptoStr, recvLength, sipInvite))
        goto cleanup;
    if (!sipInvite) {
        size_t len;
        if (sendCryptoStr == NULL) {
            sendCryptoStr = sdesTempBuffer;
            len = maxSdesString;
            sendLength = &len;
        }
        if (!sdes->createSdes(sendCryptoStr, sendLength, sipInvite))
            goto cleanup;
    }
    if (sdes->getState() == ZrtpSdesStream::SDES_SRTP_ACTIVE) {
        tiviState = CtZrtpSession::eSecureSdes;
        if (zrtpUserCallback != NULL)
            zrtpUserCallback->onNewZrtpStatus(session, NULL, index);    // Inform client about new state
    }
    sdesActive = true;
    return true;

 cleanup:
    sdesActive = false;
    delete sdes;
    sdes = NULL;
    return false;
}

bool CtZrtpStream::getSavedSdes(char *sendCryptoStr, size_t *sendLength) {

    size_t len = strlen(sdesTempBuffer);

    if (len >= *sendLength)
        return false;

    strcpy(sendCryptoStr, sdesTempBuffer);
    *sendLength = len;

    if (zrtpUserCallback != NULL)
        zrtpUserCallback->onNewZrtpStatus(session, NULL, index);
    return true;
}

bool CtZrtpStream::isSdesActive() {
    return (sdes != NULL && sdes->getState() == ZrtpSdesStream::SDES_SRTP_ACTIVE);
}

int CtZrtpStream::getCryptoMixAttribute(char *algoNames, size_t length) {

    if (sdes == NULL)
        sdes = new ZrtpSdesStream();

    return sdes->getCryptoMixAttribute(algoNames, length);
}

bool  CtZrtpStream::setCryptoMixAttribute(const char *algoNames) {
    if (isSecure()) // don't take action if we are already secure
        return false;

    if (sdes == NULL)
        sdes = new ZrtpSdesStream();

    return sdes->setCryptoMixAttribute(algoNames);
}

/* *********************
 * Here the callback methods required by the ZRTP implementation
 *
 * The ZRTP functions calls most of the callback functions with syncLock set. Exception
 * is inform enrollement callback. When in doubt: check!
 */
int32_t CtZrtpStream::sendDataZRTP(const unsigned char *data, int32_t length) {

    uint16_t totalLen = length + 12;     /* Fixed number of bytes of ZRTP header */
    uint32_t crc;

    uint16_t* pus;
    uint32_t* pui;

    if ((totalLen) > maxZrtpSize)
        return 0;

    /* Get some handy pointers */
    pus = (uint16_t*)zrtpBuffer;
    pui = (uint32_t*)zrtpBuffer;

    /* set up fixed ZRTP header */
    *zrtpBuffer = 0x10;     /* invalid RTP version - refer to ZRTP spec chap 5 */
    *(zrtpBuffer + 1) = 0;
    pus[1] = zrtpHtons(senderZrtpSeqNo++);
    pui[1] = zrtpHtonl(ZRTP_MAGIC);
    pui[2] = zrtpHtonl(ownSSRC);            // ownSSRC is stored in host order

    /* Copy ZRTP message data behind the header data */
    memcpy(zrtpBuffer+12, data, length);

    /* Setup and compute ZRTP CRC */
    crc = zrtpGenerateCksum(zrtpBuffer, totalLen-CRC_SIZE);

    /* convert and store CRC in ZRTP packet.*/
    crc = zrtpEndCksum(crc);
    *(uint32_t*)(zrtpBuffer+totalLen-CRC_SIZE) = zrtpHtonl(crc);

    /* Send the ZRTP packet using callback */
    if (zrtpSendCallback != NULL) {
        zrtpSendCallback->sendRtp(session, zrtpBuffer, totalLen, index);
        return 1;
    }
    return 0;
}

bool CtZrtpStream::srtpSecretsReady(SrtpSecret_t* secrets, EnableSecurity part)
{
    CryptoContext* recvCryptoContext;
    CryptoContext* senderCryptoContext;
    CryptoContextCtrl* recvCryptoContextCtrl;
    CryptoContextCtrl* senderCryptoContextCtrl;

    int cipher;
    int authn;
    int authKeyLen;

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
            senderCryptoContext = 
                new CryptoContext(0,                                       // SSRC (used for lookup)
                                  0,                                       // Roll-Over-Counter (ROC)
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
            senderCryptoContextCtrl = 
                new CryptoContextCtrl(0,                                         // SSRC (used for lookup)
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
            senderCryptoContext = 
                new CryptoContext(0,                                       // SSRC (used for lookup)
                                  0,                                       // Roll-Over-Counter (ROC)
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
            senderCryptoContextCtrl = 
                new CryptoContextCtrl(0,                                         // SSRC (used for lookup)
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
        if (senderCryptoContext == NULL) {
            return false;
        }
        senderCryptoContext->deriveSrtpKeys(0L);
        sendSrtp = senderCryptoContext;

        senderCryptoContextCtrl->deriveSrtcpKeys();
        sendSrtcp = senderCryptoContextCtrl;
    }
    if (part == ForReceiver) {
        // To decrypt packets: intiator uses responder keys,
        // responder initiator keys
        // See comment above.
        if (secrets->role == Initiator) {
            recvCryptoContext = 
                new CryptoContext(0,                                       // SSRC (used for lookup)
                                  0,                                       // Roll-Over-Counter (ROC)
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
            recvCryptoContextCtrl = 
                new CryptoContextCtrl(0,                                         // SSRC (used for lookup)
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
            recvCryptoContext = 
                new CryptoContext(0,                                       // SSRC (used for lookup)
                                  0,                                       // Roll-Over-Counter (ROC)
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
            recvCryptoContextCtrl = 
                new CryptoContextCtrl(0,                                         // SSRC (used for lookup)
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
        if (recvCryptoContext == NULL) {
            return false;
        }
        recvCryptoContext->deriveSrtpKeys(0L);
        recvSrtp = recvCryptoContext;

        recvCryptoContextCtrl->deriveSrtcpKeys();
        recvSrtcp = recvCryptoContextCtrl;

        supressCounter = 0;         // supress SRTP warnings for some packets after we switch to SRTP
    }
    if (zrtpHashMatch && recvSrtp != NULL && sendSrtp != NULL) {
        sdesActive = false;
    }
    return true;
}

void CtZrtpStream::srtpSecretsOn(std::string cipher, std::string sas, bool verified)
{
     // p->setStatus(ctx->peer_mitm_flag || iMitm?CTZRTP::eSecureMitm:CTZRTP::eSecure,&buf[0],iIsVideo);

    prevTiviState = tiviState;

    // TODO Discuss with Janis what else to do? Set other state, for example eSecureMitmVia or some string?
    tiviState = CtZrtpSession::eSecure;
    if (cipher.find ("SASviaMitM", cipher.size() - 10, 10) != std::string::npos) { // Found: SAS via PBX
        tiviState = CtZrtpSession::eSecureMitmVia;  //eSecureMitmVia
    }
    else if (cipher.find ("MitM", cipher.size() - 4, 4) != std::string::npos) {
        tiviState = CtZrtpSession::eSecureMitm;
    }
    else if (cipher.find ("EndAtMitM", cipher.size() - 9, 9) != std::string::npos) {
        tiviState = CtZrtpSession::eSecureMitm;
    }
    sasVerified = verified;
    if (zrtpUserCallback != NULL) {
        char *strng = NULL;
        std::string sasTmp;

        if (!sas.empty()) {                 // Multi-stream mode streams don't have SAS, no reporting
            uint8_t peerZid[IDENTIFIER_LEN];
            std::string name;

            zrtpEngine->getPeerZid(peerZid);
            getZidCacheInstance()->getPeerName(peerZid, &name);
            zrtpUserCallback->onPeer(session, (char*)name.c_str(), (int)verified, index);

            // If SAS does not contain a : then it's a short SAS
            size_t found = sas.find_first_of(':');
            if (found == std::string::npos) {
                strng = (char*)sas.c_str();
            }
            else {
                sasTmp = sas.substr(0, found);
                sasTmp.append("  ").append(sas.substr(found+1));
                strng = (char*)sasTmp.c_str();
            }
        }
        zrtpUserCallback->onNewZrtpStatus(session, strng, index);
    }
}

void CtZrtpStream::srtpSecretsOff(EnableSecurity part) {
    if (part == ForSender) {
        delete sendSrtp;
        delete sendSrtcp;
        sendSrtp = NULL;
        sendSrtcp = NULL;
    }
    if (part == ForReceiver) {
        delete recvSrtp;
        delete recvSrtcp;
        recvSrtp = NULL;
        recvSrtcp = NULL;
    }
}

int32_t CtZrtpStream::activateTimer(int32_t time) {
    std::string s("ZRTP");
    if (staticTimeoutProvider != NULL) {
        staticTimeoutProvider->requestTimeout(time, this, s);
    }
    return 1;
}

int32_t CtZrtpStream::cancelTimer() {
    std::string s("ZRTP");
    if (staticTimeoutProvider != NULL) {
        staticTimeoutProvider->cancelRequest(this, s);
    }
    return 1;
}

void CtZrtpStream::handleTimeout(const std::string &c) {
    if (zrtpEngine != NULL) {
        zrtpEngine->processTimeout();
    }
}

void CtZrtpStream::handleGoClear() {
    fprintf(stderr, "Need to process a GoClear message!");
}

void CtZrtpStream::sendInfo(MessageSeverity severity, int32_t subCode) {
    std::string *msg;

    if (severity == Info) {

        std::string peerHash;
        std::string hexString;
        size_t hexStringStart;
        switch (subCode) {
            case InfoHelloReceived:
                // The Tivi client stores the 64 char hex string only, thus
                // split the string that we get from ZRTP engine that contains
                // the version info as well (which is the right way to do because
                // the engine knows which version of the ZRTP protocol it uses.)
                if (peerHelloHash.empty())
                    break;
                peerHash = zrtpEngine->getPeerHelloHash();
                hexStringStart = peerHash.find_last_of(' ');
                hexString = peerHash.substr(hexStringStart+1);
                helloReceived = true;
                if (hexString.compare(peerHelloHash) == 0) {
                    zrtpHashMatch = true;
                    break;
                }
                if (zrtpUserCallback != NULL)
                    zrtpUserCallback->onZrtpWarning(session, (char*)"ZRTP_EVENT_WRONG_SIGNALING_HASH", index);
                break;

            case InfoSecureStateOn:
                if (type == CtZrtpSession::Master) {               // Master stream entered secure mode (security done)
                    session->masterStreamSecure(this);
                }
                // Tivi client does not expect a status change information on this
                break;

                // These two states correspond to going secure
            case InfoRespCommitReceived:
            case InfoInitDH1Received:
                prevTiviState = tiviState;
                tiviState = CtZrtpSession::eGoingSecure;
                if (zrtpUserCallback != NULL)
                    zrtpUserCallback->onNewZrtpStatus(session, NULL, index);
                break;

                // other information states are not handled by tivi client
            default:
                break;
        }
        return;
    }
    if (severity == Warning) {
        switch (subCode) {
            case WarningNoRSMatch:
                return;
                break;                          // supress this warning message

            default:
                msg = warningMap[subCode];
                if (zrtpUserCallback != NULL)
                    zrtpUserCallback->onZrtpWarning(session, (char*)msg->c_str(), index);
                return;
                break;
        }
    }
    // handle severe and ZRTP errors
    zrtpNegotiationFailed(severity, subCode);
}

void CtZrtpStream::zrtpNegotiationFailed(MessageSeverity severity, int32_t subCode) {

    std::string cs;
    std::string *strng;
    if (severity == ZrtpError) {
        if (subCode < 0) {                  // received an error packet from peer
            subCode *= -1;
            cs.assign("Received error packet: ");
        }
        else {
            cs.assign("Sent error packet: ");
        }
        strng = zrtpMap[subCode];
        if (strng != NULL)
            cs.append(*strng);
        else
            cs.append("ZRTP protocol: Unkown ZRTP error packet.");
    }
    else {
        strng = severeMap[subCode];
    }

    prevTiviState = tiviState;
    tiviState = CtZrtpSession::eError;
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->onNewZrtpStatus(session, (char*)strng->c_str(), index);
    }
}

void CtZrtpStream::zrtpNotSuppOther() {
    prevTiviState = tiviState;
    // if other party does not support ZRTP but we have SDES active set SDES state,
    // otherwise inform client about failed ZRTP negotiation.
    tiviState = isSdesActive() ? CtZrtpSession::eSecureSdes : CtZrtpSession::eNoPeer;
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->onNewZrtpStatus(session, NULL, index);
    }
}

void CtZrtpStream::synchEnter() {
    synchLock->Lock();
}

void CtZrtpStream::synchLeave() {
    synchLock->Unlock();
}

void CtZrtpStream::zrtpAskEnrollment(GnuZrtpCodes::InfoEnrollment  info) {
    // TODO: Discuss with Janis
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->onNeedEnroll(session, index, (int32_t)info);
    }
}

void CtZrtpStream::zrtpInformEnrollment(GnuZrtpCodes::InfoEnrollment  info) {
// Tivi does not use this information event
//     if (zrtpUserCallback != NULL) {
//         zrtpUserCallback->zrtpInformEnrollment(info);
//     }
}

void CtZrtpStream::signSAS(uint8_t* sasHash) {
//     if (zrtpUserCallback != NULL) {
//         zrtpUserCallback->signSAS(sasHash);
//     }
}

bool CtZrtpStream::checkSASSignature(uint8_t* sasHash) {
//     if (zrtpUserCallback != NULL) {
//         return zrtpUserCallback->checkSASSignature(sasHash);
//     }
     return false;
}

void CtZrtpStream::initStrings() {
    if (initialized) {
        return;
    }
    initialized = true;

    infoMap.insert(std::pair<int32_t, std::string*>(InfoHelloReceived, new std::string("Hello received, preparing a Commit")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoCommitDHGenerated, new std::string("Commit: Generated a public DH key")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoRespCommitReceived, new std::string("Responder: Commit received, preparing DHPart1")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoDH1DHGenerated, new std::string("DH1Part: Generated a public DH key")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoInitDH1Received, new std::string("Initiator: DHPart1 received, preparing DHPart2")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoRespDH2Received, new std::string("Responder: DHPart2 received, preparing Confirm1")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoInitConf1Received, new std::string("Initiator: Confirm1 received, preparing Confirm2")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoRespConf2Received, new std::string("Responder: Confirm2 received, preparing Conf2Ack")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoRSMatchFound, new std::string("At least one retained secrets matches - security OK")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoSecureStateOn, new std::string("Entered secure state")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoSecureStateOff, new std::string("No more security for this session")));

    warningMap.insert(std::pair<int32_t, std::string*>(WarningDHAESmismatch,
                                                new std::string("Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningGoClearReceived, new std::string("Received a GoClear message")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningDHShort,
                                                new std::string("Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningNoRSMatch, new std::string("No retained secret matches - verify SAS")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningCRCmismatch, new std::string("Internal ZRTP packet checksum mismatch - packet dropped")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningSRTPauthError, new std::string("Dropping packet because SRTP authentication failed!")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningSRTPreplayError, new std::string("Dropping packet because SRTP replay check failed!")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningNoExpectedRSMatch,
                                                new std::string("You MUST check SAS with your partner. If it doesn't match, it indicates the presence of a wiretapper.")));

    severeMap.insert(std::pair<int32_t, std::string*>(SevereHelloHMACFailed, new std::string("Hash HMAC check of Hello failed!")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereCommitHMACFailed, new std::string("Hash HMAC check of Commit failed!")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereDH1HMACFailed, new std::string("Hash HMAC check of DHPart1 failed!")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereDH2HMACFailed, new std::string("Hash HMAC check of DHPart2 failed!")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereCannotSend, new std::string("Cannot send data - connection or peer down?")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereProtocolError, new std::string("Internal protocol error occured!")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereNoTimer, new std::string("Cannot start a timer - internal resources exhausted?")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereTooMuchRetries,
                                               new std::string("Too much retries during ZRTP negotiation - connection or peer down?")));

    zrtpMap.insert(std::pair<int32_t, std::string*>(MalformedPacket, new std::string("Malformed packet (CRC OK, but wrong structure)")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(CriticalSWError, new std::string("Critical software error")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(UnsuppZRTPVersion, new std::string("Unsupported ZRTP version")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(HelloCompMismatch, new std::string("Hello components mismatch")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(UnsuppHashType, new std::string("Hash type not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(UnsuppCiphertype, new std::string("Cipher type not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(UnsuppPKExchange, new std::string("Public key exchange not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(UnsuppSRTPAuthTag, new std::string("SRTP auth. tag not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(UnsuppSASScheme, new std::string("SAS scheme not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(NoSharedSecret, new std::string("No shared secret available, DH mode required")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(DHErrorWrongPV, new std::string("DH Error: bad pvi or pvr ( == 1, 0, or p-1)")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(DHErrorWrongHVI, new std::string("DH Error: hvi != hashed data")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(SASuntrustedMiTM, new std::string("Received relayed SAS from untrusted MiTM")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(ConfirmHMACWrong, new std::string("Auth. Error: Bad Confirm pkt HMAC")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(NonceReused, new std::string("Nonce reuse")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(EqualZIDHello, new std::string("Equal ZIDs in Hello")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(GoCleatNotAllowed, new std::string("GoClear packet received, but not allowed")));

    enrollMap.insert(std::pair<int32_t, std::string*>(EnrollmentRequest, new std::string("Trusted MitM enrollment requested")));
    enrollMap.insert(std::pair<int32_t, std::string*>(EnrollmentCanceled, new std::string("Trusted MitM enrollment canceled by user")));
    enrollMap.insert(std::pair<int32_t, std::string*>(EnrollmentFailed, new std::string("Trusted MitM enrollment failed")));
    enrollMap.insert(std::pair<int32_t, std::string*>(EnrollmentOk, new std::string("Trusted MitM enrollment OK")));
}
