#include <netinet/in.h>
#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpStateClass.h>
#include <libzrtpcpp/ZrtpCrc32.h>
#include <srtp/CryptoContext.h>
#include <srtp/CryptoContextCtrl.h>
#include <srtp/SrtpHandler.h>

#include <CtZrtpStream.h>
#include <CtZrtpCallback.h>
#include <cryptcommon/aes.h>

static TimeoutProvider<std::string, CtZrtpStream*>* staticTimeoutProvider = NULL;

static std::map<int32_t, std::string*> infoMap;
static std::map<int32_t, std::string*> warningMap;
static std::map<int32_t, std::string*> severeMap;
static std::map<int32_t, std::string*> zrtpMap;
static std::map<int32_t, std::string*> enrollMap;
static int initialized = 0;

using namespace GnuZrtpCodes;

CtZrtpStream::CtZrtpStream(): index(CtZrtpSession::AudioStream), type(CtZrtpSession::NoStream), zrtpEngine(NULL),
    tiviState(CtZrtpSession::eLookingPeer), ownSSRC(0), enableZrtp(0),
    started(0), recvSrtp(NULL), recvSrtcp(NULL), sendSrtp(NULL), sendSrtcp(NULL),
    zrtpUserCallback(NULL), session(NULL), senderZrtpSeqNo(0), peerSSRC(0),
    protect(0), unprotect(0), unprotectFailed(0), srtcpIndex(0)
{
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
    stopZrtp();
}

void CtZrtpStream::stopZrtp() {

    if (zrtpEngine != NULL) {
        delete zrtpEngine;
        zrtpEngine = NULL;
        started = false;
    }
}

bool CtZrtpStream::processOutgoingRtp(uint8_t *buffer, size_t length, size_t *newLength) {
    if (sendSrtp == NULL) {
        *newLength = length;
        return true;
    }
    else {
        bool rc = SrtpHandler::protect(sendSrtp, buffer, length, newLength);
        protect++;
        return rc;
    }

}

int32_t CtZrtpStream::processIncomingRtp(uint8_t *buffer, size_t length, size_t *newLength) {
    // check if this could be a real RTP/SRTP packet.
    if ((*buffer & 0xf0) == 0x80) {             //  A real RTP, check if we are in secure mode
        if (recvSrtp == NULL) {                 // SRTP inactive, just return with newLength set
            *newLength = length;
        }
        else {
            bool rc = SrtpHandler::unprotect(recvSrtp, buffer, length, newLength);
            if (rc == 1) {
                unprotect++;
            }
            else {
                if (rc == -1) {
                    sendInfo(Warning, WarningSRTPauthError);
                }
                else {
                    sendInfo(Warning, WarningSRTPreplayError);
                }
                unprotectFailed++;
                return rc;
            }
        }
       return 1;
    }

    // At this point we assume the packet is a ZRTP packet. Process it
    // if ZRTP processing is started. In any case, let the application drop
    // the packet.
    if (started) {
        // Get CRC value into crc (see above how to compute the offset)
        uint16_t temp = length - CRC_SIZE;
        uint32_t crc = *(uint32_t*)(buffer + temp);
        crc = ntohl(crc);

        if (!zrtpCheckCksum(buffer, temp, crc)) {
                sendInfo(Warning, WarningCRCmismatch);
            return 0;
        }

        uint32_t magic = *(uint32_t*)(buffer + 4);
        magic = ntohl(magic);

        // Check if it is really a ZRTP packet, return, no further processing
        if (magic != ZRTP_MAGIC) {
            return 0;
        }
        // this now points beyond to the plain ZRTP message.
        unsigned char* zrtpMsg = (buffer + 12);

        // store peer's SSRC in host order, used when creating the CryptoContext
        peerSSRC = *(uint32_t*)(buffer + 8);
        peerSSRC = ntohl(peerSSRC);
        zrtpEngine->processZrtpMessage(zrtpMsg, peerSSRC);
    }
    return 0;
}

/*
 * Here the callback methods required by the ZRTP implementation
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
    pus[1] = htons(senderZrtpSeqNo++);
    pui[1] = htonl(ZRTP_MAGIC);
    pui[2] = htonl(ownSSRC);            // ownSSRC is stored in host order

    /* Copy ZRTP message data behind the header data */
    memcpy(zrtpBuffer+12, data, length);

    /* Setup and compute ZRTP CRC */
    crc = zrtpGenerateCksum(zrtpBuffer, totalLen-CRC_SIZE);

    /* convert and store CRC in ZRTP packet.*/
    crc = zrtpEndCksum(crc);
    *(uint32_t*)(zrtpBuffer+totalLen-CRC_SIZE) = htonl(crc);

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
        sendSrtp = senderCryptoContext;
        sendSrtp->deriveSrtpKeys(0L);

        sendSrtcp = senderCryptoContextCtrl;
        sendSrtcp->deriveSrtcpKeys();
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
        recvSrtp = recvCryptoContext;
        recvSrtp->deriveSrtpKeys(0L);

        recvSrtcp = recvCryptoContextCtrl;
        recvSrtcp->deriveSrtcpKeys();
    }
    return true;
}

void CtZrtpStream::srtpSecretsOn(std::string cipher, std::string sas, bool verified)
{
     // p->setStatus(ctx->peer_mitm_flag || iMitm?CTZRTP::eSecureMitm:CTZRTP::eSecure,&buf[0],iIsVideo);

     // TODO: deliver an enrollement event at this point first?
     // the cipher string 'c' ends with "/MitM" if we saw a SAS relay message.
    prevTiviState = tiviState;
    size_t pos = cipher.find ("MitM", cipher.size() - 4, 4);
    if (pos == std::string::npos)
        tiviState = CtZrtpSession::eSecure;
    else
        tiviState = CtZrtpSession::eSecureMitm;

    if (zrtpUserCallback != NULL) {
        char *strng = NULL;            // TODO: fill this with peer's name if available
        zrtpUserCallback->onPeer(session, strng, (int)verified, index);

        // get the SAS string if it is not empty.
        if (!sas.empty())
            strng = (char*)sas.c_str();
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
        msg = infoMap[subCode];

        switch (subCode) {

            case InfoSecureStateOn:
                if (type == CtZrtpSession::Master) {               // Master stream entered secure mode (security done)
                    session->masterStreamSecure(this);
                }
                // Tivi client does not expect a status change information on this
                // TODO: check for InfoHelloReceived subcode and handle zrtp hash checks
                break;

                // These two states correspond to going secure
            case InfoRespCommitReceived:
            case InfoInitDH1Received:
                // p->setStatus(CTZRTP::eGoingSecure,NULL,iIsVideo);
                prevTiviState = tiviState;
                tiviState = CtZrtpSession::eGoingSecure;
                break;

                // other information states are not handled by tivi client
            default:
                break;
        }
        return;
    }
    if (severity == Warning) {
        if (subCode == WarningNoExpectedRSMatch) {          // Tivi needs this after we have SAS? The just remember event
            // TODO: remember and return, discuss with Janis. Deliver after secure state reached?
        }
        msg = warningMap[subCode];
        zrtpUserCallback->onZrtpWarning(session, (char*)msg->c_str(), index);
        return;
    }
    zrtpNegotiationFailed(severity, subCode);
}

void CtZrtpStream::zrtpNegotiationFailed(MessageSeverity severity, int32_t subCode) {

//    if(event==ZRTP_EVENT_PROTOCOL_ERROR)
//        p->setStatus(CTZRTP::eError,getMsgByID(NULL,ctx->last_error),iIsVideo);

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
//    case ZRTP_EVENT_NO_ZRTP:
//            p->setStatus(CTZRTP::eNoPeer,NULL,iIsVideo);
//            break;

    prevTiviState = tiviState;
    tiviState = CtZrtpSession::eNoPeer;
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->onNewZrtpStatus(session, NULL, index);
    }
}

void CtZrtpStream::synchEnter() {
    synchLock.Lock();
}

void CtZrtpStream::synchLeave() {
    synchLock.Unlock();
}

void CtZrtpStream::zrtpAskEnrollment(GnuZrtpCodes::InfoEnrollment  info) {
    // TODO: remember enrollment event, deliver together with security on? Discuss with Janis
    if (zrtpUserCallback != NULL) {
        zrtpUserCallback->onNeedEnroll(session, index);
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
