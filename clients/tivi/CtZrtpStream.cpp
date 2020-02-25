/*
 * Copyright (c) 2019 Silent Circle.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 * Tivi client glue code for ZRTP.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <cinttypes>
#include <cstdio>

#include <common/osSpecifics.h>

#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpStateClass.h>
#include <libzrtpcpp/ZrtpCrc32.h>
#include <srtp/CryptoContext.h>
#include <srtp/CryptoContextCtrl.h>

#include <CtZrtpStream.h>
#include <CtZrtpCallback.h>
#include <cryptcommon/aes.h>
#include <cryptcommon/ZrtpRandom.h>
#include <common/ZrtpTimeoutProvider.h>
#include <cryptcommon/sidhp751/keymanagement/SidhKeyManagement.h>

// #define DEBUG_CTSTREAM
#ifdef DEBUG_CTSTREAM
static char debBuf[500];
#define DEBUG(deb)   deb
#else
#define DEBUG(deb)
#endif

using namespace GnuZrtpCodes;
using namespace std;

#if !defined (_WITHOUT_TIVI_ENV) && defined AXO_SUPPORT
const string getOwnAxoIdKey();
void checkRemoteAxoIdKey(const string user, const string devId, const string pubKey, int32_t verifyState);
int getCallInfo(int iCallID, const char *key, char *p, int iMax);
#endif

static zrtp::ZrtpTimeoutProvider *staticTimeoutProvider = nullptr;

static std::map<int32_t, std::string*> infoMap;
static std::map<int32_t, std::string*> warningMap;
static std::map<int32_t, std::string*> severeMap;
static std::map<int32_t, std::string*> zrtpMap;
static std::map<int32_t, std::string*> enrollMap;
static int initialized = 0;

static const char* peerHelloMismatchMsg = "s2_c050: Received Hello hash does not match computed Hello hash"; 
static const char* srtpDecodeFailedMsg  = "s2_c051: Parsing of received SRTP packet failed"; 
static const char* zrtpEncap = "zrtp";
static const char* noLocalSrtp          = "s3_c103: Local SRTP not enabled.";
//static const char* zrtpHashMismatch     = "s3_c106: SIP ZRTP-hash failed to match Hello message.";
static const char* noZrtpTunnel         = "s3_c104: ZRTP tunneling not enabled.";
static const char* noZrtpHashInSip      = "s3_c105: No ZRTP-hash received in SIP.";


/**
 * The following code is for internal logging only
 *
 */
static void (*_zrtp_log_cb)(void *ret, const char *tag, const char *buf) = nullptr;
static void *pLogRet=nullptr;

// this function must be public. Tivi C++ code set its internal log function
void set_zrtp_log_cb(void *pRet, void (*cb)(void *, const char *, const char *)) {
    _zrtp_log_cb=cb;
    pLogRet=pRet;
}

// This function is static (could be global) to reduce visibility
/*static*/ void zrtp_log( const char *tag, const char *buf){
    if(_zrtp_log_cb){
        _zrtp_log_cb(pLogRet, tag, buf);
    }
}

CtZrtpStream::CtZrtpStream():
    index(CtZrtpSession::AudioStream), type(CtZrtpSession::NoStream), zrtpEngine(nullptr),
    ownSSRC(0), zrtpProtect(0), sdesProtect(0), zrtpUnprotect(0), sdesUnprotect(0), unprotectFailed(0),
    enableZrtp(false), started(false), isStopped(false), discriminatorMode(false), session(nullptr), tiviState(CtZrtpSession::eLookingPeer),
    prevTiviState(CtZrtpSession::eLookingPeer), recvSrtp(nullptr), recvSrtcp(nullptr), sendSrtp(nullptr), sendSrtcp(nullptr),
    zrtpUserCallback(nullptr), zrtpSendCallback(nullptr), senderZrtpSeqNo(0), peerSSRC(0), zrtpHashMatch(false),
    sasVerified(false), helloReceived(false), useSdesForMedia(false), useZrtpTunnel(false), zrtpEncapSignaled(false), 
    sdes(nullptr), supressCounter(0), srtpAuthErrorBurst(0), srtpReplayErrorBurst(0), srtpDecodeErrorBurst(0),
    zrtpCrcErrors(0), role(NoRole), errorInfoIndex(0), numErrorArrayWrap(0)
{

    if (staticTimeoutProvider == nullptr) {
        staticTimeoutProvider = new zrtp::ZrtpTimeoutProvider;
    }
    initStrings();
    ZrtpRandom::getRandomData((uint8_t*)&senderZrtpSeqNo, 2);
    senderZrtpSeqNo &= 0x7fffU;
    memset((void*)srtpErrorInfo, 0, sizeof(srtpErrorInfo));
}

void CtZrtpStream::releaseTimeoutProvider() {
    auto timeoutProvider = staticTimeoutProvider;       // clear first before deleting
    staticTimeoutProvider = nullptr;
    delete timeoutProvider;
}

void CtZrtpStream::setUserCallback(CtZrtpCb* ucb) {
    zrtpUserCallback = ucb;
}

void CtZrtpStream::setSendCallback(CtZrtpSendCb* scb) {
    zrtpSendCallback = scb;
}

CtZrtpStream::~CtZrtpStream() {
    stopStream();
}

void CtZrtpStream::stopStream() {

    // If we got only a small amount of valid SRTP packets after ZRTP negotiation then
    // assume that our peer couldn't store the RS data, thus make sure we have a second
    // retained shared secret available. Refer to RFC 6189bis, chapter 4.6.1
    // 50 packets are about 1 second of audio data
    if (zrtpEngine != nullptr && zrtpUnprotect < 10 && !zrtpEngine->isMultiStream()) {
        zrtpEngine->setRs2Valid();
    }

    sidh751KM::SidhKeyManagement::stopKeyGeneration();

    index = CtZrtpSession::AudioStream;
    type = CtZrtpSession::NoStream;
    tiviState = CtZrtpSession::eLookingPeer;
    prevTiviState = CtZrtpSession::eLookingPeer;
    ownSSRC = 0;
    enableZrtp = false;
    started = false;
    isStopped = false;
    discriminatorMode = false;
    peerSSRC = 0;

    zrtpUnprotect = 0;
    sdesUnprotect = 0;
    zrtpProtect = 0;
    sdesProtect = 0;
    unprotectFailed = 0;

    ZrtpRandom::getRandomData((uint8_t*)&senderZrtpSeqNo, 2);
    senderZrtpSeqNo &= 0x7fffU;
    zrtpHashMatch= false;
    sasVerified = false;
    useSdesForMedia = false;
    useZrtpTunnel = false;
    zrtpEncapSignaled = false;
    supressCounter = 0;
    srtpAuthErrorBurst = 0;
    srtpReplayErrorBurst = 0;
    srtpDecodeErrorBurst = 0;
    zrtpCrcErrors = 0;
    helloReceived = false;

    peerHelloHashes.clear();

    delete zrtpEngine;
    zrtpEngine = nullptr;

    delete recvSrtp;
    recvSrtp = nullptr;

    delete recvSrtcp;
    recvSrtcp = nullptr;

    delete sendSrtp;
    sendSrtp = nullptr;

    delete sendSrtcp;
    sendSrtcp = nullptr;

    delete sdes;
    sdes = nullptr;

    memset((void*)srtpErrorInfo, 0, sizeof(srtpErrorInfo));
    numErrorArrayWrap = 0;

    // Don't delete the next classes, we don't own them.
    zrtpUserCallback = nullptr;
    zrtpSendCallback = nullptr;
    session = nullptr;
}

bool CtZrtpStream::processOutgoingRtp(uint8_t *buffer, size_t length, size_t *newLength) {
    bool rc = true;
    if (sendSrtp == nullptr) {                 // ZRTP/SRTP inactive
        *newLength = length;
        // Check if ZRTP engine is started and check states to determine if we should send the RTP packet.
        // Do not send in states: CommitSent, WaitDHPart2, WaitConfirm1, WaitConfirm2, WaitConfAck
//        if (started && (zrtpEngine->inState(CommitSent) || zrtpEngine->inState(WaitDHPart2) || zrtpEngine->inState(WaitConfirm1) ||
//            zrtpEngine->inState(WaitConfirm2) || zrtpEngine->inState(WaitConfAck))) {
//            ZrtpRandom::addEntropy(buffer, length);
//             return false;
//         }
        if (useSdesForMedia && sdes != nullptr) {   // SDES stream available, let SDES protect if necessary
            rc = sdes->outgoingRtp(buffer, length, newLength);
            sdesProtect++;
        }
         /* In discriminator mode:
          * No ZRTP/SRTP and no SDES/SRTP available
          * If we would send RTP rather than SRTP for any reason, we must drop the call.
          */
        else if (discriminatorMode) {
            if (zrtpUserCallback != nullptr)
                zrtpUserCallback->onDiscriminatorException(session, (char*)noLocalSrtp, index);
            return false;
        }
        return rc;
    }
    // At this point ZRTP/SRTP is active
    if (useSdesForMedia && sdes != nullptr) {       // We still have a SDES - other client did not send zrtp-hash thus we protect twice
        rc = sdes->outgoingRtp(buffer, length, newLength);
        if (!rc) {
            return rc;
        }
        sdesProtect++;
    }
    rc = SrtpHandler::protect(sendSrtp, buffer, length, newLength);
    if (rc) {
        zrtpProtect++;
    }
    return rc;
}

int32_t CtZrtpStream::processIncomingRtp(uint8_t *buffer, const size_t length, size_t *newLength) {
    int32_t rc = 0;
    // check if this could be a real RTP/SRTP packet.
    if ((*buffer & 0xc0U) == 0x80) {            // A real RTP, check if we are in secure mode
        if (supressCounter < supressWarn)       // Don't report SRTP problems while in startup mode
            supressCounter++;

        if (recvSrtp == nullptr) {                 // no ZRTP/SRTP available
            if (!useSdesForMedia || sdes == nullptr) {  // no SDES stream available, just set length and return
                *newLength = length;
                /*
                 * In discriminator mode:
                 * If we receive RTP rather than SRTP we must silently discard the packets.
                 * No message (discard silently)
                 */
                if (discriminatorMode) {
                    return 0;                   // discards packet silently
                }
                return 1;
            }
            rc = sdes->incomingRtp(buffer, length, newLength, srtpErrorElement());
            if (rc == 1) {                      // SDES unprotect OK, do some statistics and return success
                sdesUnprotect++;
                if (*sdesTempBuffer != 0)       // clear SDES crypto string if not already done
                    memset(sdesTempBuffer, 0, maxSdesString);
            }
        }
        else {
            // At this point we have an active ZRTP/SRTP context, unprotect with ZRTP/SRTP first
            rc = SrtpHandler::unprotect(recvSrtp, buffer, length, newLength, srtpErrorElement());
            if (rc == 1) {
                zrtpUnprotect++;
                // Got a good SRTP, check state and if in WaitConfAck (an Initiator state)
                // then simulate a conf2Ack, refer to RFC 6189, chapter 4.6, last paragraph
                if (zrtpEngine->inState(WaitConfAck)) {
                    zrtpEngine->conf2AckSecure();
                }
                if (useSdesForMedia && sdes != nullptr) {    // We still have a SDES - other client did not send matching zrtp-hash
                    rc = sdes->incomingRtp(buffer, *newLength, newLength, srtpErrorElement());
                }
            }
            else if (sdes != nullptr) {
                rc = sdes->incomingRtp(buffer, length, newLength, srtpErrorElement());
            }
        }
        if (rc == 1) {
            srtpAuthErrorBurst = 0;
            srtpReplayErrorBurst = 0;
            srtpDecodeErrorBurst = 0;
            return 1;
        }
        // We come to this point only if we have some problems during SRTP unprotect
        else if (rc == 0) {
            srtpDecodeErrorBurst++; 
            errorInfoIndex++;
        }
        else if (rc == -1) {
            srtpAuthErrorBurst++;
            errorInfoIndex++;
        }
        else if (rc == -2) {
            srtpReplayErrorBurst++;
            errorInfoIndex++;
        }

        unprotectFailed++;
        if (supressCounter >= supressWarn) {
            if (rc == 0 && srtpDecodeErrorBurst > srtpErrorBurstThreshold && zrtpUserCallback != nullptr) {
                zrtpUserCallback->onZrtpWarning(session, (char*)srtpDecodeFailedMsg, index);
            }
            if (rc == -1 && srtpAuthErrorBurst >= srtpErrorBurstThreshold) {
                sendInfo(Warning, WarningSRTPauthError);
            }
            if (rc == -2 && srtpReplayErrorBurst >= srtpErrorBurstThreshold){
                sendInfo(Warning, WarningSRTPreplayError);
            }
        }
        return rc;
    }

    // At this point we assume the packet is not a RTP packet. Check if it is a ZRTP packet.
    // Process it if ZRTP processing is started. In any case, let the application drop
    // the packet.
    if (started) {
        // Fixed header length + smallest ZRTP packet (includes CRC)
        if (length < (12 + sizeof(HelloAckPacket_t))) // data too small, dismiss
            return 0;

        size_t useLength = length;
 
        uint32_t magic = *(uint32_t*)(buffer + 4);
        magic = zrtpNtohl(magic);

        // Check if it is really a ZRTP packet, return, no further processing
        if (magic != ZRTP_MAGIC) {
            return 0;
        }
        if (useZrtpTunnel) {
            size_t newLengthTunnel;
            *buffer = 0x80;                                    // make it look like a real RTP packet
            rc = sdes->incomingZrtpTunnel(buffer, length, &newLengthTunnel, srtpErrorElement());
            if (rc < 0) {
                errorInfoIndex++;
                if (rc == -1) {
                    zrtp_log("CtZrtpStream", "Receiving tunneled ZRTP - SRTP failure -1");
                    sendInfo(Warning, WarningSRTPauthError*-1);
                }
                else {
                    zrtp_log("CtZrtpStream", "Receiving tunneled ZRTP - SRTP failure -2");
                    sendInfo(Warning, WarningSRTPreplayError*-1);
                }
                return 0;
            }
            if (*sdesTempBuffer != 0)                          // clear SDES crypto string if not already done
                memset(sdesTempBuffer, 0, maxSdesString);
            useLength = newLengthTunnel + CRC_SIZE;                  // length check assumes a ZRTP CRC
        }
        else {
            /*
             * In discriminator mode:
             * If we receive a ZRTP packet not tunneled in SRTP it must be silently discarded.
             * No message (discard silently)
             */
            if (discriminatorMode) {
                return 0;
            }
            DEBUG(char tmpBuffer[500];)
            useZrtpTunnel = false;
            // Get CRC value into crc (see above how to compute the offset)
            uint16_t temp = length - CRC_SIZE;
            uint32_t crc = *(uint32_t*)(buffer + temp);
            crc = zrtpNtohl(crc);
            if (!zrtpCheckCksum(buffer, temp, crc)) {
                zrtpCrcErrors++;
                if (zrtpCrcErrors > 15) {
                    DEBUG(snprintf(debBuf, 499, "len: %d, sdes: %p, sdesMedia: %d, zrtpEncap: %d", temp, (void*)sdes, useSdesForMedia, zrtpEncapSignaled); zrtp_log("CtZrtpStream", debBuf);)

                    sendInfo(Warning, WarningCRCmismatch);
                    zrtpCrcErrors = 0;
                }
                return 0;
            }
        }
        // this now points to the plain ZRTP message.
        unsigned char* zrtpMsg = (buffer + 12);

        // store peer's SSRC in host order, used when creating the CryptoContext
        if (peerSSRC == 0) {
            peerSSRC = *(uint32_t*)(buffer + 8);
            peerSSRC = zrtpNtohl(peerSSRC);
        }
        zrtpEngine->processZrtpMessage(zrtpMsg, peerSSRC, useLength);
    }
    return 0;
}

int CtZrtpStream::getSignalingHelloHash(char *hHash, int32_t idx) {

    if (hHash == nullptr)
        return 0;

    std::string hash;
    hash = zrtpEngine->getHelloHash(idx);
    strcpy(hHash, hash.c_str());
    return hash.size();
}

void CtZrtpStream::setSignalingHelloHash(const char *hHash) {
    sidh751KM::SidhKeyManagement::initialize();
    synchEnter();

    // set new timer values for ZRTP retransmission
    // Reason: if the SIP packet contains a hello hash then we know that the other client
    // support ZRTP, thus we can safely extend the number of Hello (T1) resend counters and
    // also set the other resend counters (T2) to indefinite (-1).
    zrtpEngine->setT1Resend(100);
    zrtpEngine->setT1ResendExtend(200);
    zrtpEngine->setT2Resend(-1);

    std::string hashStr;
    hashStr.assign(hHash);

    bool found = false;
    for (const auto& it : peerHelloHashes) {
        if (it == hashStr) {
            found = true;
            break;
        }
    }
    if (!found)
        peerHelloHashes.push_back(hashStr);

    // Could be empty in case Hello was not yet received, will be handled in sendInfo(...) function
    std::string ph = zrtpEngine->getPeerHelloHash();
    if (ph.empty()) {
        synchLeave();
        return;
    }
    size_t hexStringStart = ph.find_last_of(' ');
    std::string hexString = ph.substr(hexStringStart+1);

    for (const auto& it : peerHelloHashes) {
        bool match;
        if (it.size() > SHA256_DIGEST_LENGTH*2)      // got the full string incl. version prefix, compare with full peer hash string
            match = it == ph;
        else
            match = it == hexString;
        if (match) {
            zrtpHashMatch = true;
            // We have a matching zrtp-hash. If ZRTP/SRTP is active we may need to release
            // an existing SDES stream.
            if (sdes != nullptr && sendSrtp != nullptr && recvSrtp != nullptr) {
                useSdesForMedia = false;
            }
            break;
        }
    }
    /*
     * In discriminator mode:
     * If the received zrtp-hash value in the signaling does not match the hash of the actual received ZRTP Hello message, we must drop the call.
     */
    if (!zrtpHashMatch && zrtpUserCallback != nullptr) {
        if (discriminatorMode)
            zrtpUserCallback->onDiscriminatorException(session, (char*)peerHelloMismatchMsg, index);
        else
            zrtpUserCallback->onZrtpWarning(session, (char*)peerHelloMismatchMsg, index);
    }
    synchLeave();
}

int CtZrtpStream::isSecure() {
    return tiviState == CtZrtpSession::eSecure || tiviState == CtZrtpSession::eSecureMitm ||
           tiviState == CtZrtpSession::eSecureMitmVia || tiviState == CtZrtpSession::eSecureSdes;
}


#define T_ZRTP_LB(_K,_V)                                               \
        if(iLen+1 == sizeof(_K) && strncmp(key, _K, iLen) == 0) {      \
            return ::snprintf(p, maxLen, "%s", _V);}

#define T_ZRTP_F(_K,_FV)                                               \
        if(iLen+1 == sizeof(_K) && strncmp(key,_K, iLen) == 0) {       \
            return ::snprintf(p, maxLen, "%d", (!!(info->secretsCached & _FV)) << (!!(info->secretsMatchedDH & _FV)));}

#define T_ZRTP_I(_K,_I)                                                \
        if(iLen+1 == sizeof(_K) && strncmp(key,_K, iLen) == 0) {       \
            return ::snprintf(p, maxLen, "%d", _I);}

#define T_ZRTP_L(_K,_I)                                                \
        if(iLen+1 == sizeof(_K) && strncmp(key,_K, iLen) == 0) {       \
            return ::snprintf(p, maxLen, "%" PRId64, _I);}

int CtZrtpStream::getInfo(const char *key, char *p, int maxLen) {

//     if ((sdes == nullptr /*&& !started*/) || isStopped || !isSecure())
//         return 0;

    memset(p, 0, maxLen);
    const ZRtp::zrtpInfo *info = nullptr;
    ZRtp::zrtpInfo tmpInfo;

    int iLen = strlen(key);

    // set the security state as a combination of tivi state and stateflags
    uint32_t secState = static_cast<uint32_t>(tiviState) & 0xffU;
    if (useSdesForMedia)
        secState |= 0x100U;

    T_ZRTP_I("sec_state", secState)
    T_ZRTP_I("peerDisclosureFlag", zrtpEngine->isPeerDisclosureFlag()? 1 : 0)
    T_ZRTP_LB("buildInfo",  zrtpBuildInfo)

    // Compute Hello-hash info string
    const char *strng = nullptr;
    if (peerHelloHashes.empty()) {
        strng = "None";
    }
    else if (zrtpHashMatch) {
        strng = "Good";
    }
    else {
        strng = !sdes || helloReceived ? "Bad" : "No hello";
    }
    T_ZRTP_LB("sdp_hash", strng)

    T_ZRTP_L("sec_since", zrtpEngine->getSecureSince())

    std::string client = zrtpEngine->getPeerProtocolVersion();
    if (role != NoRole) {
        if (useZrtpTunnel)
            client.append(role == Initiator ? "(IT)" : "(RT)");
        else
            client.append(role == Initiator ? "(I)" : "(R)");
    }
    T_ZRTP_LB("lbClient",  zrtpEngine->getPeerClientId().c_str())
    T_ZRTP_LB("lbVersion", client.c_str())

    if (recvSrtp != nullptr || sendSrtp != nullptr) {
        info = &zrtpEngine->getDetailInfo();

        if (iLen == 1 && key[0] == 'v') {
            return snprintf(p, maxLen, "%d", sasVerified);
        }
        if(strncmp("sc_secure", key, iLen) == 0) {
            int v = (zrtpHashMatch && sasVerified && !peerHelloHashes.empty() && tiviState == CtZrtpSession::eSecure);

            if (v && (info->secretsCached & ZRtp::Rs1) == 0  && !sasVerified)
                v = 0;
            if (v && (info->secretsMatched & ZRtp::Rs1) == 0 && !sasVerified)
                v = 0;
            return snprintf(p, maxLen, "%d", v);
        }
    }
    else if (useSdesForMedia && sdes != nullptr) {
        T_ZRTP_LB("lbClient",      (const char*)"SDP/S")
        T_ZRTP_LB("lbVersion",     (const char*)"")

        tmpInfo.secretsMatched = 0;
        tmpInfo.secretsCached = 0;
        tmpInfo.hash = (const char*)"";
        if (sdes->getHmacTypeMix() == ZrtpSdesStream::MIX_NONE) {
            tmpInfo.pubKey = (const char*)"SIP SDP/S";
        }
        else {
            if (sdes->getCryptoMixAttribute(mixAlgoName, sizeof(mixAlgoName)) > 0)
                tmpInfo.hash = mixAlgoName;
            tmpInfo.pubKey = (const char*)"SIP SDP/S-MIX";
        }
        tmpInfo.cipher = sdes->getCipher();
        tmpInfo.authLength = sdes->getAuthAlgo();
        info = &tmpInfo;
    }
    else
        return 0;

    T_ZRTP_F("rs1",ZRtp::Rs1)
    T_ZRTP_F("rs2",ZRtp::Rs2)
    T_ZRTP_F("aux",ZRtp::Aux)
    T_ZRTP_F("pbx",ZRtp::Pbx)

    T_ZRTP_LB("lbChiper",      info->cipher)
    T_ZRTP_LB("lbAuthTag",     info->authLength)
    T_ZRTP_LB("lbHash",        info->hash)
    T_ZRTP_LB("lbKeyExchange", info->pubKey)

    return 0;
}

int CtZrtpStream::getNumberOfCountersZrtp() {
    return zrtpEngine->getNumberOfCountersZrtp();
}

int CtZrtpStream::getCountersZrtp(int32_t* counters) {
    return zrtpEngine->getCountersZrtp(counters);
}

int CtZrtpStream::enrollAccepted(char *p) {
    zrtpEngine->acceptEnrollment(true);

    uint8_t peerZid[IDENTIFIER_LEN];
    std::string name;

    zrtpEngine->getPeerZid(peerZid);
    int32_t nmLen = zrtpEngine->getZidCache()->getPeerName(peerZid, &name);

    if (nmLen == 0)
        zrtpEngine->getZidCache()->putPeerName(peerZid, std::string(p));
    return CtZrtpSession::ok;
}

int CtZrtpStream::enrollDenied() {
    zrtpEngine->acceptEnrollment(false);

    uint8_t peerZid[IDENTIFIER_LEN];
    std::string name;

    zrtpEngine->getPeerZid(peerZid);
    int32_t nmLen = zrtpEngine->getZidCache()->getPeerName(peerZid, &name);

    if (nmLen == 0)
        zrtpEngine->getZidCache()->putPeerName(peerZid, std::string(""));
    return CtZrtpSession::ok;
}


bool CtZrtpStream::createSdes(char *cryptoString, size_t *maxLen, const ZrtpSdesStream::sdesSuites sdesSuite) {
    if (isSecure() || isSdesActive())   // don't take action if we are already secure or SDES already in active state
        return false;

    if (sdes == nullptr)
        sdes = new ZrtpSdesStream(sdesSuite);

    if (sdes == nullptr || !sdes->createSdes(cryptoString, maxLen, true)) {
        delete sdes;
        sdes = nullptr;
        return false;
    }
    return true;
}

bool CtZrtpStream::parseSdes(char *recvCryptoStr, size_t recvLength, char *sendCryptoStr, size_t *sendLength, bool sipInvite) {
    if (isSecure() || isSdesActive())   // don't take action if we are already secure or SDES already in active state
        return false;

    // The ZrtpSdesStream determines its suite by parsing the crypto string.
    if (sdes == nullptr)
        sdes = new ZrtpSdesStream();

    if (sdes == nullptr || !sdes->parseSdes(recvCryptoStr, recvLength, sipInvite))
        goto cleanup;

    if (!sipInvite) {
        size_t len;
        if (sendCryptoStr == nullptr) {
            sendCryptoStr = sdesTempBuffer;
            len = maxSdesString;
            sendLength = &len;
        }
        if (!sdes->createSdes(sendCryptoStr, sendLength, sipInvite))
            goto cleanup;
    }
    if (sdes->getState() == ZrtpSdesStream::SDES_SRTP_ACTIVE) {
        tiviState = CtZrtpSession::eSecureSdes;
        if (zrtpUserCallback != nullptr) {
            zrtpUserCallback->onNewZrtpStatus(session, nullptr, index);    // Inform client about new state
        }
        useSdesForMedia = true;
        if (zrtpEncapSignaled) {
            useZrtpTunnel = true;
        }
        return true;
    }

 cleanup:
    useSdesForMedia = false;
    useZrtpTunnel = false;
    delete sdes;
    sdes = nullptr;
    return false;
}

bool CtZrtpStream::getSavedSdes(char *sendCryptoStr, size_t *sendLength) {

    size_t len = strlen(sdesTempBuffer);

    if (len >= *sendLength)
        return false;

    strcpy(sendCryptoStr, sdesTempBuffer);
    *sendLength = len;

    if (zrtpUserCallback != nullptr)
        zrtpUserCallback->onNewZrtpStatus(session, nullptr, index);
    return true;
}

bool CtZrtpStream::isSdesActive() {
    return (sdes != nullptr && sdes->getState() == ZrtpSdesStream::SDES_SRTP_ACTIVE);
}

int CtZrtpStream::getCryptoMixAttribute(char *algoNames, size_t length) {

    if (sdes == nullptr)
        sdes = new ZrtpSdesStream();

    return sdes->getCryptoMixAttribute(algoNames, length);
}

void CtZrtpStream::resetSdesContext(bool force) {
    if (force || !isSdesActive()) {
        useSdesForMedia = false;
        useZrtpTunnel = false;
        delete sdes;
        sdes = nullptr;
    }
}

bool  CtZrtpStream::setCryptoMixAttribute(const char *algoNames) {
    if (isSecure() || isSdesActive())   // don't take action if we are already secure or SDES already in active state
        return false;

    if (sdes == nullptr)
        sdes = new ZrtpSdesStream();

    return sdes->setCryptoMixAttribute(algoNames);
}

int32_t CtZrtpStream::getNumberSupportedVersions() {

    return ZRtp::getNumberSupportedVersions();
}

const char* CtZrtpStream::getZrtpEncapAttribute() {
    return zrtpEncap;
}

void CtZrtpStream::setZrtpEncapAttribute(const char *attribute) {
    if (attribute != nullptr && strncmp(attribute, zrtpEncap, 4) == 0) {
        zrtpEncapSignaled = true;
        if (useSdesForMedia) {
            useZrtpTunnel = true;
        }
    }
}

void CtZrtpStream::setAuxSecret(const unsigned char *secret, uint32_t length) {
    zrtpEngine->setAuxSecret((unsigned char*)secret, length);
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

    size_t newLength;

    if ((totalLen) > maxZrtpSize)
        return 0;

    /* Get some handy pointers */
    pus = (uint16_t*)zrtpBuffer;
    pui = (uint32_t*)zrtpBuffer;

    /* set up fixed ZRTP header */
    *(zrtpBuffer + 1) = 0;
    pus[1] = zrtpHtons(senderZrtpSeqNo++);
    pui[1] = zrtpHtonl(ZRTP_MAGIC);
    pui[2] = zrtpHtonl(ownSSRC);            // ownSSRC is stored in host order

    memcpy(zrtpBuffer+12, data, length);    // Copy ZRTP message data behind the header data

    if (useZrtpTunnel) {
        *zrtpBuffer = 0x80;                                            // temporarily make it to a real RTP packet 
        sdes->outgoingZrtpTunnel(zrtpBuffer, totalLen-CRC_SIZE, &newLength);
        *zrtpBuffer = 0x10;                                            // invalid RTP version - refer to ZRTP spec chap 5
        totalLen = newLength;
    }
    else {
        /*
         * In discriminator mode:
         * If we would send a ZRTP packet not tunneled in SRTP, we must drop the call.
         */
        if (discriminatorMode) {
            if (zrtpUserCallback != nullptr)
                zrtpUserCallback->onDiscriminatorException(session, (char*)noZrtpTunnel, index);
            return 0;
        }
        *zrtpBuffer = 0x10;                                            // invalid RTP version - refer to ZRTP spec chap 5
        crc = zrtpGenerateCksum(zrtpBuffer, totalLen-CRC_SIZE);        // Setup and compute ZRTP CRC
        crc = zrtpEndCksum(crc);                                       // convert and store CRC in ZRTP packet.
        *(uint32_t*)(zrtpBuffer+totalLen-CRC_SIZE) = zrtpHtonl(crc);
    }

    /* Send the ZRTP packet using callback */
    if (zrtpSendCallback != nullptr) {
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

    role = secrets->role;

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
        senderCryptoContext->deriveSrtpKeys(0L);
        sendSrtp = senderCryptoContext;

        senderCryptoContextCtrl->deriveSrtcpKeys();
        sendSrtcp = senderCryptoContextCtrl;
    }
    if (part == ForReceiver) {
        // To decrypt packets: initiator uses responder keys,
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
        recvCryptoContext->deriveSrtpKeys(0L);
        recvSrtp = recvCryptoContext;

        recvCryptoContextCtrl->deriveSrtcpKeys();
        recvSrtcp = recvCryptoContextCtrl;

        supressCounter = 0;         // suppress SRTP warnings for some packets after we switch to SRTP
    }
    if (!peerHelloHashes.empty() && recvSrtp != nullptr && sendSrtp != nullptr) {
        useSdesForMedia = false;
    }
    return true;
}

void CtZrtpStream::srtpSecretsOn(std::string cipher, std::string sas, bool verified)
{
     // p->setStatus(ctx->peer_mitm_flag || iMitm?CTZRTP::eSecureMitm:CTZRTP::eSecure,&buf[0],iIsVideo);

    prevTiviState = tiviState;

    tiviState = CtZrtpSession::eSecure;
    if (cipher.find ("SASviaMitM", cipher.size() - 10, 10) != std::string::npos) { // Found: SAS via PBX
        tiviState = CtZrtpSession::eSecureMitmVia;  //eSecureMitmVia
    }
    else if ((cipher.find ("MitM", cipher.size() - 4, 4) != std::string::npos) ||
             (cipher.find ("EndAtMitM", cipher.size() - 9, 9) != std::string::npos)) {
        tiviState = CtZrtpSession::eSecureMitm;
    }
    sasVerified = verified;
    if (zrtpUserCallback != nullptr) {
        char *strng = nullptr;
        std::string sasTmp;

        if (!sas.empty()) {                 // Multi-stream mode streams don't have SAS, no reporting
            uint8_t peerZid[IDENTIFIER_LEN];
            std::string name;

            zrtpEngine->getPeerZid(peerZid);
            zrtpEngine->getZidCache()->getPeerName(peerZid, &name);
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
        sendSrtp = nullptr;
        sendSrtcp = nullptr;
    }
    if (part == ForReceiver) {
        delete recvSrtp;
        delete recvSrtcp;
        recvSrtp = nullptr;
        recvSrtcp = nullptr;
    }
}

int32_t CtZrtpStream::activateTimer(int32_t time) {
    if (staticTimeoutProvider != nullptr) {
        if (timeoutId != -1) {
            staticTimeoutProvider->removeTimer(timeoutId);
        }
        timeoutId = staticTimeoutProvider->addTimer(time, 0x776469, [this](uint64_t) {
            timeoutId = -1;
            if (zrtpEngine != nullptr) {
                zrtpEngine->processTimeout();
            }
        });
    }
    return 1;
}

int32_t CtZrtpStream::cancelTimer() {
    if (staticTimeoutProvider != nullptr && timeoutId >= 0) {
        staticTimeoutProvider->removeTimer(timeoutId);
        timeoutId = -1;
    }
    return 1;
}

void CtZrtpStream::handleGoClear() {
    fprintf(stderr, "Need to process a GoClear message!\n");
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

                // The peer hello hash not yet known, handle it in setSignalingHelloHash(...) function
                if (peerHelloHashes.empty())
                    break;

                peerHash = zrtpEngine->getPeerHelloHash();
                hexStringStart = peerHash.find_last_of(' ');
                hexString = peerHash.substr(hexStringStart+1);
                helloReceived = true;

                for (const auto& it : peerHelloHashes) {
                    bool match;
                    if (it.size() > SHA256_DIGEST_LENGTH*2)      // got the full string incl. version prefix, compare with full peer hash string
                        match = it == peerHash;
                    else
                        match = it == hexString;
                    if (match) {
                        zrtpHashMatch = true;
                        break;
                    }
                }
                /*
                 * In discriminator mode:
                 * If the received zrtp-hash value in the signaling does not match the hash of the actual received ZRTP Hello message, we must drop the call.
                 */
                if (!zrtpHashMatch && zrtpUserCallback != nullptr) {
                    if (discriminatorMode)
                        zrtpUserCallback->onDiscriminatorException(session, (char*)peerHelloMismatchMsg, index);
                    else
                        zrtpUserCallback->onZrtpWarning(session, (char*)peerHelloMismatchMsg, index);
                }
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
                /*
                 * In discriminator mode:
                 * If we receive or would send a ZRTP Commit message, but did not receive a zrtp-hash value in the signaling, we must drop the call.
                 */
                if (discriminatorMode && peerHelloHashes.empty()) {
                    if (zrtpUserCallback != nullptr)
                        zrtpUserCallback->onDiscriminatorException(session, (char*)noZrtpHashInSip, index);
                    break;
                }
                prevTiviState = tiviState;
                tiviState = CtZrtpSession::eGoingSecure;
                if (zrtpUserCallback != nullptr)
                    zrtpUserCallback->onNewZrtpStatus(session, nullptr, index);
                break;

                // other information states are not handled by tivi client
            default:
                break;
        }
        return;
    }
    if (severity == Warning) {
        bool tunnel = false;
        if (subCode < 0) {
            subCode *= -1;
            tunnel = true;
        }
        if (subCode == WarningNoRSMatch) {
            return;
        }
        msg = warningMap[subCode];
        if (tunnel)
            msg->append(" (ZRTP tunnel)");
        if (zrtpUserCallback != nullptr)
            zrtpUserCallback->onZrtpWarning(session, (char*)msg->c_str(), index);
        return;
    }
    // handle severe and ZRTP errors
    zrtpNegotiationFailed(severity, subCode);
}

void CtZrtpStream::zrtpNegotiationFailed(MessageSeverity severity, int32_t subCode) {

    std::string cs;
    std::string *strng;
    const char *inOut;
    if (severity == ZrtpError) {
        if (subCode < 0) {                  // received an error packet from peer
            subCode *= -1;
            inOut = "(<--)";
        }
        else {
            inOut = "(-->)";
        }
        strng = zrtpMap[subCode];
        if (strng != nullptr)
            cs.assign(*strng);
        else
            cs.assign("s4_c255: ZRTP protocol: Unkown ZRTP error packet.");
        cs.append(inOut);
    }
    else {
        cs = *severeMap[subCode];
    }

    prevTiviState = tiviState;
    tiviState = CtZrtpSession::eError;
    if (zrtpUserCallback != nullptr) {
        zrtpUserCallback->onNewZrtpStatus(session, (char*)cs.c_str(), index);
    }
}

void CtZrtpStream::zrtpNotSuppOther() {
    prevTiviState = tiviState;
    // if other party does not support ZRTP but we have SDES active set SDES state,
    // otherwise inform client about failed ZRTP negotiation.
    tiviState = isSdesActive() ? CtZrtpSession::eSecureSdes : CtZrtpSession::eNoPeer;
    if (zrtpUserCallback != nullptr) {
        zrtpUserCallback->onNewZrtpStatus(session, nullptr, index);
    }
}

void CtZrtpStream::zrtpAskEnrollment(GnuZrtpCodes::InfoEnrollment  info) {
    if (zrtpUserCallback != nullptr) {
        zrtpUserCallback->onNeedEnroll(session, index, (int32_t)info);
    }
}

void CtZrtpStream::zrtpInformEnrollment(GnuZrtpCodes::InfoEnrollment  info) {
    (void)info;
// Tivi does not use this information event
//     if (zrtpUserCallback != nullptr) {
//         zrtpUserCallback->zrtpInformEnrollment(info);
//     }
}

void CtZrtpStream::signSAS(uint8_t* sasHash) {
#if !defined (_WITHOUT_TIVI_ENV) && defined AXO_SUPPORT
//    zrtp_log("CTStream", "++++ sign sasHash");

    string keyData = getOwnAxoIdKey();
    int32_t keyLength = keyData.size();

    if (keyLength == 0)
        return;

    uint32_t typeLength = 100 << 16 | (keyLength & 0x7fff);
    typeLength = zrtpHtonl(typeLength);

    int32_t sigLen = (sizeof(int32_t) + keyLength + 3) & ~3;  // must be modulo 4 == 0

    uint8_t* sigData = new uint8_t[sigLen];

    // First is the signature type word
    *(uint32_t*)sigData = typeLength;
    memcpy(sigData+4, (const char*)keyData.data(), keyData.size());

    zrtpEngine->setSignatureData(sigData, sigLen);
    delete[] sigData;
#else
    (void)sasHash;
#endif
}

bool CtZrtpStream::checkSASSignature(uint8_t* sasHash) {
#if !defined (_WITHOUT_TIVI_ENV) && defined AXO_SUPPORT
    int32_t callId = session->getTiviCallId();
    /*
     * Use a engine function to get caller's name (AssertedId) and caller's device id
     */
    char buf[128];
    int len = getCallInfo(callId, "AssertedId", &buf[0], sizeof(buf));
    string caller(buf);

//    zrtp_log("CTStream", "++++ check sign sasHash:");

    len = getCallInfo(callId, "xscdevid", &buf[0], sizeof(buf));
    string callerDeviceId(buf);


    // Get the data from ZRTP and hand it over to Axolotl
    int32_t sigLen = zrtpEngine->getSignatureLength();
    const uint8_t* zrtpSigData = zrtpEngine->getSignatureData();

    uint8_t* sigData = new uint8_t[sigLen];
    memcpy(sigData, zrtpSigData, sigLen);

    int32_t typeLength = *(uint32_t*)(sigData);
    typeLength = zrtpNtohl(typeLength);
    int32_t length = typeLength & 0x7fff;

    int32_t verified = zrtpEngine->isSASVerified() ? 1 : 0;

    string pubKeyData((const char*)sigData+4, length);
    checkRemoteAxoIdKey(caller, callerDeviceId, pubKeyData, verified);

    delete[] sigData;
#else
    (void)sasHash;
#endif
    return true;
}

SrtpErrorData* CtZrtpStream::srtpErrorElement() {
    if (errorInfoIndex >= NumSrtpErrorData) {
        numErrorArrayWrap++;
        errorInfoIndex %= NumSrtpErrorData;
    }
    return &srtpErrorInfo[errorInfoIndex];
}

int32_t CtZrtpStream::getSrtpTraceData(SrtpErrorData* data) {
    if (errorInfoIndex == 0)
        return 0;

    int32_t idx = errorInfoIndex;    // get the index for this run, other threads may change errorInfoIndex

    // If the error index wrapped then the oldest data element is at errorInfoIndex, the newer elements
    // start at index zero. The output array receives the data in chronological order thus we need two
    // memcpy call to make it right.
    if (numErrorArrayWrap > 0) {
        memcpy((void*)data, (void*)&srtpErrorInfo[idx], (NumSrtpErrorData - idx) * sizeof(SrtpErrorData));
        memcpy((void*)&data[NumSrtpErrorData - idx], (void*)srtpErrorInfo, idx * sizeof(SrtpErrorData));
        return NumSrtpErrorData;
    }
    memcpy((void*)data, (void*)srtpErrorInfo, idx * sizeof(SrtpErrorData));
    return idx;
}

void CtZrtpStream::initStrings() {
    if (initialized) {
        return;
    }
    initialized = true;

    infoMap.insert(std::pair<int32_t, std::string*>(InfoHelloReceived,      new std::string("s1_c001: Hello received, preparing a Commit")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoCommitDHGenerated,  new std::string("s1_c002: Commit: Generated a public DH key")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoRespCommitReceived, new std::string("s1_c003: Responder: Commit received, preparing DHPart1")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoDH1DHGenerated,     new std::string("s1_c004: DH1Part: Generated a public DH key")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoInitDH1Received,    new std::string("s1_c005: Initiator: DHPart1 received, preparing DHPart2")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoRespDH2Received,    new std::string("s1_c006: Responder: DHPart2 received, preparing Confirm1")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoInitConf1Received,  new std::string("s1_c007: Initiator: Confirm1 received, preparing Confirm2")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoRespConf2Received,  new std::string("s1_c008: Responder: Confirm2 received, preparing Conf2Ack")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoRSMatchFound,       new std::string("s1_c009: At least one retained secrets matches - security OK")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoSecureStateOn,      new std::string("s1_c010: Entered secure state")));
    infoMap.insert(std::pair<int32_t, std::string*>(InfoSecureStateOff,     new std::string("s1_c011: No more security for this session")));

    warningMap.insert(std::pair<int32_t, std::string*>(WarningDHAESmismatch,   new std::string("s2_c001: Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningGoClearReceived, new std::string("s2_c002: Received a GoClear message")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningDHShort,         new std::string("s2_c003: Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningNoRSMatch,       new std::string("s2_c004: No retained secret matches - verify SAS")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningCRCmismatch,     new std::string("s2_c005: Internal ZRTP packet CRC mismatch - packet dropped")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningSRTPauthError,   new std::string("s2_c006: Dropping packet because SRTP authentication failed!")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningSRTPreplayError, new std::string("s2_c007: Dropping packet because SRTP replay check failed!")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningNoExpectedRSMatch,
                                                new std::string("s2_c008: You MUST check SAS with your partner. If it doesn't match, it indicates the presence of a wiretapper.")));
    warningMap.insert(std::pair<int32_t, std::string*>(WarningNoExpectedAuxMatch, new std::string("s2_c009: Expected auxilliary secret match failed")));

    severeMap.insert(std::pair<int32_t, std::string*>(SevereHelloHMACFailed,  new std::string("s3_c001: Hash HMAC check of Hello failed!")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereCommitHMACFailed, new std::string("s3_c002: Hash HMAC check of Commit failed!")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereDH1HMACFailed,    new std::string("s3_c003: Hash HMAC check of DHPart1 failed!")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereDH2HMACFailed,    new std::string("s3_c004: Hash HMAC check of DHPart2 failed!")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereCannotSend,       new std::string("s3_c005: Cannot send data - connection or peer down?")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereProtocolError,    new std::string("s3_c006: Internal protocol error occured!")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereNoTimer,          new std::string("s3_c007: Cannot start a timer - internal resources exhausted?")));
    severeMap.insert(std::pair<int32_t, std::string*>(SevereTooMuchRetries,   new std::string("s3_c008: Too many retries during ZRTP negotiation - connection or peer down?")));

    zrtpMap.insert(std::pair<int32_t, std::string*>(MalformedPacket,   new std::string("s4_c016: Malformed packet (CRC OK, but wrong structure)")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(CriticalSWError,   new std::string("s4_c020: Critical software error")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(UnsuppZRTPVersion, new std::string("s4_c048: Unsupported ZRTP version")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(HelloCompMismatch, new std::string("s4_c064: Hello components mismatch")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(UnsuppHashType,    new std::string("s4_c081: Hash type not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(UnsuppCiphertype,  new std::string("s4_c082: Cipher type not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(UnsuppPKExchange,  new std::string("s4_c083: Public key exchange not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(UnsuppSRTPAuthTag, new std::string("s4_c084: SRTP auth. tag not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(UnsuppSASScheme,   new std::string("s4_c085: SAS scheme not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(NoSharedSecret,    new std::string("s4_c086: No shared secret available, DH mode required")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(DHErrorWrongPV,    new std::string("s4_c097: DH Error: bad pvi or pvr ( == 1, 0, or p-1)")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(DHErrorWrongHVI,   new std::string("s4_c098: DH Error: hvi != hashed data")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(SASuntrustedMiTM,  new std::string("s4_c099: Received relayed SAS from untrusted MiTM")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(ConfirmHMACWrong,  new std::string("s4_c112: Auth. Error: Bad Confirm pkt HMAC")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(NonceReused,       new std::string("s4_c128: Nonce reuse")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(EqualZIDHello,     new std::string("s4_c144: Duplicate ZIDs in Hello Packets")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(GoCleatNotAllowed, new std::string("s4_c160: GoClear packet received, but not allowed")));

    enrollMap.insert(std::pair<int32_t, std::string*>(EnrollmentRequest,  new std::string("s5_c000: Trusted MitM enrollment requested")));
    enrollMap.insert(std::pair<int32_t, std::string*>(EnrollmentCanceled, new std::string("s5_c001: Trusted MitM enrollment canceled by user")));
    enrollMap.insert(std::pair<int32_t, std::string*>(EnrollmentFailed,   new std::string("s5_c003: Trusted MitM enrollment failed")));
    enrollMap.insert(std::pair<int32_t, std::string*>(EnrollmentOk,       new std::string("s5_c004: Trusted MitM enrollment OK")));
}
