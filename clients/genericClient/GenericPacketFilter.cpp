//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Created by werner on 06.03.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#include <libzrtpcpp/ZrtpStateClass.h>
#include <zrtp/libzrtpcpp/zrtpPacket.h>
#include <common/osSpecifics.h>
#include <common/ZrtpTimeoutProvider.h>
#include <cryptcommon/ZrtpRandom.h>
#include "../logging/ZrtpLogging.h"

#include "GenericPacketFilter.h"

static constexpr size_t RTPHeaderLength = 12;
static constexpr int maxZrtpSize = 3072;

static zrtp::ZrtpTimeoutProvider *staticTimeoutProvider = nullptr;

GenericPacketFilter::GenericPacketFilter() {

    if (staticTimeoutProvider == nullptr) {
        staticTimeoutProvider = new zrtp::ZrtpTimeoutProvider;
    }
}

GenericPacketFilter::~GenericPacketFilter() {
    std::lock_guard<std::mutex> guard(syncLock);
    if (zrtpStarted && zrtpEngine) {
        zrtpEngine->stopZrtp();
        zrtpStarted = false;
    }
}

void
GenericPacketFilter::releaseTimeoutProvider() {
    auto timeoutProvider = staticTimeoutProvider;       // clear first before deleting
    staticTimeoutProvider = nullptr;
    delete timeoutProvider;
}

GenericPacketFilter::PacketFilterReturnCodes
GenericPacketFilter::startZrtpEngine() {
    std::lock_guard<std::mutex> guard(syncLock);

    if (!zrtpStarted) {
        if (!configuration) {
            return NoConfiguration;
        }
        std::shared_ptr<ZrtpCallback> mySelf = shared_from_this();
        zrtpEngine = std::make_unique<ZRtp>(clientId, mySelf, configuration);

        // Check data that must be set before start of ZRTP engine
        if (tpOverhead >= 0) {
            zrtpEngine->setTransportOverhead(tpOverhead);
        }
        zrtpEngine->startZrtpEngine();
        zrtpStarted = true;

        if (stateHandler != nullptr) {
            StateData stateData(static_cast<GnuZrtpCodes::MessageSeverity>(0),
                                0, codeToString.getStringForCode(static_cast<GnuZrtpCodes::MessageSeverity>(0), 0));
            stateHandler(Discovery, stateData);
        }
    }
    return Success;
}

GenericPacketFilter::FilterResult
GenericPacketFilter::filterPacket(uint8_t const * packetData, size_t & packetLength, CheckFunction const & checkFunction) {

    size_t offset = 0;
    uint32_t ssrc = 0;
    auto const checkResult = checkFunction(packetData, packetLength, offset, ssrc);

    // This seems to be a legit data packet. Check what to do with it.
    if (checkResult == NotZrtp) {
        if (!doProcessSrtp) {       // no further processing, application takes care
            return NotProcessed;
        }
        if (!recvSrtp) {            // No keys available yet - tell caller about it
            return NotDecrypted;
        }
        // At this point we have an active ZRTP/SRTP context, unprotect with ZRTP/SRTP first
        if (suppressCounter < supressWarn)       // Don't report SRTP problems while in startup mode
            suppressCounter++;

        size_t newLength;
        auto rc = SrtpHandler::unprotect(recvSrtp.get(), const_cast<uint8_t *>(packetData), packetLength, &newLength, &srtpErrorDetails);
        if (rc == 1) {
            zrtpUnprotect++;
            // Got a good SRTP, check state and if in WaitConfAck (an Initiator state)
            // then simulate a conf2Ack, refer to RFC 6189, chapter 4.6, last paragraph
            if (zrtpEngine->inState(WaitConfAck)) {
                zrtpEngine->conf2AckSecure();
            }
            packetLength = newLength;       // Length may have changed during SRTP processing
            return Decrypted;
        }
        // Well, here we have some SRTP problem.
        unprotectFailed++;
        if (suppressCounter >= supressWarn) {
            return DecryptionFailed;
        }
        return DecryptionFailedStartup;
    }

    if (checkResult == Discard) {
        return UnknownData;
    }

    if (!zrtpStarted) {
        return NotStarted;
    }
    if (peerSSRC == 0) {    // used when creating the CryptoContext
        peerSSRC = ssrc;
    }
    zrtpEngine->processZrtpMessage(packetData + offset, peerSSRC, packetLength);

    return Processed;
}

std::unique_ptr<secUtilities::SecureArrayFlex>
GenericPacketFilter::processOutgoingRtp(uint8_t *rtpData, size_t length)
{
    // Add 10 bytes to capacity: maximum length of SRTP authentication tag
    auto processedData = make_unique<secUtilities::SecureArrayFlex>(length + 10);
    processedData->assign(rtpData, length);

    if (!sendSrtp) {    // No keys yet - just return the data
        return processedData;
    }
    size_t newLength;
    auto rc = SrtpHandler::protect(sendSrtp.get(), processedData->data(), length, &newLength);
    if (rc) {
        zrtpProtect++;
        processedData->size(newLength);
        return processedData;
    }
    processedData.reset();
    return processedData;
}

GenericPacketFilter::DataCheckResult
GenericPacketFilter::checkRtpData(uint8_t const * packetData, size_t packetLength, size_t & offset, uint32_t & ssrc) {
    if ((*packetData & 0xc0U) == 0x80) {            // Most probably a real RTP packet -> no ZRTP data
        return NotZrtp;
    }
    // Not an RTP packet, check for possible ZRTP packet.

    // Fixed header length + smallest ZRTP packet (includes CRC)
    if (packetLength < (RTPHeaderLength + sizeof(HelloAckPacket_t))) {  // data too small, dismiss
        return Discard;
    }
    // Check if it's really a ZRTP packet:
    // RTP time stamp field is magic cookie (starts at 4th byte in RTP header),
    // first 2 bytes of ZRTP data is a preamble
    uint32_t zrtpMagic = *reinterpret_cast<uint32_t const *>(packetData + 4);
    zrtpMagic = zrtpNtohl(zrtpMagic);
    if (zrtpMagic != ZRTP_MAGIC) {
        return Discard;
    }
    uint16_t preamble = *reinterpret_cast<uint16_t const *>(packetData + RTPHeaderLength);
    preamble = zrtpNtohs(preamble);
    if (preamble != ZRTP_PREAMBLE) {
        return Discard;
    }
    // return peer's SSRC in host order
    ssrc = *(uint32_t*)(packetData + 8);    // RTP fixed offset to SSRC
    ssrc = zrtpNtohl(ssrc);
    offset = RTPHeaderLength;

    return IsZrtp;
}

GenericPacketFilter::ProtocolData
GenericPacketFilter::prepareToSendRtp(GenericPacketFilter& thisFilter, const uint8_t *zrtpData, int32_t length) {

    uint16_t totalLen = length + RTPHeaderLength;     /* Fixed number of bytes of ZRTP header */

    uint16_t* pus;
    uint32_t* pui;

    ProtocolData protocolData {};

    if ((totalLen) > maxZrtpSize)
        return protocolData;

    if (thisFilter.zrtpSequenceNo() == 0) {
        uint16_t seqNumber = 0;
        while (seqNumber == 0) {
            ZrtpRandom::getRandomData((uint8_t *) &seqNumber, 2);
        }
        thisFilter.zrtpSequenceNo(seqNumber & 0x7fffU);
    }
    auto ptr = std::make_shared<secUtilities::SecureArrayFlex>(totalLen);
    /* Get some handy pointers */
    pus = (uint16_t*)ptr->data();
    pui = (uint32_t*)ptr->data();

    // set up fixed ZRTP header - simulates RTP
    ptr->at(0) = 0x10;                             // invalid RTP version - refer to RFC6189
    ptr->at(1) = 0;
    auto seqNumber = thisFilter.zrtpSequenceNo();
    pus[1] = zrtpHtons(seqNumber++);
    thisFilter.zrtpSequenceNo(seqNumber);

    pui[1] = zrtpHtonl(ZRTP_MAGIC);
    pui[2] = zrtpHtonl(thisFilter.ownRtpSsrc());      // ownSSRC is stored in host order

    memcpy(ptr->data()+12, zrtpData, length);       // Copy ZRTP message data after the header data

    // Compute the ZRTP CRC over the total length, including the transport (RTP) data
    auto crc = zrtpGenerateCksum(ptr->data(), totalLen-CRC_SIZE);        // Setup and compute ZRTP CRC
    crc = zrtpEndCksum(crc);                                       // convert and store CRC in ZRTP packet.
    *(uint32_t*)(ptr->data()+totalLen-CRC_SIZE) = zrtpHtonl(crc);

    protocolData.length = totalLen;
    protocolData.ptr = ptr;
    return protocolData;
}

// region ZRTP callback methods

int32_t
GenericPacketFilter::sendDataZRTP(const unsigned char *data, int32_t length) {

    auto protocolData = (prepareToSend == nullptr) ?
            GenericPacketFilter::prepareToSendRtp(*this, data, length) :
            prepareToSend(*this, data, length);

    // No data?
    if (protocolData.length == 0 || !protocolData.ptr) {
        return 0;
    }
    // Check the callback here - the prepareToSend may set it.
    if (doSend == nullptr || !doSend(protocolData)) {
        return 0;
    }
    return 1;
}

int32_t
GenericPacketFilter::activateTimer(int32_t time) {
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

int32_t
GenericPacketFilter::cancelTimer() {
    if (staticTimeoutProvider != nullptr && timeoutId >= 0) {
        staticTimeoutProvider->removeTimer(timeoutId);
        timeoutId = -1;
    }
    return 1;
}

void
GenericPacketFilter::handleGoClear() {
    LOGGER(ERROR_LOG, "GoClear feature is not supported!\n")
}

bool
GenericPacketFilter::srtpSecretsReady(SrtpSecret_t* secrets, EnableSecurity part)
{
    if (!doProcessSrtp && keyDataReady == nullptr) {
        return false;
    }

    // Application likes to handle the key and encryption itself, forward necessary data
    if (!doProcessSrtp) {
        KeysAndAlgorithms ka;
        ka.role = secrets->role;
        ka.symEncAlgorithm = secrets->symEncAlgorithm;
        ka.keyInitiator.assign(secrets->keyInitiator, secrets->initKeyLen / 8);
        ka.keyResponder.assign(secrets->keyResponder, secrets->initKeyLen / 8);
        ka.saltInitiator.assign(secrets->saltInitiator, secrets->initSaltLen / 8);
        ka.saltResponder.assign(secrets->saltResponder, secrets->initSaltLen / 8);
        ka.authAlgorithm = secrets->authAlgorithm;
        ka.srtpAuthTagLen = secrets->srtpAuthTagLen / 8;

        return keyDataReady(part, ka);
    }

    // Generic filter handles SRTP. Setup crypto contexts.

    std::unique_ptr<CryptoContext> recvCryptoContext;
    std::unique_ptr<CryptoContext> senderCryptoContext;
    std::unique_ptr<CryptoContextCtrl> recvCryptoContextCtrl;
    std::unique_ptr<CryptoContextCtrl> senderCryptoContextCtrl;

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
    if (secrets->symEncAlgorithm == Aes) {
        cipher = SrtpEncryptionAESCM;
    }
    if (secrets->symEncAlgorithm == TwoFish) {
        cipher = SrtpEncryptionTWOCM;
    }

    role = secrets->role;

    if (part == ForSender) {
        // To encrypt packets: initiator uses initiator keys,
        // responder uses responder keys
        // Create a "half baked" crypto context first and store it. This is
        // the main crypto context for the sending part of the connection.
        if (secrets->role == Initiator) {
            senderCryptoContext = std::make_unique<CryptoContext>(0,           // SSRC (used for lookup)
                                      0,                                       // Roll-Over-Counter (ROC)
                                      0L,                                      // key derivation << 48,
                                      cipher,                                  // encryption algo
                                      authn,                                   // authentication algo
                                      (unsigned char*)secrets->keyInitiator,   // Master Key
                                      secrets->initKeyLen / 8,                 // Master Key length
                                      (unsigned char*)secrets->saltInitiator,  // Master Salt
                                      secrets->initSaltLen / 8,                // Master Salt length
                                      secrets->initKeyLen / 8,                 // encryption keylength
                                      authKeyLen,                              // authentication key len
                                      secrets->initSaltLen / 8,                // session salt len
                                      secrets->srtpAuthTagLen / 8);            // authentication tag len

            senderCryptoContextCtrl = std::make_unique<CryptoContextCtrl>(0,           // SSRC (used for lookup)
                                          cipher,                                    // encryption algo
                                          authn,                                     // authentication algo
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
            senderCryptoContext = std::make_unique<CryptoContext>(0,                                       // SSRC (used for lookup)
                                      0,                                       // Roll-Over-Counter (ROC)
                                      0L,                                      // key derivation << 48,
                                      cipher,                                  // encryption algo
                                      authn,                                   // authentication algo
                                      (unsigned char*)secrets->keyResponder,   // Master Key
                                      secrets->respKeyLen / 8,                 // Master Key length
                                      (unsigned char*)secrets->saltResponder,  // Master Salt
                                      secrets->respSaltLen / 8,                // Master Salt length
                                      secrets->respKeyLen / 8,                 // encryption keylength
                                      authKeyLen,                              // authentication key len
                                      secrets->respSaltLen / 8,                // session salt len
                                      secrets->srtpAuthTagLen / 8);            // authentication tag len

            senderCryptoContextCtrl = std::make_unique<CryptoContextCtrl>(0,                                         // SSRC (used for lookup)
                                          cipher,                                    // encryption algo
                                          authn,                                     // authentication algo
                                          (unsigned char*)secrets->keyResponder,     // Master Key
                                          secrets->respKeyLen / 8,                   // Master Key length
                                          (unsigned char*)secrets->saltResponder,    // Master Salt
                                          secrets->respSaltLen / 8,                  // Master Salt length
                                          secrets->respKeyLen / 8,                   // encryption key length
                                          authKeyLen,                                // authentication key len
                                          secrets->respSaltLen / 8,                  // session salt len
                                          secrets->srtpAuthTagLen / 8);              // authentication tag len
        }
        senderCryptoContext->deriveSrtpKeys(0L);
        sendSrtp = std::move(senderCryptoContext);

        senderCryptoContextCtrl->deriveSrtcpKeys();
        sendSrtcp = std::move(senderCryptoContextCtrl);
    }
    if (part == ForReceiver) {
        // To decrypt packets: initiator uses responder keys,
        // responder initiator keys
        // See comment above.
        if (secrets->role == Initiator) {
            recvCryptoContext = make_unique<CryptoContext>(0,                                       // SSRC (used for lookup)
                                      0,                                       // Roll-Over-Counter (ROC)
                                      0L,                                      // key derivation << 48,
                                      cipher,                                  // encryption algo
                                      authn,                                   // authentication algo
                                      (unsigned char*)secrets->keyResponder,   // Master Key
                                      secrets->respKeyLen / 8,                 // Master Key length
                                      (unsigned char*)secrets->saltResponder,  // Master Salt
                                      secrets->respSaltLen / 8,                // Master Salt length
                                      secrets->respKeyLen / 8,                 // encryption key length
                                      authKeyLen,                              // authentication key len
                                      secrets->respSaltLen / 8,                // session salt len
                                      secrets->srtpAuthTagLen / 8);            // authentication tag len

            recvCryptoContextCtrl = make_unique<CryptoContextCtrl>(0,                                         // SSRC (used for lookup)
                                          cipher,                                    // encryption algo
                                          authn,                                     // authentication algo
                                          (unsigned char*)secrets->keyResponder,     // Master Key
                                          secrets->respKeyLen / 8,                   // Master Key length
                                          (unsigned char*)secrets->saltResponder,    // Master Salt
                                          secrets->respSaltLen / 8,                  // Master Salt length
                                          secrets->respKeyLen / 8,                   // encryption key length
                                          authKeyLen,                                // authentication key len
                                          secrets->respSaltLen / 8,                  // session salt len
                                          secrets->srtpAuthTagLen / 8);              // authentication tag len
        }
        else {
            recvCryptoContext = make_unique<CryptoContext>(0,                                       // SSRC (used for lookup)
                                      0,                                       // Roll-Over-Counter (ROC)
                                      0L,                                      // key derivation << 48,
                                      cipher,                                  // encryption algo
                                      authn,                                   // authentication algo
                                      (unsigned char*)secrets->keyInitiator,   // Master Key
                                      secrets->initKeyLen / 8,                 // Master Key length
                                      (unsigned char*)secrets->saltInitiator,  // Master Salt
                                      secrets->initSaltLen / 8,                // Master Salt length
                                      secrets->initKeyLen / 8,                 // encryption key length
                                      authKeyLen,                              // authentication key len
                                      secrets->initSaltLen / 8,                // session salt len
                                      secrets->srtpAuthTagLen / 8);            // authentication tag len

            recvCryptoContextCtrl = make_unique<CryptoContextCtrl>(0,                                         // SSRC (used for lookup)
                                          cipher,                                    // encryption algo
                                          authn,                                     // authentication algo
                                          (unsigned char*)secrets->keyInitiator,     // Master Key
                                          secrets->initKeyLen / 8,                   // Master Key length
                                          (unsigned char*)secrets->saltInitiator,    // Master Salt
                                          secrets->initSaltLen / 8,                  // Master Salt length
                                          secrets->initKeyLen / 8,                   // encryption key length
                                          authKeyLen,                                // authentication key len
                                          secrets->initSaltLen / 8,                  // session salt len
                                          secrets->srtpAuthTagLen / 8);              // authentication tag len
        }
        recvCryptoContext->deriveSrtpKeys(0L);
        recvSrtp = move(recvCryptoContext);

        recvCryptoContextCtrl->deriveSrtcpKeys();
        recvSrtcp = move(recvCryptoContextCtrl);

        suppressCounter = 0;         // suppress SRTP warnings for some packets after we switch to SRTP
    }
    return true;
}

void
GenericPacketFilter::srtpSecretsOn(std::string cipher, std::string sas, bool verified)
{
    auto currentState = Secure;

    sasVerified_ = verified;
    cipherInfo_ = cipher;
    computedSAS = sas;

}

void
GenericPacketFilter::srtpSecretsOff(EnableSecurity part) {
    if (part == ForSender) {
        sendSrtp.reset();
        sendSrtcp.reset();

    }
    if (part == ForReceiver) {
        recvSrtp.reset();
        recvSrtcp.reset();
    }
}

void
GenericPacketFilter::sendInfo(GnuZrtpCodes::MessageSeverity severity, int32_t subCode) {
    std::string *msg;

    if (stateHandler == nullptr) {
        return;
    }

    StateData stateData(severity, subCode, codeToString.getStringForCode(severity, subCode));
    switch (severity) {
        case GnuZrtpCodes::Info:
            if (subCode == GnuZrtpCodes::InfoSecureStateOn) {
                StateData sasData(GnuZrtpCodes::Info, GnuZrtpCodes::InfoSecureStateOn, computedSAS);
                stateHandler(Secure, sasData);
            } else if (subCode == GnuZrtpCodes::InfoRespCommitReceived || subCode == GnuZrtpCodes::InfoInitDH1Received) {
                stateHandler(KeyNegotiation, stateData);
            } else if (reportAll) {
                stateHandler(InfoOnly, stateData);
            }
            break;

        case GnuZrtpCodes::Warning:
            stateHandler(Warning, stateData);
            break;

        case GnuZrtpCodes::Severe:
        case GnuZrtpCodes::ZrtpError:
            stateHandler(Error, stateData);
            break;
    }
}

void
GenericPacketFilter::zrtpNegotiationFailed(GnuZrtpCodes::MessageSeverity severity, int32_t subCode) {

    if (stateHandler == nullptr) {
        return;
    }

    StateData stateData(severity, subCode, codeToString.getStringForCode(severity, subCode));
    stateHandler(Error, stateData);

}

void
GenericPacketFilter::zrtpNotSuppOther() {
    if (stateHandler == nullptr) {
        return;
    }
    StateData stateData(static_cast<GnuZrtpCodes::MessageSeverity>(0),
                        0, codeToString.getStringForCode(static_cast<GnuZrtpCodes::MessageSeverity>(0), 0));
    stateHandler(NoPeer, stateData);
}

// endregion