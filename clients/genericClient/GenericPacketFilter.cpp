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

#include <zrtp/libzrtpcpp/zrtpPacket.h>
#include <common/osSpecifics.h>
#include <common/ZrtpTimeoutProvider.h>
#include <cryptcommon/ZrtpRandom.h>
#include "../common/SecureArray.h"
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


GenericPacketFilter::FilterResult
GenericPacketFilter::filterPacket(uint8_t const * packetData, size_t packetLength, CheckFunction const & checkFunction) {

    size_t offset = 0;
    uint32_t ssrc = 0;
    auto const checkResult = checkFunction(packetData, packetLength, offset, ssrc);
    if (checkResult == DontProcess) {
        return NotProcessed;
    }
    if (checkResult == Discard) {
        return Discarded;
    }

    if (peerSSRC == 0) {    // used when creating the CryptoContext
        peerSSRC = ssrc;
    }
    zrtpEngine->processZrtpMessage(packetData + offset, peerSSRC, packetLength);

    return Processed;
}

GenericPacketFilter::DataCheckResult
GenericPacketFilter::checkRtpData(uint8_t const * packetData, size_t packetLength, size_t & offset, uint32_t & ssrc) {
    if ((*packetData & 0xc0U) == 0x80) {            // Most probably a real RTP packet -> no ZRTP data
        return DontProcess;
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

    return Process;
}

GenericPacketFilter::ProtocolData
GenericPacketFilter::prepareToSendRtp(GenericPacketFilter& thisFilter, const uint8_t *zrtpData, int32_t length) {

    uint16_t totalLen = length + RTPHeaderLength;     /* Fixed number of bytes of ZRTP header */

    uint16_t* pus;
    uint32_t* pui;

    ProtocolData protocolData {};

    if ((totalLen) > maxZrtpSize)
        return protocolData;

    if (thisFilter.getZrtpSequenceNo() == 0) {
        uint16_t seqNumber = 0;
        while (seqNumber == 0) {
            ZrtpRandom::getRandomData((uint8_t *) &seqNumber, 2);
        }
        thisFilter.setZrtpSequenceNo(seqNumber & 0x7fffU);
    }
    auto ptr = std::make_shared<secUtilities::SecureArrayFlex>(totalLen);
    /* Get some handy pointers */
    pus = (uint16_t*)ptr->data();
    pui = (uint32_t*)ptr->data();

    // set up fixed ZRTP header - simulates RTP
    ptr->at(0) = 0x10;                             // invalid RTP version - refer to RFC6189
    ptr->at(1) = 0;
    auto seqNumber = thisFilter.getZrtpSequenceNo();
    pus[1] = zrtpHtons(seqNumber++);
    thisFilter.setZrtpSequenceNo(seqNumber);

    pui[1] = zrtpHtonl(ZRTP_MAGIC);
    pui[2] = zrtpHtonl(thisFilter.getOwnRtpSsrc());      // ownSSRC is stored in host order

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
    if (doSend == nullptr) {
        return 0;
    }
    if (!doSend(protocolData)) {
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
    LOGGER(ERROR_LOG, "GoClear feature is not supported!\n");
}


// endregion