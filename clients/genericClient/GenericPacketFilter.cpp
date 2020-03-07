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

#include "GenericPacketFilter.h"

static const size_t RTPHeaderLength = 12;

GenericPacketFilter::FilterResult
GenericPacketFilter::filterPacket(uint8_t const * packetData, size_t packetLength, CheckFunction const & checkFunction) {

    size_t offset = 0;
    auto const checkResult = checkFunction(packetData, packetLength, offset);
    if (checkResult == DontProcess) {
        return NotProcessed;
    }
    if (checkResult == Discard) {
        return Discarded;
    }

    return Processed;
}

GenericPacketFilter::DataCheckResult
GenericPacketFilter::checkRtpData(uint8_t const * packetData, size_t packetLength, size_t & offset) {
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
    offset = RTPHeaderLength;

    return Process;
}