/*
 * Copyright 2006 - 2018, Werner Dittmann
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
 */

/*
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <libzrtpcpp/ZrtpPacketPingAck.h>

#include "libzrtpcpp/ZrtpTextData.h"

ZrtpPacketPingAck::ZrtpPacketPingAck() {
    zrtpHeader = &data.hdr;	// the standard header

    setZrtpId();
    setLength(sizeof(PingAckPacket_t) / ZRTP_WORD_SIZE - 1);
    setMessageType(PingAckMsg);
    setVersion(reinterpret_cast<uint8_t const *>(zrtpVersion_11));  // TODO: fix version string after clarification
}

ZrtpPacketPingAck::ZrtpPacketPingAck(const uint8_t *data) {
    zrtpHeader = const_cast<zrtpPacketHeader_t *>(&reinterpret_cast<PingAckPacket_t const *>(data)->hdr); // the standard header
    pingAckHeader = const_cast<PingAck_t *>(&reinterpret_cast<PingAckPacket_t const *>(data)->pingAck);
}
