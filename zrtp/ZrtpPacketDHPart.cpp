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
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include "libzrtpcpp/ZrtpPacketDHPart.h"
#include "zrtp/crypto/zrtpDH.h"
#include "logging/ZrtpLogging.h"

constexpr int FIXED_NUM_WORDS = sizeof(DHPartPacket_t) / ZRTP_WORD_SIZE + 2;         // +2 for MAC
constexpr int DH2K_WORDS = FIXED_NUM_WORDS + DH2K_LENGTH_BYTES / ZRTP_WORD_SIZE;     // 2048 / 8 / ZRTP_WORD_SIZE
constexpr int DH3K_WORDS = FIXED_NUM_WORDS + DH3K_LENGTH_BYTES / ZRTP_WORD_SIZE;     // 3072 / 8 / ZRTP_WORD_SIZE
constexpr int EC25_WORDS = FIXED_NUM_WORDS + EC25_LENGTH_BYTES / ZRTP_WORD_SIZE;     // 2*(256 / 8 / ZRTP_WORD_SIZE)
constexpr int EC38_WORDS = FIXED_NUM_WORDS + EC38_LENGTH_BYTES / ZRTP_WORD_SIZE;     // 2*(384 / 8 / ZRTP_WORD_SIZE)
constexpr int E255_WORDS = FIXED_NUM_WORDS + E255_LENGTH_BYTES / ZRTP_WORD_SIZE;     // 32 / ZRTP_WORD_SIZE
constexpr int E414_WORDS = FIXED_NUM_WORDS + E414_LENGTH_BYTES / ZRTP_WORD_SIZE;     // 2*((414+7) / 8 / ZRTP_WORD_SIZE)
constexpr int NP06_WORDS = FIXED_NUM_WORDS + (NP06_LENGTH_BYTES_DHPart + ZRTP_WORD_SIZE - 1) / ZRTP_WORD_SIZE;
constexpr int NP09_WORDS = FIXED_NUM_WORDS + (NP09_LENGTH_BYTES_DHPart + ZRTP_WORD_SIZE - 1) / ZRTP_WORD_SIZE;
constexpr int NP12_WORDS = FIXED_NUM_WORDS + (NP12_LENGTH_BYTES_DHPart + ZRTP_WORD_SIZE - 1) / ZRTP_WORD_SIZE;

ZrtpPacketDHPart::ZrtpPacketDHPart() {
    initialize();
}

void ZrtpPacketDHPart::initialize() {

    void *allocated = &data;
    memset(allocated, 0, sizeof(data));

    zrtpHeader = &((DHPartPacket_t *) allocated)->hdr; // the standard header
    DHPartHeader = &((DHPartPacket_t *) allocated)->dhPart;
    pv = ((uint8_t *) allocated) + sizeof(DHPartPacket_t);    // point to the public key value

    setZrtpId();
}

// The fixed numbers below are taken from ZRTP specification, chap 5.1.5
// pubKeyLen must be a multiple of ZRTP_WORD_SIZE
void ZrtpPacketDHPart::setPacketLength(size_t pubKeyLen) {
    dhLength = pubKeyLen;
    // always round to multiple number of ZRTP_WORD_SIZE bytes
    roundUp = ((pubKeyLen + (ZRTP_WORD_SIZE - 1)) / ZRTP_WORD_SIZE) * ZRTP_WORD_SIZE;

    // Compute total length in bytes, is always a multiple of ZRTP_WORD_SIZE, the computer number of ZRTP_WORDS
    auto length = static_cast<uint16_t>(sizeof(DHPartPacket_t) + roundUp +
                                        (2 * ZRTP_WORD_SIZE)); // HMAC field is 2*ZRTP_WORD_SIZE
    setLength(static_cast<uint16_t>(length / ZRTP_WORD_SIZE));
}

ZrtpPacketDHPart::ZrtpPacketDHPart(uint8_t const *data, bool isNpAlgorithm) {
    zrtpHeader = &((DHPartPacket_t *) data)->hdr;  // the standard header
    DHPartHeader = &((DHPartPacket_t *) data)->dhPart;

    pv = const_cast<uint8_t *>(data + sizeof(DHPartPacket_t));    // point to the public key value(s)

    auto isDhPart2 = getMessageTypeString() == DHPart2Msg;

    switch (getLength()) {
        case DH2K_WORDS:    // Dh2k
            dhLength = DH2K_LENGTH_BYTES;
            break;
        case DH3K_WORDS:    // Dh3k
            dhLength = DH3K_LENGTH_BYTES;
            break;
        case EC25_WORDS:    // EC256
            dhLength = EC25_LENGTH_BYTES;
            break;
        case EC38_WORDS:    // EC384
            dhLength = EC38_LENGTH_BYTES;
            break;
        case E255_WORDS:    // E255
            dhLength = E255_LENGTH_BYTES;
            break;
        case E414_WORDS:    // E414
            dhLength = E414_LENGTH_BYTES;
            break;
        case NP06_WORDS:
            dhLength = NP06_LENGTH_BYTES_DHPart;
            break;
        case NP09_WORDS:
            dhLength = NP09_LENGTH_BYTES_DHPart;
            break;
        case NP12_WORDS:
            dhLength = NP12_LENGTH_BYTES_DHPart;
            break;
        default:
            pv = nullptr;
            if (!(isDhPart2 && isNpAlgorithm && getLength() == 21)) {
                LOGGER(ERROR_LOG, __func__, " Unknown DH algorithm in DH packet with length: ", getLength(), ", msg: ",
                       getMessageTypeString())
            }
    }
}

