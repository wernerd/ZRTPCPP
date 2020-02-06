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

#include <libzrtpcpp/ZrtpPacketDHPart.h>
#include <zrtp/crypto/zrtpDH.h>
#include <logging/ZrtpLogging.h>

static const int FIXED_NUM_WORDS = sizeof(DHPartPacket_t) / ZRTP_WORD_SIZE + 2;         // +2 for MAC
static const int DH2K_WORDS = FIXED_NUM_WORDS + DH2K_LENGTH_BYTES / ZRTP_WORD_SIZE;     // 2048 / 8 / ZRTP_WORD_SIZE
static const int DH3K_WORDS = FIXED_NUM_WORDS + DH3K_LENGTH_BYTES / ZRTP_WORD_SIZE;     // 3072 / 8 / ZRTP_WORD_SIZE
static const int EC25_WORDS = FIXED_NUM_WORDS + EC25_LENGTH_BYTES / ZRTP_WORD_SIZE;     // 2*(256 / 8 / ZRTP_WORD_SIZE)
static const int EC38_WORDS = FIXED_NUM_WORDS + EC38_LENGTH_BYTES / ZRTP_WORD_SIZE;     // 2*(384 / 8 / ZRTP_WORD_SIZE)
static const int E255_WORDS = FIXED_NUM_WORDS + E255_LENGTH_BYTES / ZRTP_WORD_SIZE;     // 32 / ZRTP_WORD_SIZE
static const int E414_WORDS = FIXED_NUM_WORDS + E414_LENGTH_BYTES / ZRTP_WORD_SIZE;     // 2*((414+7) / 8 / ZRTP_WORD_SIZE)
static const int SDH1_WORDS = FIXED_NUM_WORDS + SDH1_LENGTH_BYTES / ZRTP_WORD_SIZE;

ZrtpPacketDHPart::ZrtpPacketDHPart() {
    initialize();
}

void ZrtpPacketDHPart::initialize() {

    void* allocated = &data;
    memset(allocated, 0, sizeof(data));

    zrtpHeader = &((DHPartPacket_t *)allocated)->hdr; // the standard header
    DHPartHeader = &((DHPartPacket_t *)allocated)->dhPart;
    pv = ((uint8_t*)allocated) + sizeof(DHPartPacket_t);    // point to the public key value

    setZrtpId();
}

// The fixed numbers below are taken from ZRTP specification, chap 5.1.5
void ZrtpPacketDHPart::setPacketLength(size_t pubKeyLen) {
    dhLength = pubKeyLen;

    auto length = static_cast<uint16_t>(sizeof(DHPartPacket_t) + dhLength + (2 * ZRTP_WORD_SIZE)); // HMAC field is 2*ZRTP_WORD_SIZE
    setLength(static_cast<uint16_t>(length / ZRTP_WORD_SIZE));
//    LOGGER(INFO, __func__, " Computed dhLength: ", dhLength, ", length: ", length);
//
//    LOGGER(DEBUGGING, __func__, " <--");
}

ZrtpPacketDHPart::ZrtpPacketDHPart(uint8_t const * data) {
    zrtpHeader = &((DHPartPacket_t *)data)->hdr;  // the standard header
    DHPartHeader = &((DHPartPacket_t *)data)->dhPart;

    int16_t len = getLength();
    if (len == DH2K_WORDS) {         // Dh2k
        dhLength = DH2K_LENGTH_BYTES;
    }
    else if (len == DH3K_WORDS) {    // Dh3k
        dhLength = DH3K_LENGTH_BYTES;
    }
    else if (len == EC25_WORDS) {    // EC256
        dhLength = EC25_LENGTH_BYTES;
    }
    else if (len == EC38_WORDS) {    // EC384
        dhLength = EC38_LENGTH_BYTES;
    }
    else if (len == E255_WORDS) {    // E255
        dhLength = E255_LENGTH_BYTES;
    }
    else if (len == E414_WORDS) {    // E414
        dhLength = E414_LENGTH_BYTES;
    }
    else if (len == SDH1_WORDS) {    // SDH1
        dhLength = SDH1_LENGTH_BYTES;
    }
    else {
        pv = nullptr;
//        LOGGER(ERROR, __func__, " Unknown DH algorithm in DH packet with length: ", len);
        return;
    }
    pv = const_cast<uint8_t*>(data + sizeof(DHPartPacket_t));    // point to the public key value
}
