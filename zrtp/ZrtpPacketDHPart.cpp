/*
  Copyright (C) 2006-2017 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

ZrtpPacketDHPart::ZrtpPacketDHPart(const char* pkt) {
    initialize();
    setPubKeyType(pkt);
}

void ZrtpPacketDHPart::initialize() {
    LOGGER(DEBUGGING, __func__, " -->");

    void* allocated = &data;
    memset(allocated, 0, sizeof(data));

    zrtpHeader = &((DHPartPacket_t *)allocated)->hdr;       // the standard header
    DHPartHeader = &((DHPartPacket_t *)allocated)->dhPart;
    pv = ((uint8_t*)allocated) + sizeof(DHPartPacket_t);    // point to the public key value

    setZrtpId();
    LOGGER(DEBUGGING, __func__, " <--");
}

// The fixed numbers below are taken from ZRTP specification, chap 5.1.5
void ZrtpPacketDHPart::setPubKeyType(const char* pkt) {
    LOGGER(DEBUGGING, __func__, " -->");
    // Well - the algorithm type is only 4 char thus cast to int32 and compare
    if (*(int32_t*)pkt == *(int32_t*)dh2k) {
        dhLength = DH2K_LENGTH_BYTES;
    }
    else if (*(int32_t*)pkt == *(int32_t*)dh3k) {
        dhLength = DH3K_LENGTH_BYTES;
    }
    else if (*(int32_t*)pkt == *(int32_t*)ec25) {
        dhLength = EC25_LENGTH_BYTES;
    }
    else if (*(int32_t*)pkt == *(int32_t*)ec38) {
        dhLength = EC38_LENGTH_BYTES;
    }
    else if (*(int32_t*)pkt == *(int32_t*)e255) {
        dhLength = E255_LENGTH_BYTES;
    }
    else if (*(int32_t*)pkt == *(int32_t*)e414) {
        dhLength = E414_LENGTH_BYTES;
    }
    else if (*(int32_t*)pkt == *(int32_t*)sdh1) {
        dhLength = SDH1_LENGTH_BYTES;
    }
    else {
        LOGGER(ERROR, __func__, " Unknown DH algorithm in DH packet:", pkt);
        return;
    }

    uint16_t length = static_cast<uint16_t>(sizeof(DHPartPacket_t) + dhLength + (2 * ZRTP_WORD_SIZE)); // HMAC field is 2*ZRTP_WORD_SIZE
    setLength(static_cast<uint16_t>(length / ZRTP_WORD_SIZE));
    LOGGER(INFO, __func__, " Computed dhLength: ", dhLength, ", length: ", length);

    LOGGER(DEBUGGING, __func__, " <--");
}

ZrtpPacketDHPart::ZrtpPacketDHPart(uint8_t *data) {
    LOGGER(DEBUGGING, __func__, " --> ", SDH1_WORDS, ", ", FIXED_NUM_WORDS, ", ", SDH1_LENGTH_BYTES );

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
        LOGGER(ERROR, __func__, " Unknown DH algorithm in DH packet with length: ", len);
        pv = nullptr;
        return;
    }
    LOGGER(INFO, __func__, " Computed dhLength: ", dhLength);

    pv = data + sizeof(DHPartPacket_t);    // point to the public key value
    LOGGER(DEBUGGING, __func__, " <--");
}

ZrtpPacketDHPart::~ZrtpPacketDHPart() {
}
