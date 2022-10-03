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

#include <libzrtpcpp/ZrtpPacketCommit.h>

constexpr int COMMIT_LENGTH_NO_NP = (sizeof(CommitPacket_t) + (2 * ZRTP_WORD_SIZE)) / ZRTP_WORD_SIZE;

ZrtpPacketCommit::ZrtpPacketCommit() {

    zrtpHeader = &((CommitPacket_t *)data)->hdr;	// the standard header
    commitHeader = &((CommitPacket_t *)data)->commit;

    pv = const_cast<uint8_t*>(data + sizeof(CommitPacket_t));    // point to the public key value

    setZrtpId();
    setLength((sizeof (CommitPacket_t) / ZRTP_WORD_SIZE + 3) - 1);
    setMessageType((uint8_t*)CommitMsg);
}

ZrtpPacketCommit::ZrtpPacketCommit(uint8_t const *data) {
    zrtpHeader = (zrtpPacketHeader_t *)&((CommitPacket_t *)data)->hdr;	// the standard header
    commitHeader = (Commit_t *)&((CommitPacket_t *)data)->commit;

    if (getLength() > COMMIT_LENGTH_NO_NP) {
        pv = const_cast<uint8_t *>(data + sizeof(CommitPacket_t));    // point to the public key value(s)
    }
}

void ZrtpPacketCommit::setPacketLength(size_t pubKeyLen) {
    pvLength = pubKeyLen;
    // always round to multiple number of ZRTP_WORD_SIZE bytes
    roundUp = ((pubKeyLen + (ZRTP_WORD_SIZE - 1)) / ZRTP_WORD_SIZE) * ZRTP_WORD_SIZE;

    // Compute total length in bytes, is always a multiple of ZRTP_WORD_SIZE, the computer number of ZRTP_WORDS
    auto length = static_cast<uint16_t>(sizeof(CommitPacket_t) + roundUp + (2 * ZRTP_WORD_SIZE)); // HMAC field is 2*ZRTP_WORD_SIZE
    setLength(static_cast<uint16_t>(length / ZRTP_WORD_SIZE));
}

bool ZrtpPacketCommit::isLengthOk(commitType type) const  {
    int32_t len = getLength();
    // TODO: check length for various DH types including NPxx algorithms
    return type != MultiStream || len == COMMIT_MULTI;
}

void ZrtpPacketCommit::setNonce(uint8_t const * text) {
    memcpy(commitHeader->hvi, text, sizeof(commitHeader->hvi)-4*ZRTP_WORD_SIZE);
    uint16_t len = getLength();
    len -= 4;
    setLength(len);
}
