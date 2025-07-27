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

#include <libzrtpcpp/ZrtpPacketConfirm.h>

ZrtpPacketConfirm::ZrtpPacketConfirm() {
    initialize();
    setSignatureLength(0);
}

ZrtpPacketConfirm::ZrtpPacketConfirm(int32_t const sl) {
    initialize();
    setSignatureLength(sl);
}

void ZrtpPacketConfirm::initialize() {
    zrtpHeader = &reinterpret_cast<ConfirmPacket_t *>(data)->hdr; // the standard header

    setZrtpId();
}

bool ZrtpPacketConfirm::setSignatureLength(int32_t const sl) {
    if (sl > 512)
        return false;

    auto const length = sizeof(ConfirmPacket_t) + sl * ZRTP_WORD_SIZE;
    confirmHeader->sigLength = sl & 0xff; // sigLength is an uint byte
    if (sl & 0x100U) {
        // check the 9th bit
        confirmHeader->filler[1] = 1; // and set it if necessary
    }
    setLength(length / 4);
    return true;
}

// ReSharper disable once CppMemberFunctionMayBeConst
bool ZrtpPacketConfirm::setSignatureData(const uint8_t* dataIn, int32_t const length) const {
    if (int32_t const l = getSignatureLength() * 4; length > l || length % 4 != 0)
        return false;

    uint8_t* p = reinterpret_cast<uint8_t *>(&confirmHeader->expTime) + 4; // point to signature block
    memcpy(p, dataIn, length);
    return true;
}

bool ZrtpPacketConfirm::isSignatureLengthOk() const {
    int32_t const actualLen = getLength();
    int32_t expectedLen = 19; // Confirm packet fixed part is 19 ZRTP words
    int32_t const sigLen = getSignatureLength();

    expectedLen += sigLen;
    return expectedLen == actualLen;
}

int32_t ZrtpPacketConfirm::getSignatureLength() const {
    auto sl = confirmHeader->sigLength & 0xff;
    if (confirmHeader->filler[1] == 1) {
        // do we have a 9th bit
        sl |= 0x100;
    }
    return sl;
}

ZrtpPacketConfirm::ZrtpPacketConfirm(const uint8_t* data) {
    // the standard header
    zrtpHeader = const_cast<zrtpPacketHeader_t *>(&reinterpret_cast<ConfirmPacket_t const *>(data)->hdr);
    confirmHeader = const_cast<Confirm_t *>(&reinterpret_cast<ConfirmPacket_t const *>(data)->confirm);
}
