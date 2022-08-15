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
// Created by werner on 15.08.22.
// Copyright (c) 2022 Werner Dittmann. All rights reserved.
//

#include "libzrtpcpp/ZRtp.h"

int32_t
ZRtp::sendAsZrtpFrames(ZrtpPacketBase *packet) {
    if (packet == nullptr) {
        return 0;
    }

    uint8_t currentBatch;
    if (packet != sentFramePacket) {
        sentFramePacket = packet;
        currentBatch = frameBatch++;
    } else {
        currentBatch = frameBatch;
    }
    constexpr uint16_t FRAME_HEADER_LEN = static_cast<uint16_t>(sizeof(FrameHeader_t) / ZRTP_WORD_SIZE) & 0xffff;

    // space to store the ZRTP frame data: 1 -> CRC, 10 -> some security margin :)
    uint8_t frameBuffer[(MAX_MSG_LEN_WORDS + FRAME_HEADER_LEN + 1 + 10) * ZRTP_WORD_SIZE];

    auto packetLength = packet->getLength();

    uint8_t currentFrame = 0;
    uint8_t lastFrame = packetLength / MAX_MSG_LEN_WORDS;

    FrameHeader_t frameHeader;
    frameHeader.frameInfo.f.batchNumber = currentBatch;
    frameHeader.frameInfo.f.lastFrame = lastFrame;

    do {
        memset(frameBuffer, 0, sizeof(frameBuffer));
        auto processedPacketLength = packetLength < MAX_MSG_LEN_WORDS ? packetLength : MAX_MSG_LEN_WORDS;
        packetLength -= processedPacketLength;
        uint16_t frameLength = processedPacketLength + FRAME_HEADER_LEN;
        frameHeader.length = zrtpHtons (frameLength);
        frameHeader.frameInfo.f.continuationFlag = processedPacketLength < MAX_MSG_LEN_WORDS ? 0 : 1;
        frameHeader.frameInfo.f.frameNumber = currentFrame++;

        memcpy(frameBuffer, &frameHeader, FRAME_HEADER_LEN * ZRTP_WORD_SIZE);
        memcpy(frameBuffer + (FRAME_HEADER_LEN * ZRTP_WORD_SIZE), packet->getHeaderBase(), processedPacketLength * ZRTP_WORD_SIZE );

        if (auto ucb = callback.lock()) {
            return ucb->sendFrameDataZRTP(frameBuffer, (frameLength * ZRTP_WORD_SIZE) + CRC_SIZE, 0);
        }

    } while (packetLength > 0);

    return 0;
}

int32_t
ZRtp::sendAsZrtpMultiFrames(std::list<ZrtpPacketBase *>packets) {
    return 0;
}
