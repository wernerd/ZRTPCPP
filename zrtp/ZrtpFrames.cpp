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
#include <climits>
#include <thread>
#include "libzrtpcpp/ZRtp.h"
#include "libzrtpcpp/ZrtpStateEngineImpl.h"
#include "libzrtpcpp/ZrtpCodes.h"
#include "common/Utilities.h"

constexpr uint16_t FRAME_HEADER_LEN = static_cast<uint16_t>(sizeof(FrameHeader_t) / ZRTP_WORD_SIZE) & 0xffff;
constexpr int MAX_EMBEDDED_FRAMES = 10;

int32_t
ZRtp::sendAsZrtpFrames(ZrtpPacketBase *packet) {
    LOGGER(VERBOSE, "Enter ", __func__, " length: ", packet->getLength())
    if (packet == nullptr) {
        return 0;
    }

    uint8_t currentBatch;
    if (packet != sentFramePacket) {
        sentFramePacket = packet;
        currentBatch = sendFrameBatch++;
    } else {
        currentBatch = sendFrameBatch;
    }

    // space to store the ZRTP frame data: 1 -> CRC, 10 -> some security margin :)
    uint8_t frameBuffer[(LENGTH_BEFORE_SPLIT + FRAME_HEADER_LEN + 1 + 10) * ZRTP_WORD_SIZE];

    auto packetLength = packet->getLength();
    auto packetPointer = packet->getHeaderBase();

    uint8_t currentFrame = 0;
    uint8_t lastFrame = packetLength / LENGTH_BEFORE_SPLIT;

    do {
        memset(frameBuffer, 0, sizeof(frameBuffer));
        auto processedPacketLength = packetLength < LENGTH_BEFORE_SPLIT ? packetLength : LENGTH_BEFORE_SPLIT;
        packetLength -= processedPacketLength;
        uint16_t frameLength = processedPacketLength + FRAME_HEADER_LEN;

        FrameHeader_t frameHeader;
        frameHeader.frameInfo.f.batchNumber = currentBatch;
        frameHeader.frameInfo.f.lastFrame = lastFrame;
        frameHeader.length = zrtpHtons(frameLength);
        frameHeader.frameInfo.f.frameNumber = currentFrame++;
        frameHeader.frameInfo.f.continuationFlag = processedPacketLength < LENGTH_BEFORE_SPLIT ? 0 : 1;

        frameHeader.frameInfo.value = zrtpHtons(frameHeader.frameInfo.value);

        memcpy(frameBuffer, &frameHeader, FRAME_HEADER_LEN * ZRTP_WORD_SIZE);
        memcpy(frameBuffer + (FRAME_HEADER_LEN * ZRTP_WORD_SIZE), packetPointer,
               processedPacketLength * ZRTP_WORD_SIZE);
        packetPointer += processedPacketLength * ZRTP_WORD_SIZE;

        if (auto ucb = callback.lock()) {
            LOGGER(DEBUGGING, "Sending ", __func__, ", id: ", std::this_thread::get_id(), ", processed: ", processedPacketLength)
            if (ucb->sendFrameDataZRTP(frameBuffer, (frameLength * ZRTP_WORD_SIZE) + CRC_SIZE, 0) != 1)
                return 0;
        }

    } while (packetLength > 0);

    return 1;
}

int32_t
ZRtp::sendAsZrtpMultiFrames(std::unique_ptr<std::list<std::reference_wrapper<ZrtpPacketBase>>> packets) {
    LOGGER(VERBOSE, "Enter ", __func__, ", id: ", std::this_thread::get_id())

    size_t lengthAllPackets = 0;

    for (ZrtpPacketBase packet: *packets) {
        lengthAllPackets += packet.getLength();
    }
    uint16_t totalLength = lengthAllPackets + packets->size() * FRAME_HEADER_LEN;
    if (totalLength >= LENGTH_BEFORE_SPLIT) {
        return 0;
    }
    uint8_t currentBatch = ++sendFrameBatch;
    uint16_t numberOfFrames = packets->size();

    // space to store the ZRTP frame data: 1 -> CRC, 10 -> some security margin :)
    uint8_t frameBuffer[LENGTH_BEFORE_SPLIT]{0};
    uint8_t *frameBufferPointer = frameBuffer;

    // Frame info is static: contains same batch number and each packt is one frame only, thus: 0, 0
    FrameHeader_t frameHeader{0};
    frameHeader.frameInfo.f.batchNumber = currentBatch;
    frameHeader.frameInfo.value = zrtpHtons(frameHeader.frameInfo.value);

    for (ZrtpPacketBase packet: *packets) {
        uint16_t frameLength = packet.getLength() + FRAME_HEADER_LEN;
        frameHeader.length = zrtpHtons(frameLength);
        memcpy(frameBufferPointer, &frameHeader, FRAME_HEADER_LEN * ZRTP_WORD_SIZE);

        frameBufferPointer += FRAME_HEADER_LEN * ZRTP_WORD_SIZE;
        memcpy(frameBufferPointer, packet.getHeaderBase(), packet.getLength() * ZRTP_WORD_SIZE);
        frameBufferPointer += packet.getLength() * ZRTP_WORD_SIZE;
    }
    if (auto ucb = callback.lock()) {
        return ucb->sendFrameDataZRTP(frameBuffer, (totalLength * ZRTP_WORD_SIZE) + CRC_SIZE, numberOfFrames);
    }
    return 0;
}

// Returns the of total length in ZRTP words: sum of message lengths and frame headers
static int32_t
unpackAndCheck(uint8_t const *zrtpFrame, int numberOfFrames, uint8_t const *packetAddresses[]) {
    LOGGER(VERBOSE, "Enter ", __func__, "frames in packrt: ", numberOfFrames)

    uint8_t currentBatch;
    int32_t totalLength = 0;

    for (auto frameNum = 0; frameNum < numberOfFrames; frameNum++) {
        FrameHeader_t frameHeader;
        // get the frame fields, need to convert to LE, thus get via uint16_t pointer
        // value is an uint16_t union with the bit fields
        frameHeader.frameInfo.value = zrtpNtohs(*reinterpret_cast<uint16_t const *>(zrtpFrame));

        if (frameNum == 0) {
            currentBatch = frameHeader.frameInfo.f.batchNumber;
        } else if (currentBatch != frameHeader.frameInfo.f.batchNumber) {
            return 0;           // batch number of frames must match within multi-frame packets
        }
        packetAddresses[frameNum] = zrtpFrame;

        // get the frame length, right behind the frame info
        frameHeader.length = zrtpNtohs(*reinterpret_cast<uint16_t const *>(zrtpFrame + 2));

        // Get the message length and compute the total length: used to perform sanity checks
        auto currentMsgLength = zrtpNtohs(*reinterpret_cast<uint16_t const *>(zrtpFrame + 6));
        totalLength += currentMsgLength + FRAME_HEADER_LEN;

        // skip over the current ZRTP message, point to next embedded frame
        zrtpFrame += frameHeader.length * ZRTP_WORD_SIZE;
    }
    return totalLength;
}

void
ZRtp::processZrtpFramePacket(uint8_t const *zrtpMessage, uint32_t pSSRC, size_t length, uint8_t frameByte) {
    LOGGER(VERBOSE, "Enter ", __func__)

    Event ev;

    peerSSRC = pSSRC;
    ev.type = ZrtpPacket;
    ev.length = 0;

    ZrtpStateEngine *stateEngineLocal;

    // Get a local copy to avoid many checks below. Return if no state engine is available.
    // Not completely thread safe - if this fails rework your ZRTP implementation :)
    if ((stateEngineLocal = stateEngine.get()) == nullptr) {
        return;
    }
    auto numberOfFrames = (frameByte & 0xe) >> 1;
    constexpr auto MIN_MESSAGE_LENGTH = sizeof(HelloAckPacket);

    if (numberOfFrames > 0) {
        auto minimumLength =
                (numberOfFrames * FRAME_HEADER_LEN) * ZRTP_WORD_SIZE + MIN_MESSAGE_LENGTH + stateEngineLocal->getTransportOverhead();

        if (numberOfFrames > MAX_EMBEDDED_FRAMES || length < minimumLength) {
            LOGGER(ERROR_LOG, "Received data too small/too big. Length: ", length, ", num of frames: ", numberOfFrames)
            stateEngineLocal->sendErrorPacket(GnuZrtpCodes::MalformedPacket);
            return;
        }
        // A multi-frame packet can contain up to 7 packets
        uint8_t const *packetAddresses[7]{nullptr};
        auto msgLength = unpackAndCheck(zrtpMessage, numberOfFrames, packetAddresses);
        if (msgLength == 0) {
            return;         // got not all frames yet
        }

        // perform some sanity checks before processing the ZRTP messages
        if (msgLength < 0) {  // don't process message any further
            LOGGER(ERROR_LOG, "Unpacking embedded ZRTP messages failed")
            stateEngineLocal->sendErrorPacket(GnuZrtpCodes::MalformedPacket);
            return;
        }
        auto totalLength = msgLength * ZRTP_WORD_SIZE + CRC_SIZE + stateEngineLocal->getTransportOverhead();
        if (totalLength != length) {
            LOGGER(ERROR_LOG, __func__ , ": Total length does not match received length: ", totalLength, " - ", length)
            stateEngineLocal->sendErrorPacket(GnuZrtpCodes::MalformedPacket);
            return;
        }
        for (auto address: packetAddresses) {
            if (address == nullptr) {
                break;
            }
            ev.packet = address;
            stateEngineLocal->processEvent(&ev);
        }
    } else {
        auto minimumLength = FRAME_HEADER_LEN * ZRTP_WORD_SIZE + MIN_MESSAGE_LENGTH + stateEngineLocal->getTransportOverhead();
        if (length < minimumLength) {
            LOGGER(ERROR_LOG, "Received data too small. Length: ", length, ", min: ", minimumLength)
            stateEngineLocal->sendErrorPacket(GnuZrtpCodes::MalformedPacket);
            return;
        }
        auto assembledLength = assembleMessage(zrtpMessage, length);
        if (assembledLength == 0) {
            return;
        }
        auto zrtpMsgLength = zrtpNtohs(*reinterpret_cast<uint16_t *>(assembleBuffer + 2));
        if (assembledLength != zrtpMsgLength) {
            LOGGER(ERROR_LOG, "Message length does not match assembled length: ", zrtpMsgLength, " - ", assembledLength)
            stateEngineLocal->sendErrorPacket(GnuZrtpCodes::MalformedPacket);
            return;
        }
        ev.packet = assembleBuffer;
        stateEngineLocal->processEvent(&ev);

        // Reset frame related data to initial values, ready for new frame
        receiveFrameBatch = USHRT_MAX;
        lastFrameNumber = USHRT_MAX;
        memset(assembleBuffer, 0, sizeof(assembleBuffer));
    }
}

int32_t
ZRtp::assembleMessage(uint8_t const *zrtpFrame, size_t length) {
    LOGGER(VERBOSE, "Enter ", __func__)

    FrameHeader_t frameHeader;

    ZrtpStateEngine *stateEngineLocal;
    if ((stateEngineLocal = stateEngine.get()) == nullptr) {
        return 0;
    }

    // get the frame fields, need to convert to LE, thus get via uint16_t pointer
    // value is an uint16_t union with the bit fields
    frameHeader.frameInfo.value = zrtpNtohs(*reinterpret_cast<uint16_t const *>(zrtpFrame));

    if (receiveFrameBatch == USHRT_MAX) {
        receiveFrameBatch = frameHeader.frameInfo.f.batchNumber;
    } else if (receiveFrameBatch != frameHeader.frameInfo.f.batchNumber) {
        LOGGER(ERROR_LOG, "Batch number changed during frame processing.")
        stateEngineLocal->sendErrorPacket(GnuZrtpCodes::MalformedPacket);
        return 0;
    }

    if (lastFrameNumber == USHRT_MAX) {
        lastFrameNumber = frameHeader.frameInfo.f.lastFrame;
    } else if (lastFrameNumber != frameHeader.frameInfo.f.lastFrame) {
        LOGGER(ERROR_LOG, "Last frame number changed during same batch, expected: ", lastFrameNumber, ", got: ", frameHeader.frameInfo.f.lastFrame)
        stateEngineLocal->sendErrorPacket(GnuZrtpCodes::MalformedPacket);
        return 0;
    }

    if (lastFrameNumber + 1 > MAX_FRAMES) {
        LOGGER(ERROR_LOG, "Total length of ZRTP message is too big: ", lastFrameNumber, " - ", MAX_FRAMES)
        stateEngineLocal->sendErrorPacket(GnuZrtpCodes::MalformedPacket);
        return 0;
    }
    // get the frame length, right behind the frame info
    frameHeader.length = zrtpNtohs(*reinterpret_cast<uint16_t const *>(zrtpFrame + 2));

    if (frameHeader.length * ZRTP_WORD_SIZE + CRC_SIZE + stateEngineLocal->getTransportOverhead() != length) {
        LOGGER(ERROR_LOG, "Received length does not match computed length: ", length, " - ",
               frameHeader.length * ZRTP_WORD_SIZE + RTP_HEADER_LENGTH + CRC_SIZE)
        stateEngineLocal->sendErrorPacket(GnuZrtpCodes::MalformedPacket);
        return 0;
    }

    auto currentFrame = frameHeader.frameInfo.f.frameNumber;
    frameHeaders[currentFrame] = frameHeader;

    // Copy the raw ZRTP message data without fragment header
    memcpy(frameBuffers[currentFrame],
           zrtpFrame + FRAME_HEADER_LEN * ZRTP_WORD_SIZE,
           (frameHeader.length - 1) * ZRTP_WORD_SIZE);
    framesHandled[currentFrame] = true;

    auto gotAllFrames = true;
    for (int i = 0; i <= lastFrameNumber; i++) {
        gotAllFrames = gotAllFrames & framesHandled[i];
    }
    if (!gotAllFrames) {
        return 0;
    }

    int32_t totalLength{0};
    uint8_t *bufferPointer = assembleBuffer;

    for (int i = 0; i <= lastFrameNumber; i++) {
        auto header = frameHeaders[i];
        totalLength += header.length - FRAME_HEADER_LEN;
        auto frameNumber = header.frameInfo.f.frameNumber;
        memcpy(bufferPointer, frameBuffers[frameNumber], (header.length - 1) * ZRTP_WORD_SIZE);
        bufferPointer += (header.length - 1) * ZRTP_WORD_SIZE;

        // Frame processed, clear buffer and status
        memset(frameBuffers[frameNumber], 0, (header.length - 1) * ZRTP_WORD_SIZE);
        framesHandled[i] = false;
    }
    return totalLength;
}

