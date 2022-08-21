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
// Created by werner on 14.08.22.
// Copyright (c) 2022 Werner Dittmann. All rights reserved.
//

#include <cstdint>

#include "ZrtpTestCommon.h"
#include "libzrtpcpp/zrtpPacket.h"
#include "libzrtpcpp/ZrtpConfigure.h"
#include "libzrtpcpp/ZRtp.h"
#include "libzrtpcpp/ZrtpStateEngineImpl.h"

#include "../common/Utilities.h"

#include "../clients/tivi/CtZrtpSession.h"
#include "../clients/tivi/CtZrtpCallback.h"
#include "../clients/tivi/CtZrtpStream.h"

using testing::_;
using testing::Ge;
using testing::SaveArg;
using testing::DoAll;
using testing::Eq;

std::string aliceId;
std::string BobId;
uint8_t aliceZid[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
uint8_t bobZid[] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};

// RTP header according to RFC, example values:
// - no extension, no padding, no CC (CSRC count)
// - no marker, payload type 110
// - random sequence number
// - random timestamp
// - random SSRC
static unsigned char rtpPacketHeader[] = {
        0x80,               // Version (2 bits), must be 2, padding(1 bit), extension (1 bit), CC (4 bits)
        0x6e,               // Marker (1 bit), payload type (7 bits)
        0x5c, 0xba,     // sequence number, 16 bits
        0x50, 0x68, 0x1d, 0xe5,  // timestamp, 32 bits
        0x5c, 0x62, 0x15, 0x99 // CSRC - Contributing source
};

// ZRTP Frame header: same layout as RTP header but field usage is different
// and actually contain
// - a non-defined version number (0 instead of 2)
// - fixed 'payload' type 1 - ZRTP frame flag, ZRPT multi-frame packets contain additional data (number of frames)
// - fixed magic number instead of a timestamp
static unsigned char zrtpFrameHeader[] = {
        0x10,               // ZRTP: Version (2 bits) set to 0, padding(1 bit), extension (1 bit) set to 1, CC (4 bits)
        0x01,               // payload type (7 bits), set to 1
        0x5c, 0xba,     // sequence number, 16 bits
        0x5a, 0x52, 0x54, 0x50,  // timestamp, set to magic number 0x5a525450
        0x5c, 0x62, 0x15, 0x99 // CSRC - Contributing source
};

// Used to test frame packet which contains 1 HelloACK ZRTP message
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
// |Batch| Frame Num |Last Frame |I|...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
//  0 1 1 0|0 0 0 0|0 0 0 0|0 0 1 0
//
static uint8_t firstFrame[] = {
        0x60, 0x02,                 // Batch 3, frame number 0, last frame 1, continuation is 0
        0x00, 0x04,                 // Frame length
        0x50, 0x5a,                 // ZRTP_MAGIC
        0x00, 0x06,                 // Total ZRTP message length, both frames together are 6 ZRTP words
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x41, 0x43, 0x4b,
        0x78, 0x05, 0x0f, 0xd8 // CRC dummy data

};
// Used to test frame packet which contains 1 HelloACK ZRTP message
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
// |Batch| Frame Num |Last Frame |I|...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
//  0 1 1 0|0 0 0 0|1 0 0 0|0 0 1 1
//
static uint8_t secondFrame[] = {
        0x60, 0x83,                 // Batch 3, frame number 1, last frame 1, continuation is 1
        0x00, 0x04,                 // Frame length
        0x11, 0x11,                 // some data
        0x22, 0x22,                 //
        0x33, 0x44,
        0x44, 0x44,
        0x55, 0x55,
        0x66, 0x66,
        0x78, 0x05, 0x0f, 0xd8 // CRC - dummy data
};

// Used to test multi-frame packet which contains 2 HelloACK ZRTP messages
static uint8_t twoFramedHelloAck[] = {
        // First
        0x00, 0x00,                 // Batch 0, frame number 0, last frame 0, continuation is 0
        0x00, 0x04,                 // Frame length
        0x50, 0x5a,                 // ZRTP_MAGIC
        0x00, 0x03,                 // ZRTP message length, HelloAck is 3 words
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x41, 0x43, 0x4b,
        //second
        0x00, 0x00,                 // Batch 0, frame number 0, last frame 0, continuation is 0
        0x00, 0x04,                 // Frame length
        0x50, 0x5a,                 // ZRTP_MAGIC
        0x00, 0x03,                 // ZRTP message length, HelloAck is 3 words
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x41, 0x43, 0x4b,
        0x78, 0x05, 0x0f, 0xd8 // CRC

};
class MockSendCallback : public CtZrtpSendCb {
public:
    MOCK_METHOD(void, sendRtp,
                (CtZrtpSession const *session, uint8_t* packet, size_t length, CtZrtpSession::streamName streamNm),
                (override));
};

class ZrtpFrameTestFixture : public ::testing::Test {
public:
    ZrtpFrameTestFixture() = default;

    ZrtpFrameTestFixture(const ZrtpFrameTestFixture &other) = delete;

    ZrtpFrameTestFixture(const ZrtpFrameTestFixture &&other) = delete;

    ZrtpFrameTestFixture &operator=(const ZrtpFrameTestFixture &other) = delete;

    ZrtpFrameTestFixture &operator=(const ZrtpFrameTestFixture &&other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(WARNING);

        // Configure with mandatory algorithms only
        std::shared_ptr<ZrtpConfigure> configure = std::make_shared<ZrtpConfigure>();

        std::shared_ptr<ZIDCache> aliceCache = std::make_shared<ZIDCacheEmpty>();
        aliceCache->setZid(aliceZid);
        configure->setZidCache(aliceCache);

        sendCallback = std::make_shared<testing::NiceMock<MockSendCallback>>();

        auto castedCallback = std::static_pointer_cast<CtZrtpSendCb>(sendCallback);
        streamFull = std::make_shared<CtZrtpStream>();
        stream = streamFull;    // up-cast
        zrtp = new ZRtp(aliceId, stream, configure);
        streamFull->zrtpEngine = zrtp;
        streamFull->setSendCallback(castedCallback.get());
    }

    void TearDown() override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~ZrtpFrameTestFixture() override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }

    ZRtp *zrtp = nullptr;
    std::shared_ptr<ZrtpCallback> stream;
    std::shared_ptr<CtZrtpStream> streamFull;
    std::shared_ptr<testing::NiceMock<MockSendCallback>> sendCallback;
};

TEST_F(ZrtpFrameTestFixture, Basic) {
    // Just make sure the header fields have the correct length
    ASSERT_EQ(2, sizeof(FrameInfo_t));
    ASSERT_EQ(4, sizeof(FrameHeader_t));

    // Batch #3, frame number 1, last frame 3, continuation is 1
    //  0                   1
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
    // |Batch| Frame Num |Last Frame |I|...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
    //  0 1 1 0|0 0 0 0|1 0 0 0|0 1 1 1
    //  0x6087
    constexpr uint16_t frameInfoDataBE = 0x8760;    // this is network (BE) order

    // Check if implementation handles bit fields correctly
    FrameInfo_t fi;
    fi.f.batchNumber = 3;
    fi.f.frameNumber = 1;
    fi.f.lastFrame = 3;
    fi.f.continuationFlag = 1;

    ASSERT_EQ(frameInfoDataBE, zrtpHtons(fi.value));
}

// Test uses a simple HelloACK packet and sends it as a ZRTP frame packet.
// Catch the data via a Mock and check it
TEST_F(ZrtpFrameTestFixture, sendSimpleFramePacket) {
    uint8_t buffer[2000] = {0};
    int32_t copiedLen = 0;

    // Mocked call Just copies data, length, and returns.
    ON_CALL(*sendCallback, sendRtp(_, _, _, _))
            .WillByDefault(DoAll(([this, &buffer, &copiedLen]
                    (CtZrtpSession const *session, const uint8_t *data,
                     int32_t length, CtZrtpSession::streamName streamNm) {
                copiedLen = length;
                if (length < sizeof(buffer)) {
                    memcpy(buffer, data, length);
                }
            }), Return()));

    ZrtpPacketHelloAck helloAck;
    ASSERT_EQ(1, zrtp->sendAsZrtpFrames(&helloAck));

    LOGGER(DEBUGGING, "length: ", copiedLen, "\n", *zrtp::Utilities::hexdump("Frame packet", buffer, copiedLen))

    ASSERT_EQ(0x10, buffer[0]);
    ASSERT_EQ(1, buffer[1]);        // check frame packet flag

    uint32_t magic = zrtpNtohl(*reinterpret_cast<uint32_t *>(buffer + 4));
    ASSERT_EQ(ZRTP_MAGIC, magic);

    // this now points to the plain ZRTP frame.
    uint8_t *zrtpFrame = (buffer + ZRTP_RTP_HEADER_SIZE);

    FrameHeader_t frameHeader;
    // get the frame fields, need to convert to LE, thus get via uint16_t pointer
    // value is an uint16_t union with the bit fields
    frameHeader.frameInfo.value = zrtpNtohs(*reinterpret_cast<uint16_t *>(zrtpFrame));
    ASSERT_EQ(0, frameHeader.frameInfo.f.lastFrame);
    ASSERT_EQ(0, frameHeader.frameInfo.f.frameNumber);
    ASSERT_EQ(0, frameHeader.frameInfo.f.batchNumber);
    ASSERT_EQ(0, frameHeader.frameInfo.f.continuationFlag);

    // get the frame length, right behind the frame info
    frameHeader.length = zrtpNtohs(*reinterpret_cast<uint16_t *>(zrtpFrame + 2));
    ASSERT_EQ(4, frameHeader.length);

    // Real packet starts just behind the frame length
    ZrtpPacketHelloAck helloAckReceived(zrtpFrame + 4);
    ASSERT_EQ(3, helloAckReceived.getLength());
    auto msgType = helloAckReceived.getMessageType();
    ASSERT_EQ('H', *msgType);
    ASSERT_EQ('K', msgType[7]);
}

TEST_F(ZrtpFrameTestFixture, sendSimpleMultiFramePacket) {

    uint8_t buffer[2000] = {0};
    int32_t copiedLen = 0;

    // Mocked call Just copies data, length, and returns.
    ON_CALL(*sendCallback, sendRtp(_, _, _, _))
            .WillByDefault(DoAll(([&buffer, &copiedLen]
                    (CtZrtpSession const *session, const uint8_t *data,
                     int32_t length, CtZrtpSession::streamName streamNm) {
                copiedLen = length;
                if (length < sizeof(buffer)) {
                    memcpy(buffer, data, length);
                }
            }), Return()));

    ZrtpPacketHelloAck helloAck_1;
    ZrtpPacketHelloAck helloAck_2;

    std::unique_ptr<std::list<std::reference_wrapper<ZrtpPacketBase>>> packets =
            std::make_unique<std::list<std::reference_wrapper<ZrtpPacketBase>>>();
    packets->emplace_back(helloAck_1);
    packets->emplace_back(helloAck_2);

    ASSERT_EQ(1, zrtp->sendAsZrtpMultiFrames(std::move(packets)));

    LOGGER(DEBUGGING, "length: ", copiedLen, "\n", *zrtp::Utilities::hexdump("Frame packet", buffer, copiedLen))

    ASSERT_EQ(0x10, buffer[0]);
    ASSERT_EQ(5, buffer[1]);        // check frame packet flag and number of embedded frames: 101 : (2 << 1) | 1

    uint32_t magic = zrtpNtohl(*reinterpret_cast<uint32_t *>(buffer + 4));
    ASSERT_EQ(ZRTP_MAGIC, magic);

    // this now points to the plain ZRTP frame.
    uint8_t *zrtpFrame = buffer + ZRTP_RTP_HEADER_SIZE;

    // ZRTP data is between end of RTP header and start of CRC
    uint8_t * endData = buffer + copiedLen - CRC_SIZE;

    while (zrtpFrame < endData) {
        FrameHeader_t frameHeader;
        // get the frame fields, need to convert to LE, thus get via uint16_t pointer
        // value is an uint16_t union with the bit fields
        frameHeader.frameInfo.value = zrtpNtohs(*reinterpret_cast<uint16_t *>(zrtpFrame));
        ASSERT_EQ(0, frameHeader.frameInfo.f.lastFrame);
        ASSERT_EQ(0, frameHeader.frameInfo.f.frameNumber);
        ASSERT_EQ(1, frameHeader.frameInfo.f.batchNumber);  // batch 1, pre-incremented by send function
        ASSERT_EQ(0, frameHeader.frameInfo.f.continuationFlag);

        // get the frame length, right behind the frame info
        frameHeader.length = zrtpNtohs(*reinterpret_cast<uint16_t *>(zrtpFrame + 2));
        ASSERT_EQ(4, frameHeader.length);

        // Real packet starts just behind the frame length
        ZrtpPacketHelloAck helloAckReceived_1(zrtpFrame + 4);
        ASSERT_EQ(3, helloAckReceived_1.getLength());
        auto msgType = helloAckReceived_1.getMessageType();
        ASSERT_EQ('H', *msgType);
        ASSERT_EQ('K', msgType[7]);

        zrtpFrame += frameHeader.length * ZRTP_WORD_SIZE;   // skip over first frame
    }
}

TEST_F(ZrtpFrameTestFixture, incomingSimpleFramePacket) {
    auto zrtpCallback = std::make_unique<testing::NiceMock<MockZrtpState>>();

    ON_CALL(*zrtpCallback, processEvent(_))
            .WillByDefault(DoAll(([](Event* ev) {
                ASSERT_EQ(EventDataType::ZrtpPacket, ev->type);
            }), Return()));

    EXPECT_CALL(*zrtpCallback, processEvent(_)).Times(1);

    zrtp->stateEngine = std::move(zrtpCallback);
    zrtp->processZrtpFramePacket(firstFrame, 1, sizeof (firstFrame) + RTP_HEADER_LENGTH, 0x1);
    zrtp->processZrtpFramePacket(secondFrame, 1, sizeof (secondFrame) + RTP_HEADER_LENGTH, 0x1);
    zrtp->stateEngine = nullptr;
}

TEST_F(ZrtpFrameTestFixture, incomingSimpleMultiFramePacket) {

    auto zrtpCallback = std::make_unique<testing::NiceMock<MockZrtpState>>();

    ON_CALL(*zrtpCallback, processEvent(_))
            .WillByDefault(DoAll(([](Event* ev) {
                ASSERT_EQ(EventDataType::ZrtpPacket, ev->type);
            }), Return()));

    // Why three calls if there are only two embedded frames?
    // First call is the normal call which contains the unwrapped Zrtp message.
    //
    // The second call is the ZrtpClose event send by ZRtp destructor. This happens
    // because of the destruction of ZrtpFrameTestFixture and its embedded smart pointers.
    // ZrtpFrameTestFixture inherits from Test and its destructor runs last and
    // checks the EXPECT_CALL. Thus, we have two calls.
    //
    // EXPECT_CALL(*zrtpCallback, processEvent(_)).Times(3);
    //
    // To avoid this: set the stateEngine callback to nullptr right after the test call.
    // ZRtp does not call a null state engine :)
    // Also storing some event data by reference in local data during ON_CALL lambda
    // above causes a SIGSEGV in case the event is of type ZrtpClose -> some addresses
    // are illegal already because of the destructors I guess.

    EXPECT_CALL(*zrtpCallback, processEvent(_)).Times(2);

    zrtp->stateEngine = std::move(zrtpCallback);
    zrtp->processZrtpFramePacket(twoFramedHelloAck, 1, sizeof (twoFramedHelloAck) + RTP_HEADER_LENGTH, 0x5);
    zrtp->stateEngine = nullptr;
}