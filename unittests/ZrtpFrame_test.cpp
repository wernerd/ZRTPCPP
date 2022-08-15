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

#include "../zrtp/libzrtpcpp/zrtpPacket.h"
#include "../logging/ZrtpLogging.h"
#include "libzrtpcpp/ZrtpConfigure.h"
#include "ZrtpTestCommon.h"
#include "libzrtpcpp/ZRtp.h"
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
        LOGGER_INSTANCE setLogLevel(DEBUGGING);

        // Configure with mandatory algorithms only
        std::shared_ptr<ZrtpConfigure> configure = std::make_shared<ZrtpConfigure>();

        std::shared_ptr<ZIDCache> aliceCache = std::make_shared<ZIDCacheEmpty>();
        aliceCache->setZid(aliceZid);
        configure->setZidCache(aliceCache);

        int32_t timers = 0;

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

    ZRtp *zrtp;
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
TEST_F(ZrtpFrameTestFixture, wrapSimpleMessage) {
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

//    auto dmp = zrtp::Utilities::hexdump("Frame packet", buffer, copiedLen);
//    LOGGER(DEBUGGING, "length: ", copiedLen, "\n", *dmp)

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
