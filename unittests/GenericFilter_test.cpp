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
// Created by werner on 28.01.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#include <zrtp/libzrtpcpp/ZrtpTextData.h>
#include "../logging/ZrtpLogging.h"
#include "../clients/genericClient/GenericPacketFilter.h"
#include "helpers/ZrtpConfigureBuilder.h"
#include "gtest/gtest.h"

using namespace std;

static
uint8_t rtpPacket[] = {
//        V2 | PT  |   seqnum  |        timestamp      |          SSRC        |
        0x80, 0x03, 0x47, 0x11, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01,  // Header
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20};

static
uint8_t zrtpPacket[] = {
//      V0,X | PT  |   seqnum  |   ZRTP magic cookie   |          SSRC        |
        0x01, 0x00, 0x47, 0x11, 0x5a, 0x52, 0x54, 0x50, 0x00, 0x00, 0x00, 0x02,  // Header
        0x50, 0x5a, 0x03, 0x00, 'H', 'e', 'l', 'l', 'o', 'A', 'C', 'K', 'c', 'r', 'c', 'x'};    // simulate a crc field

static
uint8_t zrtpRawData[] = {
//      preamble   | length    | ZRTP content                          | space for CRC
        0x50, 0x5a, 0x00, 0x03, 'H', 'e', 'l', 'l', 'o', 'A', 'C', 'K', 'c', 'r', 'c', 'x'};    // simulate a crc field

class GenericFilterTestFixture: public ::testing::Test {
public:
    GenericFilterTestFixture() = default;

    GenericFilterTestFixture(const GenericFilterTestFixture& other) = delete;
    GenericFilterTestFixture(const GenericFilterTestFixture&& other) = delete;
    GenericFilterTestFixture& operator= (const GenericFilterTestFixture& other) = delete;
    GenericFilterTestFixture& operator= (const GenericFilterTestFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(DEBUGGING);
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
        unlink("file.data");
    }

    ~GenericFilterTestFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }
};

TEST_F(GenericFilterTestFixture, zrtpDetection) {
    size_t offset = 0;
    uint32_t ssrc = 0;
    ASSERT_EQ(GenericPacketFilter::NotZrtp, GenericPacketFilter::checkRtpData(rtpPacket, sizeof(rtpPacket), offset, ssrc));
    ASSERT_EQ(0, offset);
    ASSERT_EQ(0, ssrc);

    ASSERT_EQ(GenericPacketFilter::IsZrtp, GenericPacketFilter::checkRtpData(zrtpPacket, sizeof(zrtpPacket), offset, ssrc));
    ASSERT_EQ(12, offset);          // 12 -> RTP header length, first byte of ZRTP data
    ASSERT_EQ(2, ssrc);

}

TEST_F(GenericFilterTestFixture, prepareRtp) {
    auto filter = GenericPacketFilter::createGenericFilter();

    auto protocolData = GenericPacketFilter::prepareToSendRtp(*filter, zrtpRawData, sizeof(zrtpRawData));
    ASSERT_EQ(sizeof(zrtpRawData) + 12, protocolData.length);
    ASSERT_TRUE(protocolData.ptr);

    // the ProtocolData structure contains a shared_ptr<void>, thus we need to cast to the
    // real data first.
    auto ptr = static_pointer_cast<secUtilities::SecureArrayFlex>(protocolData.ptr);
    size_t offset = 0;
    uint32_t ssrc = 0;
    ASSERT_EQ(GenericPacketFilter::IsZrtp, GenericPacketFilter::checkRtpData(ptr->data(), protocolData.length, offset, ssrc));
    ASSERT_EQ(12, offset);          // 12 -> RTP header length, first byte of ZRTP data
}

TEST_F(GenericFilterTestFixture, buildConfigure) {

    auto config = ZrtpConfigureBuilder::builder().publicKeyAlgorithms(ec25).build();
    ASSERT_EQ(1, config->getNumConfiguredAlgos(PubKeyAlgorithm));
    ASSERT_TRUE(config->containsAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName(ec25)));

    config = ZrtpConfigureBuilder::builder().cipherAlgorithms(aes3).build();
    ASSERT_EQ(1, config->getNumConfiguredAlgos(CipherAlgorithm));
    ASSERT_TRUE(config->containsAlgo(CipherAlgorithm, zrtpSymCiphers.getByName(aes3)));

    bool cacheIsOk = false;

    config = ZrtpConfigureBuilder::builder()
            .publicKeyAlgorithms(ec25, ec38)
            .cipherAlgorithms(aes3, two3)
            .initializeCache("file.data", ZrtpConfigureBuilder::FileCache, cacheIsOk)
            .build();

    ASSERT_EQ(2, config->getNumConfiguredAlgos(PubKeyAlgorithm));
    ASSERT_EQ(2, config->getNumConfiguredAlgos(CipherAlgorithm));
    ASSERT_TRUE(config->containsAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName(ec25)));
    ASSERT_TRUE(config->containsAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName(ec38)));
    ASSERT_TRUE(config->containsAlgo(CipherAlgorithm, zrtpSymCiphers.getByName(aes3)));
    ASSERT_TRUE(config->containsAlgo(CipherAlgorithm, zrtpSymCiphers.getByName(two3)));
    ASSERT_TRUE(cacheIsOk);

    // File should exist
    struct stat fileStatus = {};
    auto result = stat("file.data", &fileStatus);
    ASSERT_EQ(0, result);
}

TEST_F(GenericFilterTestFixture, SetterGetter) {
    auto filter = GenericPacketFilter::createGenericFilter();

    filter->ownRtpSsrc(1471).zrtpSequenceNo(815);

    ASSERT_EQ(1471, filter->ownRtpSsrc());
    ASSERT_EQ(815, filter->zrtpSequenceNo());
}

TEST_F(GenericFilterTestFixture, startStopZrtp) {

    bool cacheIsOk = false;
    auto config = ZrtpConfigureBuilder::builder()
            .publicKeyAlgorithms(ec25, ec38)
            .cipherAlgorithms(aes3, two3)
            .initializeCache("file.data", ZrtpConfigureBuilder::FileCache, cacheIsOk)
            .build();

    // Just to check if doSend was called.
    bool doSendCalled = false;
    auto doSend = [& doSendCalled](GenericPacketFilter::ProtocolData& protocolData) -> bool {
        if (protocolData.length > 0 && protocolData.ptr) {
            doSendCalled = true;
        }
        return true;
    };

    auto filter = GenericPacketFilter::createGenericFilter();
    filter->setZrtpConfiguration(config)
            .ownRtpSsrc(1471)
            .onDoSend(doSend);

    auto result = filter->startZrtpEngine();
    ASSERT_EQ(GenericPacketFilter::Success, result);
    ASSERT_TRUE(doSendCalled);
}