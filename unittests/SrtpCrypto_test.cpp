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
// Created by werner on 01.02.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//
#include "../logging/ZrtpLogging.h"
#include "../common/osSpecifics.h"
#include "../common/Utilities.h"
#include "../srtp/crypto/SrtpSymCrypto.h"
#include "gtest/gtest.h"

using namespace std;

class SrtpCryptoTestFixture: public ::testing::Test {
public:
    SrtpCryptoTestFixture() = default;

    SrtpCryptoTestFixture(const SrtpCryptoTestFixture& other) = delete;
    SrtpCryptoTestFixture(const SrtpCryptoTestFixture&& other) = delete;
    SrtpCryptoTestFixture& operator= (const SrtpCryptoTestFixture& other) = delete;
    SrtpCryptoTestFixture& operator= (const SrtpCryptoTestFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(DEBUGGING);
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~SrtpCryptoTestFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }
};

/*
 * The F8 test vectors according to RFC3711
 */
static unsigned char salt[] = {0x32, 0xf2, 0x87, 0x0d};

static unsigned char iv[] = {  0x00, 0x6e, 0x5c, 0xba, 0x50, 0x68, 0x1d, 0xe5,
                               0x5c, 0x62, 0x15, 0x99, 0xd4, 0x62, 0x56, 0x4a};

static unsigned char key[]= {  0x23, 0x48, 0x29, 0x00, 0x84, 0x67, 0xbe, 0x18,
                               0x6c, 0x3d, 0xe1, 0x4a, 0xae, 0x72, 0xd6, 0x2c};

static unsigned char payload[] = {
        0x70, 0x73, 0x65, 0x75, 0x64, 0x6f, 0x72, 0x61,
        0x6e, 0x64, 0x6f, 0x6d, 0x6e, 0x65, 0x73, 0x73,
        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x6e, 0x65, 0x78, 0x74, 0x20, 0x62, 0x65, 0x73,
        0x74, 0x20, 0x74, 0x68, 0x69, 0x6e, 0x67};  // 39 bytes

static unsigned char cipherText[] = {
        0x01, 0x9c, 0xe7, 0xa2, 0x6e, 0x78, 0x54, 0x01,
        0x4a, 0x63, 0x66, 0xaa, 0x95, 0xd4, 0xee, 0xfd,
        0x1a, 0xd4, 0x17, 0x2a, 0x14, 0xf9, 0xfa, 0xf4,
        0x55, 0xb7, 0xf1, 0xd4, 0xb6, 0x2b, 0xd0, 0x8f,
        0x56, 0x2c, 0x0e, 0xef, 0x7c, 0x48, 0x02}; // 39 bytes

static unsigned char rtpPacket[] = {
        0x80, 0x6e, 0x5c, 0xba, 0x50, 0x68, 0x1d, 0xe5,
        0x5c, 0x62, 0x15, 0x99,                        // header
        0x70, 0x73, 0x65, 0x75, 0x64, 0x6f, 0x72, 0x61, // payload
        0x6e, 0x64, 0x6f, 0x6d, 0x6e, 0x65, 0x73, 0x73,
        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x6e, 0x65, 0x78, 0x74, 0x20, 0x62, 0x65, 0x73,
        0x74, 0x20, 0x74, 0x68, 0x69, 0x6e, 0x67};

static uint32_t ROC = 0xd462564a;

TEST_F(SrtpCryptoTestFixture, f8_test) {
    auto aesCipher = make_unique<SrtpSymCrypto>(SrtpEncryptionAESF8);
    auto f8AesCipher = make_unique<SrtpSymCrypto>(SrtpEncryptionAESF8);

    aesCipher->setNewKey(key, sizeof(key));

    /* Create the F8 IV (refer to chapter 4.1.2.2 in RFC 3711):
     *
     * IV = 0x00 || M || PT || SEQ  ||      TS    ||    SSRC   ||    ROC
     *      8Bit  1bit  7bit  16bit       32bit        32bit        32bit
     * ------------\     /--------------------------------------------------
     *       XX       XX      XX XX   XX XX XX XX   XX XX XX XX  XX XX XX XX
     */

    unsigned char derivedIv[16];
    auto* ui32p = (uint32_t*)derivedIv;

    memcpy(derivedIv, rtpPacket, 12);
    derivedIv[0] = 0;

    // set ROC in network order into IV
    ui32p[3] = zrtpHtonl(ROC);

    int32_t pad = 0;

    ASSERT_EQ(0, memcmp(iv, derivedIv, 16)) << "Wrong IV constructed\n"
            << *zrtp::Utilities::hexdump("derivedIv", derivedIv, 16)
            << *zrtp::Utilities::hexdump("test vector Iv", iv, 16);

    SrtpSymCrypto::f8_deriveForIV(f8AesCipher.get(), key, sizeof(key), salt, sizeof(salt));

    // now encrypt the RTP payload data
    aesCipher->f8_encrypt(rtpPacket + 12, sizeof(rtpPacket)-12+pad, derivedIv, f8AesCipher.get());

    // compare with test vector cipher data
    ASSERT_EQ(0, memcmp(rtpPacket+12, cipherText, sizeof(rtpPacket)-12+pad)) << "cipher data mismatch\n"
        << *zrtp::Utilities::hexdump("Computed cipher data", rtpPacket+12, sizeof(rtpPacket)-12+pad)
        << *zrtp::Utilities::hexdump("Test vector cipher data", cipherText, sizeof(cipherText));

    // Now decrypt the data to get the payload data again
    aesCipher->f8_encrypt(rtpPacket+12, sizeof(rtpPacket)-12+pad, derivedIv, f8AesCipher.get());

    // compare decrypted data with test vector payload data
    ASSERT_EQ(0, memcmp(rtpPacket+12, payload, sizeof(rtpPacket)-12+pad)) << "payload data mismatch\n"
        << *zrtp::Utilities::hexdump("Computed payload data", rtpPacket+12, sizeof(rtpPacket)-12+pad)
        << *zrtp::Utilities::hexdump("Test vector payload data", payload, sizeof(payload));
}

static uint8_t tagValue[] = { 0x5e, 0xbc, 0x5b, 0xfd, 0x51, 0xc8, 0x78, 0xb4, 0x06, 0x93 };

TEST_F(SrtpCryptoTestFixture, authentication_test) {

    // Reuse some data from F8 test vectors just to initialize CryptoContext
    auto testCryptoContext
            = make_unique<CryptoContext>(0,                             // SSRC (used for lookup)
                                         0,                             // Roll-Over-Counter (ROC)
                                         0L,                            // key derivation << 48,
                                         SrtpEncryptionAESCM,           // encryption algo
                                         SrtpAuthenticationSha1Hmac,    // authentication algo
                                         key,                           // Master Key
                                         16,                            // Master Key length
                                         iv,                            // Master Salt
                                         14,                            // Master Salt length
                                         16,                            // encryption keyl
                                         20,                            // authentication key len
                                         14,                            // session salt len
                                         10);                           // authentication tag lenA

    testCryptoContext->deriveSrtpKeys(0L);

    uint8_t computedTag[10];
    testCryptoContext->srtpAuthenticate(rtpPacket, sizeof(rtpPacket), 0, computedTag);
    ASSERT_EQ(0, memcmp(tagValue, computedTag, sizeof(tagValue))) << "tag data mismatch\n"
        << *zrtp::Utilities::hexdump("Computed tag data", computedTag, sizeof(tagValue))
        << *zrtp::Utilities::hexdump("Test vector tag data", tagValue, sizeof(tagValue));
}
