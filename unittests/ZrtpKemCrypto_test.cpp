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

#include "../logging/ZrtpLogging.h"
#include "../common/Utilities.h"

#include "crypto/zrtpKem.h"

#include "gtest/gtest.h"

//
// These tests use the zrtpDH crypto functions and compare the results
// to plain Botan crypto functions. Make sure the crypto wrapper works.
using namespace std;

class ZrtpKemCryptoTestFixture: public ::testing::Test {
public:
    ZrtpKemCryptoTestFixture() = default;

    ZrtpKemCryptoTestFixture(const ZrtpKemCryptoTestFixture& other) = delete;
    ZrtpKemCryptoTestFixture(const ZrtpKemCryptoTestFixture&& other) = delete;
    ZrtpKemCryptoTestFixture& operator= (const ZrtpKemCryptoTestFixture& other) = delete;
    ZrtpKemCryptoTestFixture& operator= (const ZrtpKemCryptoTestFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(WARNING);
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~ZrtpKemCryptoTestFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }
};

TEST_F(ZrtpKemCryptoTestFixture, simpleExchange_653) {

    secUtilities::SecureArray<SNTRUP_CRYPTO_SECRETKEYBYTES_653> secretKey;
    secUtilities::SecureArray<SNTRUP_CRYPTO_PUBLICKEYBYTES_653> publicKey;
    secUtilities::SecureArray<SNTRUP_CRYPTO_CIPHERTEXTBYTES_653> cipherText;
    secUtilities::SecureArray<SNTRUP_CRYPTO_BYTES> sharedKeyEnc;
    secUtilities::SecureArray<SNTRUP_CRYPTO_BYTES> sharedKeyDec;

    crypto_kem_sntrup653_keypair(publicKey.data(), secretKey.data());

    crypto_kem_sntrup653_enc(cipherText.data(), sharedKeyEnc.data(), publicKey.data());
    LOGGER(DEBUGGING, *zrtp::Utilities::hexdump("Shared key enc", sharedKeyEnc.data(), SNTRUP_CRYPTO_BYTES))

    crypto_kem_sntrup653_dec(sharedKeyDec.data(), cipherText.data(), secretKey.data());
    LOGGER(DEBUGGING, *zrtp::Utilities::hexdump("Shared key dec", sharedKeyDec.data(), SNTRUP_CRYPTO_BYTES))

    ASSERT_TRUE(sharedKeyDec.equals(sharedKeyEnc, SNTRUP_CRYPTO_BYTES));
}

TEST_F(ZrtpKemCryptoTestFixture, simpleExchange_953) {

    secUtilities::SecureArray<SNTRUP_CRYPTO_SECRETKEYBYTES_953> secretKey;
    secUtilities::SecureArray<SNTRUP_CRYPTO_PUBLICKEYBYTES_953> publicKey;
    secUtilities::SecureArray<SNTRUP_CRYPTO_CIPHERTEXTBYTES_953> cipherText;
    secUtilities::SecureArray<SNTRUP_CRYPTO_BYTES> sharedKeyEnc;
    secUtilities::SecureArray<SNTRUP_CRYPTO_BYTES> sharedKeyDec;

    crypto_kem_sntrup953_keypair(publicKey.data(), secretKey.data());

    crypto_kem_sntrup953_enc(cipherText.data(), sharedKeyEnc.data(), publicKey.data());
    LOGGER(DEBUGGING, *zrtp::Utilities::hexdump("Shared key enc", sharedKeyEnc.data(), SNTRUP_CRYPTO_BYTES))

    crypto_kem_sntrup953_dec(sharedKeyDec.data(), cipherText.data(), secretKey.data());
    LOGGER(DEBUGGING, *zrtp::Utilities::hexdump("Shared key dec", sharedKeyDec.data(), SNTRUP_CRYPTO_BYTES))

    ASSERT_TRUE(sharedKeyDec.equals(sharedKeyEnc, SNTRUP_CRYPTO_BYTES));
}

TEST_F(ZrtpKemCryptoTestFixture, simpleExchange_1277) {

    secUtilities::SecureArray<SNTRUP_CRYPTO_SECRETKEYBYTES_1277> secretKey;
    secUtilities::SecureArray<SNTRUP_CRYPTO_PUBLICKEYBYTES_1277> publicKey;
    secUtilities::SecureArray<SNTRUP_CRYPTO_CIPHERTEXTBYTES_1277> cipherText;
    secUtilities::SecureArray<SNTRUP_CRYPTO_BYTES> sharedKeyEnc;
    secUtilities::SecureArray<SNTRUP_CRYPTO_BYTES> sharedKeyDec;

    crypto_kem_sntrup1277_keypair(publicKey.data(), secretKey.data());

    crypto_kem_sntrup1277_enc(cipherText.data(), sharedKeyEnc.data(), publicKey.data());
    LOGGER(DEBUGGING, *zrtp::Utilities::hexdump("Shared key enc", sharedKeyEnc.data(), SNTRUP_CRYPTO_BYTES))

    crypto_kem_sntrup1277_dec(sharedKeyDec.data(), cipherText.data(), secretKey.data());
    LOGGER(DEBUGGING, *zrtp::Utilities::hexdump("Shared key dec", sharedKeyDec.data(), SNTRUP_CRYPTO_BYTES))

    ASSERT_TRUE(sharedKeyDec.equals(sharedKeyEnc, SNTRUP_CRYPTO_BYTES));
}

