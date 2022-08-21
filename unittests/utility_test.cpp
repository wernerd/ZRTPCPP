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
// Created by werner on 31.01.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#include <cinttypes>
#include "../logging/ZrtpLogging.h"
#include "../common/Utilities.h"
#include "botan_all.h"

#include "gtest/gtest.h"

using namespace std;

class UtilityTestFixture: public ::testing::Test {
public:
    UtilityTestFixture() = default;

    UtilityTestFixture(const UtilityTestFixture& other) = delete;
    UtilityTestFixture(const UtilityTestFixture&& other) = delete;
    UtilityTestFixture& operator= (const UtilityTestFixture& other) = delete;
    UtilityTestFixture& operator= (const UtilityTestFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(DEBUGGING);
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~UtilityTestFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }
};

using namespace string_hash::literals;
static int32_t one() { return 1; }
static int32_t two() { return 2; }
static void other() {}

static int32_t foo( const std::string& value ) {
    switch( string_hash::hash(value) ) {
        case "one"_hash:
            return one();
        case "two"_hash:
            return two();
            /*many more cases*/
        default: other(); break;
    }
}

TEST_F(UtilityTestFixture, Switch) {
    ASSERT_EQ(1, foo("one"));
    ASSERT_EQ(2, foo("two"));
}

//BASE64("") = ""
//BASE64("f") = "Zg=="
//BASE64("fo") = "Zm8="
//BASE64("foo") = "Zm9v"
//BASE64("foob") = "Zm9vYg=="
//BASE64("fooba") = "Zm9vYmE="
//BASE64("foobar") = "Zm9vYmFy"

static uint8_t b64In0[] = "";
static uint8_t b64In1[] = "f";
static uint8_t b64In2[] = "fo";
static uint8_t b64In3[] = "foo";
static uint8_t b64In4[] = "foob";
static uint8_t b64In5[] = "fooba";
static uint8_t b64In6[] = "foobar";

TEST_F(UtilityTestFixture, Base64) {
    uint8_t b64decoded[100] = {};

    auto b64Out = Botan::base64_encode(b64In0, 0);
    ASSERT_EQ(0, b64Out.size());

    b64Out = Botan::base64_encode(b64In1, 1);
    ASSERT_EQ(4, b64Out.size());
    ASSERT_TRUE(b64Out == "Zg==");

    auto decodeLength = Botan::base64_decode(b64decoded, b64Out);
    ASSERT_EQ(1, decodeLength);
    ASSERT_TRUE(b64decoded[0] == 'f');

    b64Out = Botan::base64_encode(b64In2, 2);
    ASSERT_EQ(4, b64Out.size());
    ASSERT_TRUE(b64Out == "Zm8=");

    decodeLength = Botan::base64_decode(b64decoded, b64Out);
    ASSERT_EQ(2, decodeLength);
    ASSERT_EQ(0, memcmp(b64decoded, "fo", 2));

    b64Out = Botan::base64_encode(b64In3, 3);
    ASSERT_EQ(4, b64Out.size());
    ASSERT_TRUE(b64Out == "Zm9v");

    decodeLength = Botan::base64_decode(b64decoded, b64Out);
    ASSERT_EQ(3, decodeLength);
    ASSERT_EQ(0, memcmp(b64decoded, "foo", 3));

    b64Out = Botan::base64_encode(b64In4, 4);
    ASSERT_EQ(8, b64Out.size());
    ASSERT_TRUE(b64Out == "Zm9vYg==");

    decodeLength = Botan::base64_decode(b64decoded, b64Out);
    ASSERT_EQ(4, decodeLength);
    ASSERT_EQ(0, memcmp(b64decoded, "foob", 4));

    b64Out = Botan::base64_encode(b64In5, 5);
    ASSERT_EQ(8, b64Out.size());
    ASSERT_TRUE(b64Out == "Zm9vYmE=");

    decodeLength = Botan::base64_decode(b64decoded, b64Out);
    ASSERT_EQ(5, decodeLength);
    ASSERT_EQ(0, memcmp(b64decoded, "fooba", 5));

    b64Out = Botan::base64_encode(b64In6, 6);
    ASSERT_EQ(8, b64Out.size());
    ASSERT_TRUE(b64Out == "Zm9vYmFy");

    decodeLength = Botan::base64_decode(b64decoded, b64Out);
    ASSERT_EQ(6, decodeLength);
    ASSERT_EQ(0, memcmp(b64decoded, "foobar", 6));
}
//TEST_F(UtilityTestFixture, TimeTest) {
//
//    constexpr uint64_t ms = 1555521975329;
//    constexpr time_t sec = 1555522670;
//    const string expectedMs("2019-04-17T17:26:15.329Z");
//    const string expectedSec("2019-04-17T17:37:50Z");
//
//    auto fmtMs = zrtp::Utilities::getIsoTimeUtcMs(ms);
//    ASSERT_EQ(expectedMs, fmtMs);
//
//    auto fmtSec = zrtp::Utilities::getIsoTimeUtc(sec);
//    ASSERT_EQ(expectedSec, fmtSec);
//}

