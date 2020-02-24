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

