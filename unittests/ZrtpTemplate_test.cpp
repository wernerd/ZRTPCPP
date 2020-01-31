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
#include "gmock/gmock.h"

using namespace std;

class ZrtpConfigureTestFixture: public ::testing::Test {
public:
    ZrtpConfigureTestFixture() = default;

    ZrtpConfigureTestFixture(const ZrtpConfigureTestFixture& other) = delete;
    ZrtpConfigureTestFixture(const ZrtpConfigureTestFixture&& other) = delete;
    ZrtpConfigureTestFixture& operator= (const ZrtpConfigureTestFixture& other) = delete;
    ZrtpConfigureTestFixture& operator= (const ZrtpConfigureTestFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(DEBUGGING);
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~ZrtpConfigureTestFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }
};
