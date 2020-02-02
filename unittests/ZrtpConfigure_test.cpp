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

#include "gtest/gtest.h"
#include "../logging/ZrtpLogging.h"
#include "../zrtp/libzrtpcpp/ZrtpConfigure.h"

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

TEST_F(ZrtpConfigureTestFixture, Configure) {
    ZrtpConfigure config;

    auto e = zrtpHashes.getByName("S256");
    ASSERT_EQ(string("S256"), string(e.getName()));
    ASSERT_EQ(HashAlgorithm, e.getAlgoType());

    ASSERT_EQ((ZrtpConfigure::maxNoOfAlgos-1), config.addAlgo(HashAlgorithm, e));

    auto e1 = zrtpHashes.getByName("S384");

    // Add new algorithm at position 0, thus before existing algorithm
    ASSERT_EQ((ZrtpConfigure::maxNoOfAlgos-2), config.addAlgoAt(HashAlgorithm, e1, 0));

    auto e2 = config.getAlgoAt(HashAlgorithm, 0);
    ASSERT_EQ(string("S384"), string(e2.getName()));

    ASSERT_EQ(2, config.getNumConfiguredAlgos(HashAlgorithm));

    config.removeAlgo(HashAlgorithm, e2);
    e2 = config.getAlgoAt(HashAlgorithm, 0);
    ASSERT_EQ(string("S256"), string(e2.getName()));

    config.clear();

    // cleared the configuration data only, global data should still be OK, check it
    auto e3 = zrtpHashes.getByName("S256");
    ASSERT_EQ(string("S256"), string(e3.getName()));
    ASSERT_EQ(HashAlgorithm, e3.getAlgoType());
}