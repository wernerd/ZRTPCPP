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

#include <zrtp/libzrtpcpp/ZrtpConfigure.h>
#include <zrtp/libzrtpcpp/ZRtp.h>
#include "../logging/ZrtpLogging.h"
#include "ZrtpTestCommon.h"

using namespace std;

using testing::_;
using testing::Ge;
using testing::Return;
using testing::SaveArg;
using testing::DoAll;

string aliceId;
string BobId;
uint8_t aliceZid[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
uint8_t bobZid[] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};

class ZrtpStartStopFixture: public ::testing::Test {
public:
    ZrtpStartStopFixture() = default;

    ZrtpStartStopFixture(const ZrtpStartStopFixture& other) = delete;
    ZrtpStartStopFixture(const ZrtpStartStopFixture&& other) = delete;
    ZrtpStartStopFixture& operator= (const ZrtpStartStopFixture& other) = delete;
    ZrtpStartStopFixture& operator= (const ZrtpStartStopFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(DEBUGGING);
        aliceId = "test zid 1";
        BobId = "test zid 2";
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~ZrtpStartStopFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
        aliceId.clear();
        BobId.clear();
    }
};

// No timeout happens in this test: Start and cancel timer call must be in sync
TEST_F(ZrtpStartStopFixture, check_timer_start_cancel) {
    // Configure with mandatory algorithms only
    shared_ptr<ZrtpConfigure> configure = make_shared<ZrtpConfigure>();

    shared_ptr<ZIDCache> aliceCache = std::make_shared<ZIDCacheEmpty>();
    aliceCache->setZid(aliceZid);
    configure->setZidCache(aliceCache);

    int32_t timers = 0;

    auto callback = std::make_shared<testing::NiceMock<MockZrtpCallback>>();

    ON_CALL(*callback, activateTimer).WillByDefault(DoAll(([&timers](int32_t time) { timers++; }), Return(1)));
    ON_CALL(*callback, cancelTimer).WillByDefault(DoAll([&timers]() { timers--; }, Return(1)));

    auto castedCallback = static_cast<shared_ptr<ZrtpCallback>>(callback);
    ZRtp zrtp(aliceId, castedCallback, configure);
    zrtp.startZrtpEngine();
    zrtp.stopZrtp();

    ASSERT_EQ(0, timers);
}
