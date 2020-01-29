//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Created by werner on 28.01.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#include <zrtp/libzrtpcpp/ZrtpConfigure.h>
#include <zrtp/libzrtpcpp/ZRtp.h>
#include "../logging/ZrtpLogging.h"
#include "gmock/gmock.h"

using namespace std;

using testing::_;
using testing::Ge;
using testing::Return;
using testing::SaveArg;
using testing::DoAll;

string myId_1;
string myId_2;
uint8_t myZid_1[] = {1,2,3,4,5,6,7,8,9,10,11,12};
uint8_t myZid_2[] = {2,3,4,5,6,7,8,9,10,11,12,13};

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
        myId_1 = "test zid 1";
        myId_2 = "test zid 2";
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~ZrtpStartStopFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
        myId_1.clear();
        myId_2.clear();
    }
};

class MockCallback : public ZrtpCallback {
public:
    MOCK_METHOD(int32_t, sendDataZRTP, (const uint8_t* data, int32_t length), (override));
    MOCK_METHOD(int32_t, activateTimer, (int32_t time), (override));
    MOCK_METHOD(int32_t, cancelTimer, (), (override));
    MOCK_METHOD(void, sendInfo, (GnuZrtpCodes::MessageSeverity severity, int32_t subCode), (override));
    MOCK_METHOD(bool, srtpSecretsReady, (SrtpSecret_t* secrets, EnableSecurity part), (override));
    MOCK_METHOD(void, srtpSecretsOff, (EnableSecurity part), (override));
    MOCK_METHOD(void, srtpSecretsOn, (std::string c, std::string s, bool verified), (override));
    MOCK_METHOD(void, handleGoClear, (), (override));
    MOCK_METHOD(void, zrtpNegotiationFailed, (GnuZrtpCodes::MessageSeverity severity, int32_t subCode), (override));
    MOCK_METHOD(void, zrtpNotSuppOther, (), (override));
    MOCK_METHOD(void, synchEnter, (), (override));
    MOCK_METHOD(void, synchLeave, (), (override));
    MOCK_METHOD(void, zrtpAskEnrollment, (GnuZrtpCodes::InfoEnrollment info), (override));
    MOCK_METHOD(void, zrtpInformEnrollment, (GnuZrtpCodes::InfoEnrollment info), (override));
    MOCK_METHOD(void, signSAS, (uint8_t* sasHash), (override));
    MOCK_METHOD(bool, checkSASSignature, (uint8_t* sasHash), (override));

    // Setup defaults with appropriate return values, overwrite in tests as required
    MockCallback() {
        ON_CALL(*this, sendDataZRTP).WillByDefault(Return(1));

        ON_CALL(*this, activateTimer).WillByDefault(Return(1));
        ON_CALL(*this, cancelTimer).WillByDefault(Return(1));

        ON_CALL(*this, srtpSecretsReady).WillByDefault(Return(true));
        ON_CALL(*this, checkSASSignature).WillByDefault(Return(true));
    }
};

// Check to make sure we don't have dangling locks during simple start/stop
// SynchEnter and SynchLeave call must match.
TEST_F(ZrtpStartStopFixture, check_synch_enter_leave) {
    // Configure with mandatory algorithms only
    shared_ptr<ZrtpConfigure> configure = make_shared<ZrtpConfigure>();

    int32_t syncs = 0;

    testing::NiceMock<MockCallback> callback;

    ON_CALL(callback, synchEnter).WillByDefault([&syncs]() { syncs++; });
    ON_CALL(callback, synchLeave).WillByDefault([&syncs]() { syncs--; });

    ZRtp zrtp(myZid_1, callback, myId_1, configure, false, false);
    zrtp.startZrtpEngine();
    zrtp.stopZrtp();

    ASSERT_EQ(0, syncs);
}

// No timeout happens in this test: Start and cancel timer call must be in sync
TEST_F(ZrtpStartStopFixture, check_timer_start_cancel) {
    // Configure with mandatory algorithms only
    shared_ptr<ZrtpConfigure> configure = make_shared<ZrtpConfigure>();

    int32_t timers = 0;

    testing::NiceMock<MockCallback> callback;

    ON_CALL(callback, activateTimer).WillByDefault(DoAll(([&timers](int32_t time) { timers++; }), Return(1)));
    ON_CALL(callback, cancelTimer).WillByDefault(DoAll([&timers]() { timers--; }, Return(1)));

    ZRtp zrtp(myZid_1, callback, myId_1, configure, false, false);
    zrtp.startZrtpEngine();
    zrtp.stopZrtp();

    ASSERT_EQ(0, timers);
}
