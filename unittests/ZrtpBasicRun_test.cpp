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
#include <thread>
#include <condition_variable>
#include "../logging/ZrtpLogging.h"
#include "ZrtpTestCommon.h"

using namespace std;

using testing::_;
using testing::Ge;
using testing::SaveArg;
using testing::DoAll;
using testing::Eq;

string aliceId;
string bobId;
uint8_t aliceZid[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
uint8_t bobZid[] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};


// This fixture contains necessary functions and data to run two independent
// ZRtp instances in two threads. This setup allows to run these two instances
// and perform a 'send/receive' of ZRTP packet. Using the mock callbacks we
// can perform several tests during the data exchange, save some intermediate
// data and check them after the ZRTP protocol run completes.
class ZrtpBasicRunFixture: public ::testing::Test {
public:
    ZrtpBasicRunFixture() = default;

    ZrtpBasicRunFixture(const ZrtpBasicRunFixture& other) = delete;
    ZrtpBasicRunFixture(const ZrtpBasicRunFixture&& other) = delete;
    ZrtpBasicRunFixture& operator= (const ZrtpBasicRunFixture& other) = delete;
    ZrtpBasicRunFixture& operator= (const ZrtpBasicRunFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(WARNING);
        aliceId = "Alice";
        bobId = "Bob";
    }

    void TearDown() override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
        aliceId.clear();
        bobId.clear();

        if (aliceThread.joinable()) aliceThread.join();
        aliceQueue.clear();

        if (bobThread.joinable()) bobThread.join();
        bobQueue.clear();
    }

    ~ZrtpBasicRunFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }

    // region Alice functions
    void aliceSetupThread(shared_ptr<ZrtpConfigure>& configure) {
        shared_ptr<ZrtpCallback> cb = aliceCb;      // perform implicit up-cast to base class
        aliceZrtp = make_unique<ZRtp>(aliceZid, cb, aliceId, configure, false, false);
        aliceZrtp->setTransportOverhead(0);     // Testing, no transport protocol (e.g RTP)
        aliceThread = thread(aliceZrtpRun, this);
    }

    void aliceStartThread() {
        aliceThreadRun = true;
        aliceStartCv.notify_all();
    }

    void aliceStopThread() {
        aliceThreadRun = false;
        aliceQueueCv.notify_all();
    }

    void aliceQueueData(uint8_t const * packetData, int32_t length) {
        auto* header = (zrtpPacketHeader_t *)packetData;
        string packetType((char *)header->messageType, sizeof(header->messageType));
        LOGGER(INFO, "Bob   --> ", packetType)

        auto data = std::make_unique<uint8_t[]>(length);
        memcpy(data.get(), packetData, length);
        pair<unique_ptr<uint8_t[]>, size_t> dataPair(move(data), length);

        unique_lock<mutex> queueLock(aliceQueueMutex);
        aliceQueue.push_back(move(dataPair));
        queueLock.unlock();
        aliceQueueCv.notify_all();
    }

    static void aliceZrtpRun(ZrtpBasicRunFixture *thiz) {
        {
            unique_lock<mutex> startLock(thiz->aliceStartMutex);
            while (!thiz->aliceThreadRun) {
                thiz->aliceStartCv.wait(startLock);
            }
            thiz->aliceZrtp->startZrtpEngine();
        }
        unique_lock<mutex> queueLock(thiz->aliceQueueMutex);
        while (thiz->aliceThreadRun) {
            while (thiz->aliceQueue.empty() && thiz->aliceThreadRun) {
                LOGGER(DEBUGGING, "Alice thread waiting: ", thiz->aliceThreadRun)
                thiz->aliceQueueCv.wait(queueLock);
            }
            if (!thiz->aliceThreadRun) break;

            for (; !thiz->aliceQueue.empty(); thiz->aliceQueue.pop_front()) {
               auto& zrtpData = thiz->aliceQueue.front();
               queueLock.unlock();          // unlock Alice's queue while processing 'received' data, Bob may add data

               thiz->aliceZrtp->processZrtpMessage(zrtpData.first.get(), 123, zrtpData.second);

               if (!thiz->aliceThreadRun) break;
               queueLock.lock();
            }
        }

        thiz->aliceZrtp->stopZrtp();
        LOGGER(DEBUGGING, "Alice thread terminating.")
    }
    // endregion

    // region Bob functions
    void bobSetupThread(shared_ptr<ZrtpConfigure>& configure) {
        shared_ptr<ZrtpCallback> cb = bobCb;      // perform implicit up-cast to base class
        bobZrtp = make_unique<ZRtp>(bobZid, cb, bobId, configure, false, false);
        bobZrtp->setTransportOverhead(0);        // Testing, no transport protocol (e.g RTP)
        bobThread = thread(bobZrtpRun, this);
    }

    void bobStartThread() {
        bobThreadRun = true;
        bobStartCv.notify_all();
    }

    void bobStopThread() {
        bobThreadRun = false;
        bobQueueCv.notify_all();
    }

    void bobQueueData(uint8_t const * packetData, int32_t length) {
        auto* header = (zrtpPacketHeader_t *)packetData;
        string packetType((char *)header->messageType, sizeof(header->messageType));
        LOGGER(INFO, "Alice --> ", packetType)

        auto data = std::make_unique<uint8_t[]>(length);
        memcpy(data.get(), packetData, length);
        pair<unique_ptr<uint8_t[]>, size_t> dataPair(move(data), length);

        unique_lock<mutex> queueLock(bobQueueMutex);
        bobQueue.push_back(move(dataPair));
        queueLock.unlock();
        bobQueueCv.notify_all();
    }

    static void bobZrtpRun(ZrtpBasicRunFixture *thiz) {
        LOGGER(DEBUGGING, "Bob thread id: ",  std::this_thread::get_id())
        {
            unique_lock<mutex> startLock(thiz->bobStartMutex);
            while (!thiz->bobThreadRun) {
                thiz->bobStartCv.wait(startLock);
            }
            thiz->bobZrtp->startZrtpEngine();
        }
        unique_lock<mutex> queueLock(thiz->bobQueueMutex);
        while (thiz->bobThreadRun) {
            while (thiz->bobQueue.empty() && thiz->bobThreadRun) {
                LOGGER(DEBUGGING, "Bob thread waiting: ", thiz->bobThreadRun)
                thiz->bobQueueCv.wait(queueLock);
            }
            if (!thiz->bobThreadRun) break;

            for (; !thiz->bobQueue.empty(); thiz->bobQueue.pop_front()) {
                auto& zrtpData = thiz->bobQueue.front();
                queueLock.unlock();          // unlock bob's queue while processing 'received' data, Bob may add data

                thiz->bobZrtp->processZrtpMessage(zrtpData.first.get(), 321, zrtpData.second);

                if (!thiz->bobThreadRun) break;
                queueLock.lock();
            }
        }

        thiz->bobZrtp->stopZrtp();
        LOGGER(DEBUGGING, "Bob thread terminating.")
    }
    // endregion
    mutex securityOn;
    condition_variable securityOnCv;

    shared_ptr<testing::NiceMock<MockZrtpCallback>> aliceCb;
    unique_ptr<ZRtp> aliceZrtp;
    thread aliceThread;
    mutex aliceStartMutex;
    condition_variable aliceStartCv;
    mutex aliceQueueMutex;
    condition_variable aliceQueueCv;
    list<pair<unique_ptr<uint8_t[]>, size_t>> aliceQueue;

    shared_ptr<testing::NiceMock<MockZrtpCallback>> bobCb;
    unique_ptr<ZRtp> bobZrtp;
    thread bobThread;
    mutex bobStartMutex;
    condition_variable bobStartCv;
    mutex bobQueueMutex;
    condition_variable bobQueueCv;
    list<pair<unique_ptr<uint8_t[]>, size_t>> bobQueue;

    bool aliceThreadRun = false;
    bool bobThreadRun = false;
};


// Simple test to start and stop execution threads, make sure we don't have dangling locks
// after the simple start/stop
TEST_F(ZrtpBasicRunFixture, alice_check_thread_start_stop) {
    // Configure with mandatory algorithms only
    shared_ptr<ZrtpConfigure> configure = make_shared<ZrtpConfigure>();

    aliceCb = make_shared<testing::NiceMock<MockZrtpCallback>>();
    bobCb = make_shared<testing::NiceMock<MockZrtpCallback>>();

    int32_t syncs = 0;

    ON_CALL(*aliceCb, synchEnter).WillByDefault([&syncs]() { syncs++; });
    ON_CALL(*aliceCb, synchLeave).WillByDefault([&syncs]() { syncs--; });

    aliceSetupThread(configure);
    aliceStartThread();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));  // time to settle thread before stopping it
    aliceStopThread();

    ASSERT_EQ(0, syncs);
}

TEST_F(ZrtpBasicRunFixture, bob_check_thread_start_stop) {
    // Configure with mandatory algorithms only
    shared_ptr<ZrtpConfigure> configure = make_shared<ZrtpConfigure>();

    aliceCb = make_shared<testing::NiceMock<MockZrtpCallback>>();
    bobCb = make_shared<testing::NiceMock<MockZrtpCallback>>();

    int32_t syncs = 0;

    ON_CALL(*bobCb, synchEnter).WillByDefault([&syncs]() { syncs++; });
    ON_CALL(*bobCb, synchLeave).WillByDefault([&syncs]() { syncs--; });

    bobSetupThread(configure);
    bobStartThread();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));  // time to settle thread before stopping it
    bobStopThread();

    ASSERT_EQ(0, syncs);
}

TEST_F(ZrtpBasicRunFixture, full_run_test) {
    // Configure with mandatory algorithms only
    auto aliceConfigure = make_shared<ZrtpConfigure>();
    auto bobConfigure = make_shared<ZrtpConfigure>();

    shared_ptr<ZIDCache> aliceCache = std::make_shared<ZIDCacheEmpty>();
    aliceCache->setZid(aliceZid);
    aliceConfigure->setZidCache(aliceCache);

    shared_ptr<ZIDCache>  bobCache = std::make_shared<ZIDCacheEmpty>();
    bobCache->setZid(bobZid);
    bobConfigure->setZidCache(bobCache);

    aliceCb = make_shared<testing::NiceMock<MockZrtpCallback>>();
    bobCb = make_shared<testing::NiceMock<MockZrtpCallback>>();

    int32_t aliceTimers = 0;
    int32_t bobTimers = 0;

    bool failure = false;

    // No timeout happens in this test: Start and cancel timer calls must match
    ON_CALL(*aliceCb, activateTimer).WillByDefault(DoAll(([&aliceTimers](int32_t time) { aliceTimers++; }), Return(1)));
    ON_CALL(*aliceCb, cancelTimer).WillByDefault(DoAll([&aliceTimers]() { aliceTimers--; }, Return(1)));
    ON_CALL(*bobCb, activateTimer).WillByDefault(DoAll(([&bobTimers](int32_t time) { bobTimers++; }), Return(1)));
    ON_CALL(*bobCb, cancelTimer).WillByDefault(DoAll([&bobTimers]() { bobTimers--; }, Return(1)));

    // send data just forwards the data, no further checks yet.
    // When Alice sends data put the data into Bob's receive queue and signal 'data available'
    ON_CALL(*aliceCb, sendDataZRTP(_, _))
            .WillByDefault(DoAll(([this](const uint8_t* data, int32_t length) { bobQueueData(data, length); }), Return(1)));

    // When Bob sends data put the data into Alice's receive queue and signal 'data available'
    ON_CALL(*bobCb, sendDataZRTP(_, _))
            .WillByDefault(DoAll(([this](const uint8_t* data, int32_t length) { aliceQueueData(data, length); }), Return(1)));

    ON_CALL(*aliceCb, sendInfo)
            .WillByDefault([](GnuZrtpCodes::MessageSeverity severity, int32_t subCode) { LOGGER(DEBUGGING, "SendInfo Alice: ", severity, ", code: ", subCode) });

    ON_CALL(*bobCb, sendInfo)
            .WillByDefault([](GnuZrtpCodes::MessageSeverity severity, int32_t subCode) { LOGGER(DEBUGGING, "SendInfo Bob  : ", severity, ", code: ", subCode) });

    // We don't expect failures during the ZRTP protocol
    ON_CALL(*aliceCb, zrtpNegotiationFailed)
            .WillByDefault([&failure, this](GnuZrtpCodes::MessageSeverity severity, int32_t subCode) {
                LOGGER(ERROR_LOG, "zrtpNegotiationFailed Alice: ", severity, ", code: ", subCode)
                failure = true;
                this->securityOnCv.notify_all();
            });

    ON_CALL(*bobCb, zrtpNegotiationFailed)
            .WillByDefault([&failure, this](GnuZrtpCodes::MessageSeverity severity, int32_t subCode) {
                LOGGER(ERROR_LOG, "zrtpNegotiationFailed Bob  : ", severity, ", code: ", subCode)
                failure = true;
                this->securityOnCv.notify_all();
            });

    ON_CALL(*aliceCb, zrtpNotSuppOther)
            .WillByDefault([&failure, this]() { failure = true; this->securityOnCv.notify_all(); });

    ON_CALL(*bobCb, zrtpNotSuppOther)
            .WillByDefault([&failure, this]() { failure = true; this->securityOnCv.notify_all(); });

    EXPECT_CALL(*aliceCb, zrtpNegotiationFailed(_, _)).Times(0);
    EXPECT_CALL(*bobCb, zrtpNegotiationFailed(_, _)).Times(0);

    EXPECT_CALL(*aliceCb, zrtpNotSuppOther).Times(0);
    EXPECT_CALL(*bobCb, zrtpNotSuppOther).Times(0);

    string aliceCipher;
    string aliceSas;
    string bobCipher;
    string bobSas;

    bool aliceSecureOn = false;
    bool bobSecureOn = false;

    // These calls must happen in the given sequence during the ZRTP protocol run
    {
        testing::InSequence aliceSequence;

        // Expect the srtpSecretsReady two times: one call sets up the Initiator, the other the Responder
        // i.e. the two send/receive endpoints. Each endpoint has its own set of SRTP secrets.
        EXPECT_CALL(*aliceCb, srtpSecretsReady(_, _)).Times(2).WillRepeatedly(Return(true));

        // Once all secrets set and the two endpoints are active report the ciphers and the
        // SAS. One call only.
        EXPECT_CALL(*aliceCb, srtpSecretsOn(_, _, Eq(false)))
                .WillOnce([this, &aliceCipher, &aliceSas, &aliceSecureOn](string c, string s, bool v) {
                    aliceCipher = move(c);
                    aliceSas = move(s);
                    aliceSecureOn = true;
                    this->securityOnCv.notify_all();
                    LOGGER(INFO, "Alice cipher: ", aliceCipher, ", SAS: ", aliceSas)
                });

        // Terminating the ZRTP session calls the srtpSecretsOff two times: for Initiator and for Responder.
        EXPECT_CALL(*aliceCb, srtpSecretsOff(_)).Times(2);
    }

    {
        testing::InSequence bobSequence;

        EXPECT_CALL(*bobCb, srtpSecretsReady(_, _)).Times(2).WillRepeatedly(Return(true));

        EXPECT_CALL(*bobCb, srtpSecretsOn(_, _, Eq(false)))
                .WillOnce([this, &bobCipher, &bobSas, &bobSecureOn](string c, string s, bool v) {
                    bobCipher = move(c);
                    bobSas = move(s);
                    bobSecureOn = true;
                    this->securityOnCv.notify_all();
                    LOGGER(INFO, "  Bob cipher: ", bobCipher, ", SAS: ", bobSas)
                });

        EXPECT_CALL(*bobCb, srtpSecretsOff(_)).Times(2);
    }

    aliceSetupThread(aliceConfigure);
    bobSetupThread(bobConfigure);

    aliceStartThread();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    bobStartThread();

    unique_lock<mutex> secure(securityOn);
    while (!failure && !(aliceSecureOn && bobSecureOn)) {
        securityOnCv.wait(secure);
    }
    // time to complete internal ZRTP security handling before stopping
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    aliceStopThread();
    bobStopThread();

    ASSERT_EQ(0, aliceTimers);
    ASSERT_EQ(0, bobTimers);

    ASSERT_EQ(aliceCipher, bobCipher);
    ASSERT_EQ(aliceSas, bobSas);
}

TEST_F(ZrtpBasicRunFixture, full_run_test_sidh503) {
    // Configure with mandatory algorithms only
    auto aliceConfigure = make_shared<ZrtpConfigure>();
    auto bobConfigure = make_shared<ZrtpConfigure>();

    aliceConfigure->clear();
    bobConfigure->clear();
    aliceConfigure->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("SDH5"));
    bobConfigure->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("SDH5"));


    aliceConfigure->addAlgo(HashAlgorithm, zrtpHashes.getByName("S384"));
    aliceConfigure->addAlgo(HashAlgorithm, zrtpHashes.getByName("SKN3"));
    aliceConfigure->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("AES3"));
    aliceConfigure->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("2FS3"));

    bobConfigure->addAlgo(HashAlgorithm, zrtpHashes.getByName("S384"));
    bobConfigure->addAlgo(HashAlgorithm, zrtpHashes.getByName("SKN3"));
    bobConfigure->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("AES3"));
    bobConfigure->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("2FS3"));

    shared_ptr<ZIDCache> aliceCache = std::make_shared<ZIDCacheEmpty>();
    aliceCache->setZid(aliceZid);
    aliceConfigure->setZidCache(aliceCache);

    shared_ptr<ZIDCache>  bobCache = std::make_shared<ZIDCacheEmpty>();
    bobCache->setZid(bobZid);
    bobConfigure->setZidCache(bobCache);

    aliceCb = make_shared<testing::NiceMock<MockZrtpCallback>>();
    bobCb = make_shared<testing::NiceMock<MockZrtpCallback>>();

    int32_t aliceTimers = 0;
    int32_t bobTimers = 0;

    bool failure = false;

    // No timeout happens in this test: Start and cancel timer calls must match
    ON_CALL(*aliceCb, activateTimer).WillByDefault(DoAll(([&aliceTimers](int32_t time) { aliceTimers++; }), Return(1)));
    ON_CALL(*aliceCb, cancelTimer).WillByDefault(DoAll([&aliceTimers]() { aliceTimers--; }, Return(1)));
    ON_CALL(*bobCb, activateTimer).WillByDefault(DoAll(([&bobTimers](int32_t time) { bobTimers++; }), Return(1)));
    ON_CALL(*bobCb, cancelTimer).WillByDefault(DoAll([&bobTimers]() { bobTimers--; }, Return(1)));

    // send data just forwards the data, no further checks yet.
    // When Alice sends data put the data into Bob's receive queue and signal 'data available'
    ON_CALL(*aliceCb, sendDataZRTP(_, _))
            .WillByDefault(DoAll(([this](const uint8_t* data, int32_t length) { bobQueueData(data, length); }), Return(1)));

    // When Bob sends data put the data into Alice's receive queue and signal 'data available'
    ON_CALL(*bobCb, sendDataZRTP(_, _))
            .WillByDefault(DoAll(([this](const uint8_t* data, int32_t length) { aliceQueueData(data, length); }), Return(1)));

    ON_CALL(*aliceCb, sendInfo)
            .WillByDefault([](GnuZrtpCodes::MessageSeverity severity, int32_t subCode) { LOGGER(DEBUGGING, "SendInfo Alice: ", severity, ", code: ", subCode) });

    ON_CALL(*bobCb, sendInfo)
            .WillByDefault([](GnuZrtpCodes::MessageSeverity severity, int32_t subCode) { LOGGER(DEBUGGING, "SendInfo Bob  : ", severity, ", code: ", subCode) });

    // We don't expect failures during the ZRTP protocol
    ON_CALL(*aliceCb, zrtpNegotiationFailed)
            .WillByDefault([&failure, this](GnuZrtpCodes::MessageSeverity severity, int32_t subCode) {
                LOGGER(ERROR_LOG, "zrtpNegotiationFailed Alice: ", severity, ", code: ", subCode)
                failure = true;
                this->securityOnCv.notify_all();
            });

    ON_CALL(*bobCb, zrtpNegotiationFailed)
            .WillByDefault([&failure, this](GnuZrtpCodes::MessageSeverity severity, int32_t subCode) {
                LOGGER(ERROR_LOG, "zrtpNegotiationFailed Bob  : ", severity, ", code: ", subCode)
                failure = true;
                this->securityOnCv.notify_all();
            });

    ON_CALL(*aliceCb, zrtpNotSuppOther)
            .WillByDefault([&failure, this]() { failure = true; this->securityOnCv.notify_all(); });

    ON_CALL(*bobCb, zrtpNotSuppOther)
            .WillByDefault([&failure, this]() { failure = true; this->securityOnCv.notify_all(); });

    EXPECT_CALL(*aliceCb, zrtpNegotiationFailed(_, _)).Times(0);
    EXPECT_CALL(*bobCb, zrtpNegotiationFailed(_, _)).Times(0);

    EXPECT_CALL(*aliceCb, zrtpNotSuppOther).Times(0);
    EXPECT_CALL(*bobCb, zrtpNotSuppOther).Times(0);

    string aliceCipher;
    string aliceSas;
    string bobCipher;
    string bobSas;

    bool aliceSecureOn = false;
    bool bobSecureOn = false;

    // These calls must happen in the given sequence during the ZRTP protocol run
    {
        testing::InSequence aliceSequence;

        // Expect the srtpSecretsReady two times: one call sets up the Initiator, the other the Responder
        // i.e. the two send/receive endpoints. Each endpoint has its own set of SRTP secrets.
        EXPECT_CALL(*aliceCb, srtpSecretsReady(_, _)).Times(2).WillRepeatedly(Return(true));

        // Once all secrets set and the two endpoints are active report the ciphers and the
        // SAS. One call only.
        EXPECT_CALL(*aliceCb, srtpSecretsOn(_, _, Eq(false)))
                .WillOnce([this, &aliceCipher, &aliceSas, &aliceSecureOn](string c, string s, bool v) {
                    aliceCipher = move(c);
                    aliceSas = move(s);
                    aliceSecureOn = true;
                    this->securityOnCv.notify_all();
                    LOGGER(INFO, "Alice cipher: ", aliceCipher, ", SAS: ", aliceSas)
                });

        // Terminating the ZRTP session calls the srtpSecretsOff two times: for Initiator and for Responder.
        EXPECT_CALL(*aliceCb, srtpSecretsOff(_)).Times(2);
    }

    {
        testing::InSequence bobSequence;

        EXPECT_CALL(*bobCb, srtpSecretsReady(_, _)).Times(2).WillRepeatedly(Return(true));

        EXPECT_CALL(*bobCb, srtpSecretsOn(_, _, Eq(false)))
                .WillOnce([this, &bobCipher, &bobSas, &bobSecureOn](string c, string s, bool v) {
                    bobCipher = move(c);
                    bobSas = move(s);
                    bobSecureOn = true;
                    this->securityOnCv.notify_all();
                    LOGGER(INFO, "  Bob cipher: ", bobCipher, ", SAS: ", bobSas)
                });

        EXPECT_CALL(*bobCb, srtpSecretsOff(_)).Times(2);
    }

    aliceSetupThread(aliceConfigure);
    bobSetupThread(bobConfigure);

    aliceStartThread();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    bobStartThread();

    unique_lock<mutex> secure(securityOn);
    while (!failure && !(aliceSecureOn && bobSecureOn)) {
        securityOnCv.wait(secure);
    }
    // time to complete internal ZRTP security handling before stopping
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    aliceStopThread();
    bobStopThread();

    ASSERT_EQ(0, aliceTimers);
    ASSERT_EQ(0, bobTimers);

    ASSERT_EQ(aliceCipher, bobCipher);
    ASSERT_EQ(aliceSas, bobSas);
}

TEST_F(ZrtpBasicRunFixture, full_run_test_sidh751) {
    // Configure with mandatory algorithms only
    auto aliceConfigure = make_shared<ZrtpConfigure>();
    auto bobConfigure = make_shared<ZrtpConfigure>();

    aliceConfigure->clear();
    bobConfigure->clear();
    aliceConfigure->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("SDH7"));
    bobConfigure->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("SDH7"));


    aliceConfigure->addAlgo(HashAlgorithm, zrtpHashes.getByName("S384"));
    aliceConfigure->addAlgo(HashAlgorithm, zrtpHashes.getByName("SKN3"));
    aliceConfigure->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("AES3"));
    aliceConfigure->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("2FS3"));

    bobConfigure->addAlgo(HashAlgorithm, zrtpHashes.getByName("S384"));
    bobConfigure->addAlgo(HashAlgorithm, zrtpHashes.getByName("SKN3"));
    bobConfigure->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("AES3"));
    bobConfigure->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("2FS3"));

    shared_ptr<ZIDCache> aliceCache = std::make_shared<ZIDCacheEmpty>();
    aliceCache->setZid(aliceZid);
    aliceConfigure->setZidCache(aliceCache);

    shared_ptr<ZIDCache>  bobCache = std::make_shared<ZIDCacheEmpty>();
    bobCache->setZid(bobZid);
    bobConfigure->setZidCache(bobCache);

    aliceCb = make_shared<testing::NiceMock<MockZrtpCallback>>();
    bobCb = make_shared<testing::NiceMock<MockZrtpCallback>>();

    int32_t aliceTimers = 0;
    int32_t bobTimers = 0;

    bool failure = false;

    // No timeout happens in this test: Start and cancel timer calls must match
    ON_CALL(*aliceCb, activateTimer).WillByDefault(DoAll(([&aliceTimers](int32_t time) { aliceTimers++; }), Return(1)));
    ON_CALL(*aliceCb, cancelTimer).WillByDefault(DoAll([&aliceTimers]() { aliceTimers--; }, Return(1)));
    ON_CALL(*bobCb, activateTimer).WillByDefault(DoAll(([&bobTimers](int32_t time) { bobTimers++; }), Return(1)));
    ON_CALL(*bobCb, cancelTimer).WillByDefault(DoAll([&bobTimers]() { bobTimers--; }, Return(1)));

    // send data just forwards the data, no further checks yet.
    // When Alice sends data put the data into Bob's receive queue and signal 'data available'
    ON_CALL(*aliceCb, sendDataZRTP(_, _))
            .WillByDefault(DoAll(([this](const uint8_t* data, int32_t length) { bobQueueData(data, length); }), Return(1)));

    // When Bob sends data put the data into Alice's receive queue and signal 'data available'
    ON_CALL(*bobCb, sendDataZRTP(_, _))
            .WillByDefault(DoAll(([this](const uint8_t* data, int32_t length) { aliceQueueData(data, length); }), Return(1)));

    ON_CALL(*aliceCb, sendInfo)
            .WillByDefault([](GnuZrtpCodes::MessageSeverity severity, int32_t subCode) { LOGGER(DEBUGGING, "SendInfo Alice: ", severity, ", code: ", subCode) });

    ON_CALL(*bobCb, sendInfo)
            .WillByDefault([](GnuZrtpCodes::MessageSeverity severity, int32_t subCode) { LOGGER(DEBUGGING, "SendInfo Bob  : ", severity, ", code: ", subCode) });

    // We don't expect failures during the ZRTP protocol
    ON_CALL(*aliceCb, zrtpNegotiationFailed)
            .WillByDefault([&failure, this](GnuZrtpCodes::MessageSeverity severity, int32_t subCode) {
                LOGGER(ERROR_LOG, "zrtpNegotiationFailed Alice: ", severity, ", code: ", subCode)
                failure = true;
                this->securityOnCv.notify_all();
            });

    ON_CALL(*bobCb, zrtpNegotiationFailed)
            .WillByDefault([&failure, this](GnuZrtpCodes::MessageSeverity severity, int32_t subCode) {
                LOGGER(ERROR_LOG, "zrtpNegotiationFailed Bob  : ", severity, ", code: ", subCode)
                failure = true;
                this->securityOnCv.notify_all();
            });

    ON_CALL(*aliceCb, zrtpNotSuppOther)
            .WillByDefault([&failure, this]() { failure = true; this->securityOnCv.notify_all(); });

    ON_CALL(*bobCb, zrtpNotSuppOther)
            .WillByDefault([&failure, this]() { failure = true; this->securityOnCv.notify_all(); });

    EXPECT_CALL(*aliceCb, zrtpNegotiationFailed(_, _)).Times(0);
    EXPECT_CALL(*bobCb, zrtpNegotiationFailed(_, _)).Times(0);

    EXPECT_CALL(*aliceCb, zrtpNotSuppOther).Times(0);
    EXPECT_CALL(*bobCb, zrtpNotSuppOther).Times(0);

    string aliceCipher;
    string aliceSas;
    string bobCipher;
    string bobSas;

    bool aliceSecureOn = false;
    bool bobSecureOn = false;

    // These calls must happen in the given sequence during the ZRTP protocol run
    {
        testing::InSequence aliceSequence;

        // Expect the srtpSecretsReady two times: one call sets up the Initiator, the other the Responder
        // i.e. the two send/receive endpoints. Each endpoint has its own set of SRTP secrets.
        EXPECT_CALL(*aliceCb, srtpSecretsReady(_, _)).Times(2).WillRepeatedly(Return(true));

        // Once all secrets set and the two endpoints are active report the ciphers and the
        // SAS. One call only.
        EXPECT_CALL(*aliceCb, srtpSecretsOn(_, _, Eq(false)))
                .WillOnce([this, &aliceCipher, &aliceSas, &aliceSecureOn](string c, string s, bool v) {
                    aliceCipher = move(c);
                    aliceSas = move(s);
                    aliceSecureOn = true;
                    this->securityOnCv.notify_all();
                    LOGGER(INFO, "Alice cipher: ", aliceCipher, ", SAS: ", aliceSas)
                });

        // Terminating the ZRTP session calls the srtpSecretsOff two times: for Initiator and for Responder.
        EXPECT_CALL(*aliceCb, srtpSecretsOff(_)).Times(2);
    }

    {
        testing::InSequence bobSequence;

        EXPECT_CALL(*bobCb, srtpSecretsReady(_, _)).Times(2).WillRepeatedly(Return(true));

        EXPECT_CALL(*bobCb, srtpSecretsOn(_, _, Eq(false)))
                .WillOnce([this, &bobCipher, &bobSas, &bobSecureOn](string c, string s, bool v) {
                    bobCipher = move(c);
                    bobSas = move(s);
                    bobSecureOn = true;
                    this->securityOnCv.notify_all();
                    LOGGER(INFO, "  Bob cipher: ", bobCipher, ", SAS: ", bobSas)
                });

        EXPECT_CALL(*bobCb, srtpSecretsOff(_)).Times(2);
    }

    aliceSetupThread(aliceConfigure);
    bobSetupThread(bobConfigure);

    aliceStartThread();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    bobStartThread();

    unique_lock<mutex> secure(securityOn);
    while (!failure && !(aliceSecureOn && bobSecureOn)) {
        securityOnCv.wait(secure);
    }
    // time to complete internal ZRTP security handling before stopping
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    aliceStopThread();
    bobStopThread();

    ASSERT_EQ(0, aliceTimers);
    ASSERT_EQ(0, bobTimers);

    ASSERT_EQ(aliceCipher, bobCipher);
    ASSERT_EQ(aliceSas, bobSas);
}
