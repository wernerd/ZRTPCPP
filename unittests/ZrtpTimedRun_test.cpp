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
#include <common/ZrtpTimeoutProvider.h>
#include "../logging/ZrtpLogging.h"
#include "ZrtpTestCommon.h"
#include "NetworkSimulation.h"

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
class ZrtpTimedRunFixture: public ::testing::Test {
public:
    ZrtpTimedRunFixture() = default;

    ZrtpTimedRunFixture(const ZrtpTimedRunFixture& other) = delete;
    ZrtpTimedRunFixture(const ZrtpTimedRunFixture&& other) = delete;
    ZrtpTimedRunFixture& operator= (const ZrtpTimedRunFixture& other) = delete;
    ZrtpTimedRunFixture& operator= (const ZrtpTimedRunFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(WARNING);
        aliceId = "Alice";
        bobId = "Bob";

        aliceNetwork = std::make_unique<zrtp::NetworkSimulation>(aliceTimoutProvider,
                [this](auto && PH1, auto && PH2) { bobQueueData(std::forward<decltype(PH1)>(PH1), std::forward<decltype(PH2)>(PH2)); });
        bobNetwork = std::make_unique<zrtp::NetworkSimulation>(bobTimoutProvider,
                [this](auto && PH1, auto && PH2) { aliceQueueData(std::forward<decltype(PH1)>(PH1), std::forward<decltype(PH2)>(PH2)); });
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

    ~ZrtpTimedRunFixture( ) override {
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

    void aliceQueueData(zrtp::ZrtpDataPairPtr dataPairPtr, int64_t tts) {
        auto* header = (zrtpPacketHeader_t *)dataPairPtr->first.get();
        string packetType((char *)header->messageType, sizeof(header->messageType));
        LOGGER(INFO, "From Bob:   ", packetType, " at: ", tts)

        unique_lock<mutex> queueLock(aliceQueueMutex);
        aliceQueue.push_back(move(dataPairPtr));
        queueLock.unlock();
        aliceQueueCv.notify_all();
    }

    static void aliceZrtpRun(ZrtpTimedRunFixture *thiz) {
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

                thiz->aliceZrtp->processZrtpMessage(zrtpData->first.get(), 123, zrtpData->second);

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

    void bobQueueData(zrtp::ZrtpDataPairPtr dataPairPtr, int64_t tts) {
        auto* header = (zrtpPacketHeader_t *)dataPairPtr->first.get();
        string packetType((char *)header->messageType, sizeof(header->messageType));
        LOGGER(INFO, "From Alice: ", packetType, " at: ", tts)

        unique_lock<mutex> queueLock(bobQueueMutex);
        bobQueue.push_back(move(dataPairPtr));
        queueLock.unlock();
        bobQueueCv.notify_all();
    }

    static void bobZrtpRun(ZrtpTimedRunFixture *thiz) {
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

                thiz->bobZrtp->processZrtpMessage(zrtpData->first.get(), 321, zrtpData->second);

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
    list<zrtp::ZrtpDataPairPtr> aliceQueue;
    zrtp::ZrtpTimeoutProvider aliceTimoutProvider;
    std::unique_ptr<zrtp::NetworkSimulation> aliceNetwork;

    shared_ptr<testing::NiceMock<MockZrtpCallback>> bobCb;
    unique_ptr<ZRtp> bobZrtp;
    thread bobThread;
    mutex bobStartMutex;
    condition_variable bobStartCv;
    mutex bobQueueMutex;
    condition_variable bobQueueCv;
    list<zrtp::ZrtpDataPairPtr> bobQueue;
    zrtp::ZrtpTimeoutProvider bobTimoutProvider;
    std::unique_ptr<zrtp::NetworkSimulation> bobNetwork;

    bool aliceThreadRun = false;
    bool bobThreadRun = false;

    int32_t aliceTimeoutId = 0;
    int32_t bobTimeoutId = 0;
};

TEST_F(ZrtpTimedRunFixture, full_run_test) {
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

    aliceNetwork->setNetworkDelay(100);
    bobNetwork->setNetworkDelay(100);

    // No timeout happens in this test: Start and cancel timer calls must match
    ON_CALL(*aliceCb, activateTimer).WillByDefault(DoAll(
            ([&aliceTimers, this](int32_t time) {
                aliceTimers++;
                aliceTimeoutId = aliceTimoutProvider.addTimer(time, 111, [&aliceTimers, this](int64_t d) {
                    aliceTimers--;
                    aliceZrtp->processTimeout();
                });
            }), Return(1)));
    ON_CALL(*aliceCb, cancelTimer).WillByDefault(DoAll(
            [&aliceTimers, this]() {
                aliceTimers--;
                aliceTimoutProvider.removeTimer(aliceTimeoutId);
            }, Return(1)));

    ON_CALL(*bobCb, activateTimer).WillByDefault(DoAll(
            ([&bobTimers, this](int32_t time) {
                bobTimers++;
                bobTimeoutId = bobTimoutProvider.addTimer(time, 222, [&bobTimers, this](int64_t d) {
                    bobTimers--;
                    bobZrtp->processTimeout();
                });
            }), Return(1)));
    ON_CALL(*bobCb, cancelTimer).WillByDefault(DoAll(
            [&bobTimers, this]() {
                bobTimers--;
                bobTimoutProvider.removeTimer(bobTimeoutId);
            }, Return(1)));

    // send data just forwards the data, no further checks yet.
    // When Alice sends data put the data into Bob's receive queue and signal 'data available'
    ON_CALL(*aliceCb, sendDataZRTP(_, _))
            .WillByDefault(DoAll(([this](const uint8_t* data, int32_t length) {
                auto tts = aliceNetwork->addDataToQueue(data, length);
                auto* header = (zrtpPacketHeader_t *)data;
                string packetType((char *)header->messageType, sizeof(header->messageType));
                LOGGER(INFO, "To Bob:     ", packetType, " at: ", tts, " - now: ", zrtp::Utilities::currentTimeMillis())
            }), Return(1)));

    // When Bob sends data put the data into Alice's receive queue and signal 'data available'
    ON_CALL(*bobCb, sendDataZRTP(_, _))
            .WillByDefault(DoAll(([this](const uint8_t* data, int32_t length) {
                auto tts = bobNetwork->addDataToQueue(data, length);
                auto* header = (zrtpPacketHeader_t *)data;
                string packetType((char *)header->messageType, sizeof(header->messageType));
                LOGGER(INFO, "To Alice:   ", packetType, " at: ", tts, " - now: ", zrtp::Utilities::currentTimeMillis())
            }), Return(1)));

    // We don't expect failures during the ZRTP protocol
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
//    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    bobStartThread();

    unique_lock<mutex> secure(securityOn);
    while (!(aliceSecureOn && bobSecureOn)) {
        securityOnCv.wait(secure);
    }
    // time to complete internal ZRTP security handling
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    aliceStopThread();
    bobStopThread();

    ASSERT_EQ(0, aliceTimers);
    ASSERT_EQ(0, bobTimers);

    ASSERT_EQ(aliceCipher, bobCipher);
    ASSERT_EQ(aliceSas, bobSas);
}