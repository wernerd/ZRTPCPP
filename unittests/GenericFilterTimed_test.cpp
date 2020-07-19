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

#include <thread>
#include <condition_variable>

#include <zrtp/libzrtpcpp/ZrtpConfigure.h>
#include <zrtp/libzrtpcpp/ZRtp.h>
#include <helpers/ZrtpConfigureBuilder.h>
#include "../logging/ZrtpLogging.h"
#include "../clients/genericClient/GenericPacketFilter.h"

#include "NetworkSimulation.h"
#include "gtest/gtest.h"

using namespace std;

string aliceId;
string bobId;
uint8_t aliceZid[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
uint8_t bobZid[] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};


// This fixture contains necessary functions and data to run two independent
// ZRtp instances in two threads. This setup allows to run these two instances
// and perform a 'send/receive' of ZRTP packet. Using the mock callbacks we
// can perform several tests during the data exchange, save some intermediate
// data and check them after the ZRTP protocol run completes.
class GenericTimedFixture: public ::testing::Test {
public:
    GenericTimedFixture() = default;

    GenericTimedFixture(const GenericTimedFixture& other) = delete;
    GenericTimedFixture(const GenericTimedFixture&& other) = delete;
    GenericTimedFixture& operator= (const GenericTimedFixture& other) = delete;
    GenericTimedFixture& operator= (const GenericTimedFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(ERROR_LOG);
        aliceId = "Alice";
        bobId = "Bob";

        aliceNetwork = std::make_unique<zrtp::NetworkSimulation>(
                aliceTimoutProvider,
                [this](zrtp::ZrtpDataPairPtr dataPtr, int64_t tts) { bobQueueData(move(dataPtr), tts); }
        );
        bobNetwork = std::make_unique<zrtp::NetworkSimulation>(
                bobTimoutProvider,
                [this](zrtp::ZrtpDataPairPtr dataPtr, int64_t tts) { aliceQueueData(move(dataPtr), tts); }
        );
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

        unlink("alice.data");
        unlink("bob.data");
    }

    ~GenericTimedFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }

    // region Alice functions
    void aliceSetup(std::shared_ptr<ZrtpConfigure>& configuration) {

        // Set configuration, flags, required callbacks
        aliceZrtp = GenericPacketFilter::createGenericFilter();
        aliceZrtp->setZrtpConfiguration(configuration)
                .processSrtp(true)
                .reportAllStates(true)
                .onDoSend([this](GenericPacketFilter::ProtocolData& data) -> bool {
                    // the static prepareToSend uses SecureArrayFlex to store packet data. ProtocolData.ptr is a void ptr, thus cast it
                    shared_ptr<secUtilities::SecureArrayFlex> packetPtr = static_pointer_cast<secUtilities::SecureArrayFlex>(data.ptr);
                    auto tts = aliceNetwork->addDataToQueue(packetPtr->data(), data.length);
                    LOGGER(DEBUGGING, "To Bob:    at: ", tts, " - now: ", zrtp::Utilities::currentTimeMillis())
                    return true;
                })
                .onStateReport([this]
                                       (GenericPacketFilter::ZrtpAppStates state, GenericPacketFilter::StateData & stateData) {
                    switch (state) {
                        case GenericPacketFilter::InfoOnly: {
                            LOGGER(INFO, "Alice Info: ", stateData.infoText)
                            break;
                        }
                        case GenericPacketFilter::Warning: {
                            LOGGER(INFO, "Alice Warning: ", stateData.infoText)
                            break;
                        }
                        case GenericPacketFilter::Error: {
                            LOGGER(ERROR_LOG, "Alice Error: ", stateData.infoText)
                            aliceErrorState.severity = stateData.severity;
                            aliceErrorState.subCode = stateData.subCode;
                            protocolFailure = true;
                            zrtpDoneCv.notify_all();
                            break;
                        }
                        case GenericPacketFilter::Discovery: {
                            LOGGER(INFO, "Alice Discovery: ", stateData.infoText)
                            break;
                        }
                        case GenericPacketFilter::KeyNegotiation: {
                            LOGGER(INFO, "Alice KeyNegotiation: ", stateData.infoText)
                            break;
                        }
                        case GenericPacketFilter::NoPeer: {
                            LOGGER(INFO, "Alice NoPeer: ", stateData.infoText)
                            break;
                        }
                        case GenericPacketFilter::Secure: {
                            aliceSas = aliceZrtp->computedSas();
                            aliceCipher = aliceZrtp->cipherInfo();

                            LOGGER(INFO, "Alice Secure: ", stateData.infoText, ", SAS: ", aliceZrtp->computedSas(), ", cipher: ", aliceZrtp->cipherInfo())
                            aliceSecureOn = true;
                            zrtpDoneCv.notify_all();
                            break;
                        }
                    }
                });
    }

    void aliceStartThread() {
        aliceThread = thread(aliceZrtpRun, this);
        aliceThreadRun = true;
        aliceStartCv.notify_all();
    }

    void aliceStopThread() {
        aliceThreadRun = false;
        aliceQueueCv.notify_all();
    }

    void aliceQueueData(zrtp::ZrtpDataPairPtr dataPairPtr, int64_t tts) {
        LOGGER(DEBUGGING, "From Bob   at: ", tts)

        unique_lock<mutex> queueLock(aliceQueueMutex);
        aliceQueue.push_back(move(dataPairPtr));
        queueLock.unlock();
        aliceQueueCv.notify_all();
    }

    static void aliceZrtpRun(GenericTimedFixture *thiz) {
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

                auto result = thiz->aliceZrtp->filterPacket(zrtpData->first.get(), zrtpData->second, GenericPacketFilter::checkRtpData);
                LOGGER(DEBUGGING, "Alice filter result: ", result)

                if (!thiz->aliceThreadRun) break;
                queueLock.lock();
            }
        }

        thiz->aliceZrtp.reset();
        LOGGER(DEBUGGING, "Alice thread terminating.")
    }
    // endregion

    // region Bob functions
    void bobSetup(std::shared_ptr<ZrtpConfigure>& configuration) {

        bobZrtp = GenericPacketFilter::createGenericFilter();
        bobZrtp->setZrtpConfiguration(configuration)
                .processSrtp(true)
                .reportAllStates(true)
                .onDoSend([this](GenericPacketFilter::ProtocolData& data) -> bool {
                    // the static prepareToSend uses SecureArrayFlex to store packet data. ProtocolData.ptr is a void ptr, thus cast it
                    shared_ptr<secUtilities::SecureArrayFlex> packetPtr = static_pointer_cast<secUtilities::SecureArrayFlex>(data.ptr);
                    auto tts = bobNetwork->addDataToQueue(packetPtr->data(), data.length);
                    LOGGER(DEBUGGING, "To Alice:  at: ", tts, " - now: ", zrtp::Utilities::currentTimeMillis())
                    return true;
                })
                .onStateReport([this]
                                       (GenericPacketFilter::ZrtpAppStates state, GenericPacketFilter::StateData & stateData) {
                    switch (state) {
                        case GenericPacketFilter::InfoOnly: {
                            LOGGER(INFO, "Bob   Info: ", stateData.infoText)
                            break;
                        }
                        case GenericPacketFilter::Warning: {
                            LOGGER(INFO, "Bob   Warning: ", stateData.infoText)
                            break;
                        }
                        case GenericPacketFilter::Error: {
                            LOGGER(ERROR_LOG, "Bob   Error: ", stateData.infoText)
                            bobErrorState.severity = stateData.severity;
                            bobErrorState.subCode = stateData.subCode;
                            protocolFailure = true;
                            zrtpDoneCv.notify_all();
                            break;
                        }
                        case GenericPacketFilter::Discovery: {
                            LOGGER(INFO, "Bob   Discovery: ", stateData.infoText)
                            break;
                        }
                        case GenericPacketFilter::KeyNegotiation: {
                            LOGGER(INFO, "Bob   KeyNegotiation: ", stateData.infoText)
                            break;
                        }
                        case GenericPacketFilter::NoPeer: {
                            LOGGER(INFO, "Bob   NoPeer: ", stateData.infoText)
                            break;
                        }
                        case GenericPacketFilter::Secure: {
                            bobSas = bobZrtp->computedSas();
                            bobCipher = bobZrtp->cipherInfo();

                            LOGGER(INFO, "Bob   Secure: ", stateData.infoText, ", SAS: ", bobZrtp->computedSas(), ", cipher: ", bobZrtp->cipherInfo())
                            bobSecureOn = true;
                            zrtpDoneCv.notify_all();
                            break;
                        }
                    }
                });
    }

    void bobStartThread() {
        bobThread = thread(bobZrtpRun, this);
        bobThreadRun = true;
        bobStartCv.notify_all();
    }

    void bobStopThread() {
        bobThreadRun = false;
        bobQueueCv.notify_all();
    }

    void bobQueueData(zrtp::ZrtpDataPairPtr dataPairPtr, int64_t tts) {
        LOGGER(DEBUGGING, "From Alice at: ", tts)

        unique_lock<mutex> queueLock(bobQueueMutex);
        bobQueue.push_back(move(dataPairPtr));
        queueLock.unlock();
        bobQueueCv.notify_all();
    }

    static void bobZrtpRun(GenericTimedFixture *thiz) {
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

                auto result = thiz->bobZrtp->filterPacket(zrtpData->first.get(), zrtpData->second, GenericPacketFilter::checkRtpData);
                LOGGER(DEBUGGING, "Bob   filter result: ", result)

                if (!thiz->bobThreadRun) break;
                queueLock.lock();
            }
        }

        thiz->bobZrtp.reset();
        LOGGER(DEBUGGING, "Bob thread terminating.")
    }
    // endregion
    mutex zrtpDoneMutex;
    condition_variable zrtpDoneCv;
    bool protocolFailure = false;

    GenericPacketFilter::GenericPacketFilterPtr aliceZrtp;
    thread aliceThread;
    mutex aliceStartMutex;
    condition_variable aliceStartCv;
    mutex aliceQueueMutex;
    condition_variable aliceQueueCv;
    list<zrtp::ZrtpDataPairPtr> aliceQueue;
    zrtp::ZrtpTimeoutProvider aliceTimoutProvider;
    std::unique_ptr<zrtp::NetworkSimulation> aliceNetwork;
    string aliceCipher;
    string aliceSas;
    GenericPacketFilter::StateData aliceErrorState {static_cast<GnuZrtpCodes::MessageSeverity>(0), 0, ""};
    bool aliceSecureOn = false;
    bool aliceThreadRun = false;
    bool aliceCacheIsOk = false;

    GenericPacketFilter::GenericPacketFilterPtr bobZrtp;
    thread bobThread;
    mutex bobStartMutex;
    condition_variable bobStartCv;
    mutex bobQueueMutex;
    condition_variable bobQueueCv;
    list<zrtp::ZrtpDataPairPtr> bobQueue;
    zrtp::ZrtpTimeoutProvider bobTimoutProvider;
    std::unique_ptr<zrtp::NetworkSimulation> bobNetwork;
    string bobCipher;
    string bobSas;
    GenericPacketFilter::StateData bobErrorState {static_cast<GnuZrtpCodes::MessageSeverity>(0), 0, ""};
    bool bobSecureOn = false;
    bool bobThreadRun = false;
    bool bobCacheIsOk = false;
};

TEST_F(GenericTimedFixture, full_run_test) {

    // Configure algorithms, ZID cache file
    auto aliceConfig = ZrtpConfigureBuilder::builder()
            .publicKeyAlgorithms(ec25, ec38)
            .cipherAlgorithms(aes3, two3)
            .initializeCache("alice.data", ZrtpConfigureBuilder::FileCache, aliceCacheIsOk)
            .build();

    aliceSetup(aliceConfig);

    auto bobConfig = ZrtpConfigureBuilder::builder()
            .publicKeyAlgorithms(ec25, ec38)
            .cipherAlgorithms(aes3, two3)
            .initializeCache("bob.data", ZrtpConfigureBuilder::FileCache, bobCacheIsOk)
            .build();
    bobSetup(bobConfig);

    aliceNetwork->setNetworkDelay(100);
    bobNetwork->setNetworkDelay(100);

    aliceStartThread();
    bobStartThread();

    unique_lock<mutex> secure(zrtpDoneMutex);
    while (!(aliceSecureOn && bobSecureOn) && !protocolFailure) {
        zrtpDoneCv.wait(secure);
    }
    // time to complete internal ZRTP security handling
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    aliceStopThread();
    bobStopThread();

    ASSERT_FALSE(protocolFailure);
    ASSERT_TRUE(aliceSecureOn);
    ASSERT_TRUE(bobSecureOn);
    ASSERT_EQ(aliceCipher, bobCipher);
    ASSERT_EQ(aliceSas, bobSas);
}