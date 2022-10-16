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
// Created by werner on 02.02.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#ifndef LIBZRTPCPP_NETWORKSIMULATION_H
#define LIBZRTPCPP_NETWORKSIMULATION_H

#include "../common/ZrtpTimeoutProvider.h"

namespace zrtp {

    using ZrtpDataPair = std::pair<std::unique_ptr<uint8_t[]>, size_t>;
    using ZrtpDataPairPtr = std::unique_ptr<std::pair<std::unique_ptr<uint8_t[]>, size_t>>;
    using TimedZrtpData = std::pair<int64_t, ZrtpDataPairPtr>;

    using TimedZrtpDataPair = std::unique_ptr<std::pair<int64_t, ZrtpDataPairPtr> >;

    class NetworkSimulation {

    public:

        explicit NetworkSimulation(ZrtpTimeoutProvider & provider, std::function<void(ZrtpDataPairPtr, int64_t)> recvFunc ) :
                timeoutProvider(provider), receiveFunction(std::move(recvFunc))
        {}

        /**
         * @brief Queue the data and send it at a later time to receiver.
         *
         * If the requested network delay is 0 then the functions sends the data immediately
         * and returns.
         *
         * If the network delay is > 0 the function computes the time to send the data as follows:
         *
         *      timeToSend = currentTimeInMs + networkDelay
         *
         * Example:
         *  - network delay is 200ms
         *  - sender sends data every 10ms
         *  The receiver gets the first packet 200ms after sending, the next packet
         *  after 210ms, next after 220ms and so on.
         *
         * @param packetData
         * @param length
         * @return Time to send the data (absolute time since epoch in ms)
         */
        int64_t addDataToQueue(uint8_t const * packetData, int32_t length) {

            auto data = std::make_unique<uint8_t[]>(length);
            memcpy(data.get(), packetData, length);

            auto rawDataPtr = std::make_unique<ZrtpDataPair>(std::move(data), length);

            auto currentTime = Utilities::currentTimeMillis();

            if (networkDelay == 0) {
                receiveFunction(std::move(rawDataPtr), currentTime);
                return currentTime;
            }

            int64_t timeToSend = currentTime + networkDelay;
            {
                lock_guard<mutex> queueLock(queueMutex);
                auto timedPair = std::make_unique<TimedZrtpData >(timeToSend, std::move(rawDataPtr));
                dataQueue.push_back(std::move(timedPair));
            }
            // Queue a timer event, the data is the time to send: requested time in handling lambda
            timeoutProvider.addTimer(timeToSend, timeToSend, [this](int64_t requestedTime) {

                lock_guard<mutex> queueLock(queueMutex);
                for (auto it = dataQueue.begin(); it != dataQueue.end(); ) {
                    if ((*it)->first == requestedTime) {
                        receiveFunction(std::move((*it)->second), (*it)->first);
                        it = dataQueue.erase(it);
                    }
                    else {
                        ++it;
                    }
                }
            });
            return timeToSend;
        }

        void setNetworkDelay(int64_t delay) { networkDelay = delay; }

    private:
        ZrtpTimeoutProvider & timeoutProvider;
        std::mutex queueMutex;
        std::list<TimedZrtpDataPair> dataQueue;
        std::function<void(ZrtpDataPairPtr, int64_t)> receiveFunction;
        int64_t networkDelay = 0;
    };
}

#endif //LIBZRTPCPP_NETWORKSIMULATION_H
