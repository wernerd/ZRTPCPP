/*
 * Copyright 2006 - 2018, Werner Dittmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//
// Created by wdi on 05.01.20.
//

#ifndef LIBZRTPCPP_ZRTPTIMEOUTPROVIDER_H
#define LIBZRTPCPP_ZRTPTIMEOUTPROVIDER_H

#include <cstdint>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "Utilities.h"

namespace zrtp {
    class ZrtpTimeoutProvider {

        // Internal timer task data
        struct TimerTask {
            TimerTask(int32_t i, int64_t t, int64_t d, std::function<void(int64_t)> f):
                    id(i), timeToRun(t), data(d), cbFunction(std::move(f)){}
            int32_t id;
            int64_t timeToRun;
            int64_t data;
            std::function<void(int64_t)> cbFunction;
        };
        using TimerTaskPtr = std::unique_ptr<TimerTask>;

    public:
        ZrtpTimeoutProvider() {
            timerThread = std::thread(&ZrtpTimeoutProvider::timerRun, this);
        }

        ~ZrtpTimeoutProvider() {
            runTimerThread = false;
            waitForTasks.notify_all();
            if (timerThread.joinable()) timerThread.join();
        }

        /**
         * @brief Schedules the specified function for execution at relative time.
         *
         * @param relativeTime Execute function after waiting this number of milli-seconds
         * @param data Caller data, not interpreted or used by the timer tasks
         * @return positive number: id of the timer task or an error code (< 0)
         */
        int32_t addTimer(int32_t relativeTime, int64_t data, const std::function<void(int64_t)>& cbFunction) {
            return addTimer(Utilities::currentTimeMillis() + relativeTime, data, cbFunction);
        }

        /**
         * @brief Schedules the specified function for execution at specified time.
         *
         * @param relativeTime Execute function at/after the specified time given in milli-seconds
         * @param data Caller data, not interpreted or used by the timer tasks
         * @return positive number: id of the timer task or an error code (< 0)
         */
        int32_t addTimer(int64_t absoluteTime, int64_t data, const std::function<void(int64_t)>& cbFunction) {
            std::lock_guard<std::mutex> tl(tasksLock);

            auto taskId = nextTaskId++;
            nextTaskId %= INT32_MAX;

            auto task = std::make_unique<TimerTask>(taskId, absoluteTime, data, cbFunction);

            if (tasks.empty()) {
                tasks.push_front(std::move(task));
            } else if (tasks.size() == 1) {
                if (task->timeToRun >= tasks.front()->timeToRun) {
                    tasks.push_back(std::move(task));
                } else {
                    tasks.push_front(std::move(task));
                }
            } else {
                tasks.push_back(std::move(task));
                tasks.sort([](const TimerTaskPtr &l, const TimerTaskPtr &r) { return l->timeToRun < r->timeToRun; });
            }
            waitForTasks.notify_all();
            return taskId;
        }

        /**
         * @brief Remove a timer if it still exists.
         *
         * @param taskId Timer to remove
         */
        void removeTimer(int32_t taskId) {
            std::lock_guard<std::mutex> tl(tasksLock);

            if (tasks.empty()) return;
            tasks.remove_if([&](const TimerTaskPtr &t) { return t->id == taskId; });
            waitForTasks.notify_all();
        }

#ifdef UNIT_TESTS
        [[nodiscard]] const std::list<TimerTaskPtr >& getTasks() const { return tasks; }
#endif
    private:
        void timerRun() {
            std::unique_lock runLock(tasksLock);
            while (runTimerThread) {
                if (tasks.empty()) {
                    waitForTasks.wait(runLock);
                    continue;
                }
                auto current = Utilities::currentTimeMillis();

                if (current < tasks.front()->timeToRun) {
                    auto waitTime = tasks.front()->timeToRun - current;
                    waitForTasks.wait_for(runLock, std::chrono::milliseconds(waitTime));
                    continue;
                }
                if (tasks.empty()) continue;
                auto task = move(tasks.front());
                tasks.pop_front();
                runLock.unlock();
                task->cbFunction(task->data);
                runLock.lock();
            }
        }

        std::list<TimerTaskPtr > tasks;
        std::mutex tasksLock;

        std::condition_variable waitForTasks;

        std::thread timerThread;

        int32_t nextTaskId = 1;
        bool runTimerThread = true;
    };
}
#endif //LIBZRTPCPP_ZRTPTIMEOUTPROVIDER_H
