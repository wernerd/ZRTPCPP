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

using namespace std;

namespace zrtp {
    class ZrtpTimeoutProvider {

        // Internal timer task data
        struct TimerTask {
            TimerTask(int32_t i, int64_t t, int64_t d, function<void(int64_t)> f):
                    id(i), timeToRun(t), data(d), cbFunction(move(f)){}
            int32_t id;
            int64_t timeToRun;
            int64_t data;
            function<void(int64_t)> cbFunction;
        };
        using TimerTaskPtr = unique_ptr<TimerTask>;

    public:
        ZrtpTimeoutProvider() {
            timerThread = thread(&ZrtpTimeoutProvider::timerRun, this);
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
        int32_t addTimer(int32_t relativeTime, int64_t data, const function<void(int64_t)>& cbFunction) {
            auto steadyTime = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now().time_since_epoch()).count();
            relativeTime = (relativeTime > 0) ? relativeTime : 1;       // at least one millisecond, never negative

            lock_guard<mutex> tl(tasksLock);

            auto taskId = nextTaskId++;
            nextTaskId %= INT32_MAX;

            auto task = make_unique<TimerTask>(taskId, steadyTime + relativeTime, data, cbFunction);

            if (tasks.empty()) {
                tasks.push_front(move(task));
            } else if (tasks.size() == 1) {
                if (task->timeToRun >= tasks.front()->timeToRun) {
                    tasks.push_back(move(task));
                } else {
                    tasks.push_front(move(task));
                }
            } else {
                tasks.push_back(move(task));
                tasks.sort([](const TimerTaskPtr &l, const TimerTaskPtr &r) { return l->timeToRun < r->timeToRun; });
            }
            waitForTasks.notify_all();
            return taskId;

        }

        /**
         * @brief Schedules the function for execution at specified absolute time since the Unix epoch
         *
         * @param relativeTime Execute function at/after the specified time given in milli-seconds
         * @param data Caller data, not interpreted or used by the timer tasks
         * @return positive number: id of the timer task or an error code (< 0)
         */
        int32_t addTimer(int64_t absoluteTime, int64_t data, const function<void(int64_t)>& cbFunction) {
            return addTimer(static_cast<int32_t >(absoluteTime - Utilities::currentTimeMillis()),
                            data, cbFunction);
        }

        /**
         * @brief Remove a timer if it still exists.
         *
         * @param taskId Timer to remove
         */
        void removeTimer(int32_t taskId) {
            lock_guard<mutex> tl(tasksLock);

            if (tasks.empty()) return;
            tasks.remove_if([&](const TimerTaskPtr &t) { return t->id == taskId; });
            waitForTasks.notify_all();
        }

#ifdef UNIT_TESTS
        [[nodiscard]] const list<TimerTaskPtr >& getTasks() const { return tasks; }
#endif
    private:
        void timerRun() {
            unique_lock runLock(tasksLock);
            while (runTimerThread) {
                if (tasks.empty()) {
                    waitForTasks.wait(runLock);
                    continue;
                }
                auto current = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now().time_since_epoch()).count();

                if (current < tasks.front()->timeToRun) {
                    auto waitTime = tasks.front()->timeToRun - current;
                    waitForTasks.wait_for(runLock, chrono::milliseconds(waitTime));
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

        list<TimerTaskPtr > tasks;
        mutex tasksLock;

        condition_variable waitForTasks;

        thread timerThread;

        int32_t nextTaskId = 1;
        bool runTimerThread = true;
    };
}
#endif //LIBZRTPCPP_ZRTPTIMEOUTPROVIDER_H
