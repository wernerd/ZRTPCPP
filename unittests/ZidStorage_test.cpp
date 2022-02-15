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

#include <cinttypes>
#include "libzrtpcpp/ZIDCacheDb.h"
#include "../logging/ZrtpLogging.h"
#include "../common/Utilities.h"
#include "gtest/gtest.h"

using namespace std;

class ZidStorageTestFixture: public ::testing::Test {
public:
    ZidStorageTestFixture() = default;

    ZidStorageTestFixture(const ZidStorageTestFixture& other) = delete;
    ZidStorageTestFixture(const ZidStorageTestFixture&& other) = delete;
    ZidStorageTestFixture& operator= (const ZidStorageTestFixture& other) = delete;
    ZidStorageTestFixture& operator= (const ZidStorageTestFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(DEBUGGING);
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~ZidStorageTestFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }
};

#ifdef ZID_DATABASE
constexpr char memoryDb[] = ":memory:";
constexpr uint8_t otherZid[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};

TEST_F(ZidStorageTestFixture, Database) {

    ZIDCacheDb zidDb;
    ASSERT_EQ(1, zidDb.open(const_cast<char *>(memoryDb)));

    auto ownZid = zidDb.getZid();
    ASSERT_TRUE(ownZid != nullptr);

    // Cannot get/create a remote ZID record with my own ZID
    auto ownZidRecord = zidDb.getRecord(const_cast<unsigned char *>(ownZid));
    ASSERT_FALSE(ownZidRecord);

    auto otherZidRecord = zidDb.getRecord(const_cast<unsigned char *>(otherZid));
    ASSERT_FALSE(otherZidRecord->isOwnZIDRecord());
    ASSERT_FALSE(otherZidRecord->isSasVerified());

    otherZidRecord->setSasVerified();
    zidDb.saveRecord(*otherZidRecord);

    // re-read record, check modified data
    auto ownZidRecordNew = zidDb.getRecord(const_cast<unsigned char *>(ownZid));
    ASSERT_TRUE(otherZidRecord->isSasVerified());

    zidDb.close();
}
#endif

