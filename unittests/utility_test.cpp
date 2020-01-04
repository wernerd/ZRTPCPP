//
// Created by wdi on 04.01.20.
//

#include <cinttypes>
//#include "../logging/ZinaLogging.h"
//#include "../util/Utilities.h"
#include "gtest/gtest.h"

using namespace std;

class UtilityTestFixture: public ::testing::Test {
public:
    UtilityTestFixture() = default;

    UtilityTestFixture(const UtilityTestFixture& other) = delete;
    UtilityTestFixture(const UtilityTestFixture&& other) = delete;
    UtilityTestFixture& operator= (const UtilityTestFixture& other) = delete;
    UtilityTestFixture& operator= (const UtilityTestFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        // LOGGER_INSTANCE setLogLevel(DEBUGGING);
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~UtilityTestFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        // LOGGER_INSTANCE setLogLevel(VERBOSE);
    }
};

TEST_F(UtilityTestFixture, TimeTest) {

//constexpr uint64_t ms = 1555521975329;
//constexpr time_t sec =  1555522670;
//const string expectedMs ("2019-04-17T17:26:15.329Z");
//const string expectedSec("2019-04-17T17:37:50Z");
//
//auto fmtMs = Utilities::getIsoTimeUtcMs(ms);
//ASSERT_EQ(expectedMs, fmtMs);
//
//auto fmtSec = Utilities::getIsoTimeUtc(sec);
//ASSERT_EQ(expectedSec, fmtSec);
}

