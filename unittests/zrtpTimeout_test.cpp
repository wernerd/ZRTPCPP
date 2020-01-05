//
// Created by wdi on 5.01.20 г..
//

#include "../logging/ZrtpLogging.h"
#include "../common/Utilities.h"
#include "../common/ZrtpTimeoutProvider.h"
#include "gtest/gtest.h"

using namespace std;

class ZrtpTimeoutTestFixture : public ::testing::Test {
public:
    ZrtpTimeoutTestFixture() = default;

    ZrtpTimeoutTestFixture(const ZrtpTimeoutTestFixture &other) = delete;

    ZrtpTimeoutTestFixture(const ZrtpTimeoutTestFixture &&other) = delete;

    ZrtpTimeoutTestFixture &operator=(const ZrtpTimeoutTestFixture &other) = delete;

    ZrtpTimeoutTestFixture &operator=(const ZrtpTimeoutTestFixture &&other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(DEBUGGING);
    }

    void TearDown() override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~ZrtpTimeoutTestFixture() override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }
};

TEST_F(ZrtpTimeoutTestFixture, AddRemove) {
    zrtp::ZrtpTimeoutProvider provider;

    ASSERT_TRUE(provider.getTasks().empty());
    // The check for incorrect value just proves that no callback happened - add/remove is too fast
    auto id = provider.addTimer(100, 321, [](int64_t d) { ASSERT_EQ(555, d); });
    ASSERT_TRUE(id > 0);
    ASSERT_EQ(1, provider.getTasks().size());
    provider.removeTimer(id);
    ASSERT_TRUE(provider.getTasks().empty());
}

TEST_F(ZrtpTimeoutTestFixture, AddThenCallback) {
    zrtp::ZrtpTimeoutProvider provider;

    ASSERT_TRUE(provider.getTasks().empty());
    // The check for incorrect value just proves that callback happened - add/remove is too fast
    auto current = zrtp::Utilities::currentTimeMillis();

    auto id = provider.addTimer(100, 321, [&](int64_t d) {
        ASSERT_EQ(321, d);
        auto calledAt = zrtp::Utilities::currentTimeMillis();
        // Check if callback is in a reasonable time range
        ASSERT_TRUE(calledAt >= current + 100 && calledAt <= current + 105)
                                    << "timeout range missed, expected between: " << current + 100 << " and +5ms, actual: "
                                    << calledAt;
    });
    ASSERT_TRUE(id > 0);
    ASSERT_EQ(1, provider.getTasks().size());
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(provider.getTasks().empty());
}