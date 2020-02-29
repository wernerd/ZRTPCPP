cmake_minimum_required(VERSION 3.10)

#######
# Setup for ZRTP tests using google test framework
#######

add_executable(zrtpConfigure_test ZrtpConfigure_test.cpp)
target_link_libraries(zrtpConfigure_test gtest_main ${zrtplibName})

add_executable(utility_test utility_test.cpp)
target_link_libraries(utility_test gtest_main ${zrtplibName})

add_executable(zrtpTimeout_test ZrtpTimeout_test.cpp)
target_link_libraries(zrtpTimeout_test gtest_main ${zrtplibName})

add_executable(zrtpStartStop_test ZrtpStartStop_test.cpp)
target_link_libraries(zrtpStartStop_test gmock_main ${zrtplibName})

add_executable(zrtpHello_test ZrtpHello_test.cpp)
target_link_libraries(zrtpHello_test gmock_main ${zrtplibName})

add_executable(zrtpRun_test ZrtpBasicRun_test.cpp ZrtpTestCommon.h)
target_link_libraries(zrtpRun_test gmock_main ${zrtplibName})

add_executable(zrtpTimedRun_test ZrtpTimedRun_test.cpp ZrtpTestCommon.h NetworkSimulation.h)
target_link_libraries(zrtpTimedRun_test gmock_main ${zrtplibName})

if (SIDH)
    add_executable(zrtpSidh503_test ZrtpSidh503_test.cpp)
    target_link_libraries(zrtpSidh503_test gtest_main ${zrtplibName})

    add_executable(zrtpSidh751_test ZrtpSidh751_test.cpp)
    target_link_libraries(zrtpSidh751_test gtest_main ${zrtplibName})
endif()

if(SDES)
    add_executable(sdesRun_test sdesRun_test.cpp)
    target_link_libraries(sdesRun_test gtest_main ${zrtplibName})
endif()

if (NOT CCRTP)
    add_executable(srtpCrypto_test SrtpCrypto_test.cpp ZrtpTestCommon.h)
    target_link_libraries(srtpCrypto_test gtest_main ${zrtplibName})
endif()
