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

if(SDES)
    add_executable(sdesRun_test sdesRun_test.cpp)
    target_link_libraries(sdesRun_test gtest_main ${zrtplibName})
endif()

if (NOT CCRTP)
    add_executable(srtpCrypto_test SrtpCrypto_test.cpp ZrtpTestCommon.h)
    target_link_libraries(srtpCrypto_test gtest_main ${zrtplibName})
endif()
