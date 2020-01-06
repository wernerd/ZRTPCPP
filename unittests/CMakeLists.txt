cmake_minimum_required(VERSION 3.10)

#######
# Setup for ZrtpConfigure test using google test framework
#######

set (test_src
        zrtpConfigure_test.cpp
        utility_test.cpp
        zrtpTimeout_test.cpp)

add_executable(zrtpConfigure_test zrtpConfigure_test.cpp)
target_link_libraries(zrtpConfigure_test gtest_main ${zrtplibName})

add_executable(utility_test utility_test.cpp)
target_link_libraries(utility_test gtest_main ${zrtplibName})

add_executable(zrtpTimeout_test zrtpTimeout_test.cpp)
target_link_libraries(zrtpTimeout_test gtest_main ${zrtplibName})

add_executable(sdesRun_test sdesRun_test.cpp)
target_link_libraries(sdesRun_test gtest_main ${zrtplibName})
