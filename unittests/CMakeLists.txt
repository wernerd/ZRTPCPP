cmake_minimum_required(VERSION 3.10)

#######
# Setup for ZrtpConfigure test using google test framework
#######

add_executable(zrtpConfigure_test zrtpConfigure_test.cpp)
target_link_libraries(zrtpConfigure_test gtest_main ${zrtplibName})

add_executable(utility_test utility_test.cpp)
target_link_libraries(utility_test gtest_main ${zrtplibName})
