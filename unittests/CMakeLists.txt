cmake_minimum_required(VERSION 3.10)

#######
# Setup for ZrtpConfigure test using catch2 testframework
#######
set (configure_test_src
        catchMain.cpp
        zrtpConfigureTest.cpp
        )
add_executable(zrtpConfigure_test ${configure_test_src} )
target_link_libraries(zrtpConfigure_test ${zrtplibName})
