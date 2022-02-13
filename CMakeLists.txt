#
# Copyright 2006 - 2018, Werner Dittmann
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
cmake_minimum_required(VERSION 3.18)

PROJECT(libzrtpcpp)

SET(CPACK_PACKAGE_VERSION_MAJOR 5)
SET(CPACK_PACKAGE_VERSION_MINOR 0)
SET(CPACK_PACKAGE_VERSION_PATCH 0)

set (VERSION 5.0.0)
set (SOVERSION 5)

cmake_policy(SET CMP0077 NEW)
# Define supported command line parameters.
#
# Example to build the tivi client: cmake -DTIVI=true ..
# Without any options cmake generates libzrtpcpp for use with GNU ccRTP
#
option(CCRTP "Build library to use with GNU ccRTP." OFF)
option(CORE_LIB "Build core library only, no specific client support." OFF)
option(TIVI "Build library for the Tivi client, implies '-DSDES=ON' and '-DSRTP=ON'." OFF)
option(SQLITE "Use SQLite DB as backend for ZRTP cache." OFF)
option(SQLCIPHER "Use SQLCipher DB as backend for ZRTP cache." OFF)
option(SRTP "Include SRTP when not building for CCRTP." OFF)
option(AXO "Include Axolotl support when not building for CCRTP." OFF)
option(TESTS "Generate Unit test." OFF)

## The following options are used for SIDH mainly
option(SIDH "Include SIDH Post-Quantum algorithm." OFF)

if (TESTS)
    set(ANDROID false)
    set(IOS false)
endif()

if (ANDROID OR IOS)
    set (EMBEDDED true)
endif()

if(MSVC60)
    set(BUILD_STATIC ON CACHE BOOL "static linking only" FORCE)
    MARK_AS_ADVANCED(BUILD_STATIC)
else()
    option(BUILD_STATIC "Set to OFF to build shared libraries" OFF)
endif()

if (EMBEDDED)
    set(BUILD_STATIC true)
endif()

#
# If your project needs SAS relay support (refer to RFC6189 chapter 7.3) then
# uncomment the following add_definitions statement. Make sure you understand
# the consequences.
## add_compile_definitions(ZRTP_SAS_RELAY_SUPPORT)

# **** Check what and how to build ****
#
if (CCRTP AND (TIVI OR CORE_LIB OR WEBRTC))
    MESSAGE(FATAL_ERROR "Cannot build more than one client at once. Use different build directories.")
endif()

if (TIVI AND (CCRTP OR CORE_LIB OR WEBRTC))
    MESSAGE(FATAL_ERROR "Cannot build more than one client at once. Use different build directories.")
endif()

if (CORE_LIB AND (CCRTP OR TIVI OR WEBRTC))
    MESSAGE(FATAL_ERROR "Cannot build more than one client at once. Use different build directories.")
endif()

if (SQLITE AND SQLCIPHER)
    MESSAGE(FATAL_ERROR "Cannot build with multiple DB backends.")
endif()

if (CCRTP)
    set (PACKAGE libzrtpcpp)
    set(zrtplibName zrtpcpp)
    set(SRTP false)
elseif (TIVI)
    set (PACKAGE libzrtptivi)
    set(zrtplibName zrtptivi)
    set(SDES true)
    set(SRTP true)
elseif (CORE_LIB)
    set (PACKAGE libzrtpcore)
    set(zrtplibName zrtpcppcore)
    if (ANDROID AND (SQLITE OR SQLCIPHER))
        MESSAGE(STATUS "No support for SQLITE or SQLCIPHER when building core library for Android. Options set to false." )
        MESSAGE(STATUS "This requires a special setup with SQLite or SQLCipher.")
        set(SQLITE false)
        set(SQLCIPHER false)
    endif()
else()
    MESSAGE(FATAL_ERROR "No client defined: define client using -DCCRTP=true, or -DTIVI=true, or -DCORE_LIB=true.")
endif()

string(TOLOWER "${CMAKE_BUILD_TYPE}" build_type)
if ("debug" STREQUAL build_type)
    set (LOG_MAX_LEVEL "-DLOG_MAX_LEVEL=VERBOSE")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DLOG_MAX_LEVEL=VERBOSE")
else()
    set (LOG_MAX_LEVEL "-DLOG_MAX_LEVEL=WARNING")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DLOG_MAX_LEVEL=WARNING")
endif()

set(CMAKE_CXX_STANDARD 17)

include(FetchContent)

set(sidh_lc sidh)
set(botan_lc botan)

## check if a local fetch configuration is available. If yes: load it. This local
## configuration may set fetch content source dir variables to point to local git
## repos. Cmake does not download the repo in this case but uses the local git repo.
## cmake sets up the fetch content data correctly. Use this feature to develop
## locally without disturbing builds of a CI system.

## Never check-in the LocalFetchConfig.cmake file. It's *Local* for a reason :-)
if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/LocalFetchConfig.cmake)
    include(${CMAKE_CURRENT_SOURCE_DIR}/LocalFetchConfig.cmake)
endif()

if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
    set(enable-x86_64 true)         ## SIDH definition
endif()

set(ZRTP_TOP_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(ZRTP_TOP_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})
# set to true for debug and trace during CMakeLists development
# set(CMAKE_VERBOSE_MAKEFILE TRUE)

execute_process(
        COMMAND git rev-parse --short HEAD OUTPUT_VARIABLE GIT_COMMIT
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
STRING(REGEX REPLACE "(\r?\n)+$" "" GIT_COMMIT "${GIT_COMMIT}")

# include most of the fine stuff we need
include(FindPkgConfig)
include(CheckLibraryExists)
include(CheckIncludeFiles)
include(CheckFunctionExists)

if (NOT LIB_SUFFIX)
    set(LIBDIRNAME "lib")
    # this caused problems in debian where it has to always be lib....
    if (NOT EXISTS /etc/debian_version)
        if ( "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64" )
            set(LIBDIRNAME "lib64")
        endif()
    endif()
else()
    set(LIBDIRNAME "lib${LIB_SUFFIX}")
endif()

MESSAGE(STATUS "Configuring GNU ${PROJECT_NAME} ${VERSION} for ${PACKAGE}, commit: ${GIT_COMMIT} ...")

set(CMAKE_MACOSX_RPATH 1)

check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(string.h HAVE_STRING_H)

if (NOT EMBEDDED)
    if (SQLITE)
        pkg_check_modules(SQLITE3 sqlite3>=3.7)
        if (SQLITE3_FOUND)
            check_include_files(sqlite3.h HAVE_SQLITE_H)
            set(LIBS ${LIBS} -lsqlite3)
            MESSAGE(STATUS "Using SQLite based ZRTP cache")
        else()
            message(FATAL_ERROR "SQLite3 library not found")
        endif()
    elseif(SQLCIPHER)
        pkg_check_modules(SQLCIPHER sqlcipher>=3.7)
        if (SQLCIPHER_FOUND)
            set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${SQLCIPHER_INCLUDE_DIRS})
            check_include_files(sqlite3.h HAVE_SQLCIPHER_H)
            set(LIBS ${LIBS} ${SQLCIPHER_LDFLAGS})
            MESSAGE(STATUS "Using SQlCipher based ZRTP cache: ${SQLCIPHER_LIBRARIES} ${SQLCIPHER_LIBRARY_DIRS} ${SQLCIPHER_LDFLAGS}")
            add_definitions(-DSQL_CIPHER -DSQLITE_HAS_CODEC)
            include_directories(${SQLCIPHER_INCLUDE_DIRS}) #update includes directory from pkg-config
        else()
            message(FATAL_ERROR "SQLCipher library not found")
        endif()
    endif()
endif()

# necessary and required modules checked, ready to generate config.h in top-level build directory
configure_file(config.h.cmake ${CMAKE_BINARY_DIR}/config.h)

if(CMAKE_COMPILER_IS_GNUCXX)
    add_compile_definitions(NEW_STDCPP)
endif()

if (AXO)
    add_compile_definitions(AXO_SUPPORT)
endif()

if (TESTS)
    add_definitions(-DUNIT_TESTS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -g -O2 -fno-strict-aliasing -Wno-unknown-pragmas ${LOG_MAX_LEVEL}")
     # Download and unpack googletest at configure time.
    set(gtest_fetch googletest)

    FetchContent_Declare(
            ${gtest_fetch}
            # Specify the commit you depend on and update it regularly.
            ##            URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
            URL https://github.com/google/googletest/archive/refs/tags/release-1.11.0.zip
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -std=c++17 -g -O2 -fno-strict-aliasing -Wno-unknown-pragmas ${LOG_MAX_LEVEL}")
endif()

if ("${BOTAN_REPO}" STREQUAL "")
    set(BOTAN_REPO https://github.com/wernerd/botan.git)
endif()
if ("${BOTAN_TAG}" STREQUAL "")
    set(BOTAN_TAG 16fabba96f79c6bbf5d28120e393babb3f11e4ec)  ## branch skein-enhance-2 top
endif()
# Botan modules required by ZRTP library
set(BOTAN_MODULES "sha2_32,sha2_64,sha1,twofish,aes,skein,hmac,pubkey,curve25519,cfb,cbc,ec_group,ecdh,dh,dl_group" )
FetchContent_Declare(
        ${botan_lc}
        SOURCE_SUBDIR amalLibs                              ## create amalgamation, build static lib
        GIT_REPOSITORY ${BOTAN_REPO}
        GIT_TAG        ${BOTAN_TAG}
)

if ("${SIDH_REPO}" STREQUAL "")
    set(SIDH_REPO https://github.com/wernerd/PQCrypto-SIDH.git)
endif()
if ("${SIDH_TAG}" STREQUAL "")
    set(SIDH_TAG 95dd9526452c61aa4b30eef650edebf6328b1aab)  ## branch wdi top
endif()
set(sidhLibNameStatic)
if (SIDH)
    set(sidh_fetch ${sidh_lc})
    FetchContent_Declare(
            ${sidh_fetch}
            GIT_REPOSITORY ${SIDH_REPO}
            GIT_TAG        ${SIDH_TAG}
    )
    FetchContent_MakeAvailable(${sidh_fetch})
    include_directories (${sidh_SOURCE_DIR} ${sidh_SOURCE_DIR}/src)
    set(sidhLibNameStatic sidhCppStatic)
    add_definitions(-DSIDH_SUPPORT)
endif()

if ("${BOTAN_LIB_NAME}" STREQUAL "")
    set(BOTAN_LIB_NAME botanstatic)
endif ()

FetchContent_MakeAvailable(${botan_lc} ${gtest_fetch})

# to make sure these includes are taken first - it contains config.h
include_directories(BEFORE ${CMAKE_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/zrtp ${CMAKE_CURRENT_SOURCE_DIR}/srtp)
## include_directories (${CMAKE_CURRENT_SOURCE_DIR}/botancrypto/${botan_all})
add_compile_definitions(SUPPORT_NON_NIST)

if (SRTP)
    set (sdes_src
            ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpSdesStream.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpSdesStream.h)

    if (SDES)
        add_definitions(-DENABLE_SDES_MIX)  ## SDES mixer
    endif()
endif()

# **** The following source files are common for all clients ****
#
set(botan_src
        ${CMAKE_CURRENT_SOURCE_DIR}/botancrypto/ZrtpBotanRng.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/botancrypto/ZrtpBotanRng.h
        ${CMAKE_CURRENT_SOURCE_DIR}/botancrypto/ZrtpCurve41417.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/botancrypto/ZrtpCurve41417.h
        ${CMAKE_CURRENT_SOURCE_DIR}/botancrypto/Ec41417Group.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/botancrypto/Ec41417Group.h
        ${CMAKE_CURRENT_SOURCE_DIR}/botancrypto/Point41417.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/botancrypto/Point41417.h
)

set(zrtp_src_include
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/Base32.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/EmojiBase32.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDCacheDb.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDCacheFile.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDCacheEmpty.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDCache.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDRecordDb.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDRecordFile.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDRecord.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDRecordEmpty.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/zrtpB64Decode.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/zrtpB64Encode.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/zrtpCacheDbBackend.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCallback.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCallbackWrapper.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCodes.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpConfigure.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCrc32.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCWrapper.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZRtp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketBase.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketClearAck.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketCommit.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketConf2Ack.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketConfirm.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketDHPart.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketErrorAck.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketError.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketGoClear.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/zrtpPacket.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketHelloAck.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketHello.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketPingAck.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketPing.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketRelayAck.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketSASrelay.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpStateClass.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpStates.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpTextData.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpUserCallback.h
        )

set(zrtp_src_no_cache
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpCallbackWrapper.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZRtp.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpCrc32.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketCommit.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketConf2Ack.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketConfirm.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketDHPart.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketGoClear.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketClearAck.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketHelloAck.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketHello.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketError.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketErrorAck.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketPingAck.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketPing.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketSASrelay.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpPacketRelayAck.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpStateClass.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpConfigure.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZrtpCWrapper.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/Base32.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/EmojiBase32.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/zrtpB64Encode.c
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/zrtpB64Decode.c
        ${CMAKE_CURRENT_SOURCE_DIR}/common/icuUtf8.c
        ${CMAKE_CURRENT_SOURCE_DIR}/common/icuUtf.h
        ${CMAKE_CURRENT_SOURCE_DIR}/common/osSpecifics.c
        ${CMAKE_CURRENT_SOURCE_DIR}/common/osSpecifics.h
        ${CMAKE_CURRENT_SOURCE_DIR}/common/Utilities.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/common/Utilities.h
        ${CMAKE_CURRENT_SOURCE_DIR}/common/typedefs.h
        ${CMAKE_CURRENT_SOURCE_DIR}/common/ZrtpTimeoutProvider.h
        ${CMAKE_CURRENT_SOURCE_DIR}/common/SecureArray.h
        ${CMAKE_CURRENT_SOURCE_DIR}/common/ZrtpConstants.h
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers/ZrtpConfigureBuilder.h
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers/ZrtpConfigureBuilder.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers/ZrtpUserCallbackEmpty.h
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers/ZrtpCodeToString.h
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers/ZrtpCodeToString.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/logging/Logger.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/logging/ZrtpLogging.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/logging/logger_config.h
        ${CMAKE_CURRENT_SOURCE_DIR}/logging/osSpecifics.h
        ${sdes_src} ${zrtp_src_include} ${botan_src})

set(zrtp_crypto_includes
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/aesCFB.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/hmac256.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/hmac384.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/sha256.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/sha384.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/skein256.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/skein384.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/skeinMac256.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/skeinMac384.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/twoCFB.h
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/zrtpDH.h
        )

set(zrtp_botan_crypto_src
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/botan/zrtpDH.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/botan/hmac256.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/botan/sha256.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/botan/hmac384.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/botan/sha384.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/botan/skeinMac256.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/botan/skein256.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/botan/skeinMac384.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/botan/skein384.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/botan/aesCFB.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/crypto/botan/twoCFB.cpp
        ${zrtp_crypto_includes})

set(zrtp_src ${zrtp_src_no_cache}
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZIDCacheEmpty.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZIDRecordEmpty.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZIDCacheFile.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZIDRecordFile.cpp)

if (SQLITE OR SQLCIPHER)
    add_compile_definitions(ZID_DATABASE)
    set(zrtp_src ${zrtp_src}
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZIDCacheDb.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/ZIDRecordDb.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/zrtp/zrtpCacheSqliteBackend.c)
endif()

if (CCRTP)
    add_subdirectory(clients/ccrtp)
    add_subdirectory(demo)
endif()

if (TIVI)
    add_subdirectory(clients/tivi)
endif()

if (CORE_LIB)
    add_subdirectory(clients/genericClient)
endif()

if (TESTS AND NOT EMBEDDED)
    add_subdirectory(unittests)
endif()

    ##very useful for macosx, specially when using gtkosx bundler
if(APPLE)
    if (NOT CMAKE_INSTALL_NAME_DIR)
        set(CMAKE_INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE STRING "CMAKE_INSTALL_NAME_DIR set for macosx" )
    endif (NOT CMAKE_INSTALL_NAME_DIR)
endif(APPLE)
