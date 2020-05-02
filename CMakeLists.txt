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
cmake_minimum_required(VERSION 3.0)

PROJECT(libzrtpcpp)

SET(CPACK_PACKAGE_VERSION_MAJOR 5)
SET(CPACK_PACKAGE_VERSION_MINOR 0)
SET(CPACK_PACKAGE_VERSION_PATCH 0)

set (VERSION 5.0.0)
set (SOVERSION 5)

# Define supported command line parameters.
#
# Example to build the tivi client: cmake -DTIVI=true ..
# Without any options cmake generates libzrtpcpp for use with GNU ccRTP
#
option(CCRTP "Build library to use with GNU ccRTP." OFF)
option(CORE_LIB "Build core library only, no specific client support." OFF)
option(CRYPTO_STANDALONE "Use embedded crypto and big number modules." ON)
option(TIVI "Build library for the Tivi client, implies '-DCRYPTO_STANDALONE=ON' and '-DSDES=ON'." OFF)
# option(WEBRTC "Create static lib for webRTC, with SIDH support." OFF)
option(SQLITE "Use SQLite DB as backend for ZRTP cache." OFF)
option(SQLCIPHER "Use SQLCipher DB as backend for ZRTP cache." OFF)
option(SRTP "Include SRTP when not building for CCRTP." OFF)
option(AXO "Include Axolotl support when not building for CCRTP." OFF)
option(TESTS "Generate Unit test." OFF)

option(ANDROID "Generate Android libraries, use if via Gradle build script" OFF)
# option(JAVA "Generate Java support files (requires JDK and SWIG)" OFF)

## The following options are used for SIDH mainly
option(SIDH "Include SIDH Post-Quantum algorithm." OFF)

option(x64 "Set this to true to build SIDH for a x64 (64 bit) architecture." OFF)
option(x86 "Set this to true to build SIDH for a x86 (32 bit) architecture." OFF)
option(arm "Set this to true to build SIDH for a arm (32 bit) architecture." OFF)
option(arm64 "Set this to true to build SIDH for a arm64 (64 bit) architecture." OFF)
option(GENERIC "Set this to true to use the portable SIDH implementation." OFF)

if(MSVC60)
    set(BUILD_STATIC ON CACHE BOOL "static linking only" FORCE)
    MARK_AS_ADVANCED(BUILD_STATIC)
else()
    option(BUILD_STATIC "Set to OFF to build shared libraries" OFF)
endif()

#
# If your project needs SAS relay support (refer to RFC6189 chapter 7.3) then
# uncomment the following add_definitiones statement. Make sure you understand
# the consequences.
## add_definitions(-DZRTP_SAS_RELAY_SUPPORT)

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

#if (WEBRTC AND (CCRTP OR TIVI OR CORE_LIB))
#    MESSAGE(FATAL_ERROR "Cannot build more than one client at once. Use different build directories.")
#endif()

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
    set(CRYPTO_STANDALONE true)
    set(SDES true)
    set(SRTP true)
elseif (CORE_LIB)
    set (PACKAGE libzrtpcore)
    set(zrtplibName zrtpcppcore)
#elseif (WEBRTC)
#    set (PACKAGE libzrtpwebrtc)
#    set(zrtplibName zrtpcppwebrtc)
#    set(SQLITE true)
#    set(ANDROID true)
#    set(SIDH true)      ## For SIDH testing
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

# set to true for debug and trace during CMakeLists development
# set(CMAKE_VERBOSE_MAKEFILE TRUE)

execute_process(COMMAND git rev-parse --short HEAD OUTPUT_VARIABLE GIT_COMMIT)
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

if (NOT CRYPTO_STANDALONE)
    pkg_check_modules(OPENSSL libcrypto>=0.9.8)
    if (OPENSSL_FOUND)
      set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${OPENSSL_INCLUDE_DIRS}) #update include files search directory
      check_include_files(openssl/bn.h HAVE_OPENSSL_BN_H)
      check_include_files(openssl/aes.h HAVE_OPENSSL_AES_H)
      check_include_files(openssl/sha.h HAVE_OPENSSL_SHA_H)
      check_library_exists(crypto EVP_CipherInit_ex "${OPENSSL_LIBDIR}" HAVE_SSL_CRYPT) #use search lib directory from pkg-config
      set(LIBS ${LIBS} -lcrypto)
      set(CRYPTOBACKEND "libcrypto >= 0.9.8")
      set(BUILD_REQ "libopenssl-devel >= 0.9.8")
      set(PACKAGE_REQ "libopenssl >= 0.9.8")
      add_definitions(-DZRTP_OPENSSL)
      include_directories(${OPENSSL_INCLUDE_DIRS}) #update includes directory from pkg-config
      MESSAGE(STATUS "Using OpenSSL crypto backend")
  else()
      message(FATAL_ERROR "No crypto library found")
  endif()
else()
    # For crypto standalone mode we need to configure the bnlib.
    check_include_files(stdint.h HAVE_STDINT_H)
    check_include_files(stdint.h HAVE_ASSERT_H)
    check_include_files(limits.h HAVE_LIMITS_H)

    check_function_exists(memmove HAVE_MEMMOVE)
    check_function_exists(memcpy HAVE_MEMCPY)

    # necessary and required modules checked, ready to generate config.h
    configure_file(${CMAKE_SOURCE_DIR}/bnlib/bnconfig.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/bnconfig.h)
    MESSAGE(STATUS "Using internal (standalone) crypto functions")

endif()

#### For Botan migration tests only - remove once Botan migration done
#pkg_check_modules(BOTAN botan-2)
#if (BOTAN_FOUND)
#    set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${BOTAN_INCLUDE_DIRS}) #update include files search directory
#    set(LIBS ${LIBS} ${BOTAN_LDFLAGS})
#    include_directories(${BOTAN_INCLUDE_DIRS}) #update includes directory from pkg-config
#    MESSAGE(STATUS "Botan-2: ${BOTAN_LIBRARIES} ${BOTAN_LIBRARY_DIRS} ${BOTAN_LDFLAGS}")
#    MESSAGE(STATUS "Botan-2 lib found")
#    set(USE_BOTAN true)
#endif()

set (USE_BOTAN true)

if (NOT ANDROID)
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
    add_definitions(-DNEW_STDCPP)
endif()


if (AXO)
    add_definitions(-DAXO_SUPPORT)
endif()

if (TESTS)
    add_definitions(-DUNIT_TESTS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -g -O2 -fno-strict-aliasing -Wno-unknown-pragmas ${LOG_MAX_LEVEL}")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -std=c++17 -g -O2 -fno-strict-aliasing -Wno-unknown-pragmas ${LOG_MAX_LEVEL}")
endif()

set(sidhLibNameStatic)
if (SIDH)
    include_directories (${CMAKE_SOURCE_DIR}/sidh/src)
    add_subdirectory(sidh)
    set(sidhLibNameStatic sidhCppStatic)
    add_definitions(-DSIDH_SUPPORT)
endif()

include_directories(BEFORE ${CMAKE_BINARY_DIR})
include_directories (${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/zrtp)

if(CRYPTO_STANDALONE)
    add_definitions(-DSUPPORT_NON_NIST)
    include_directories (${CMAKE_SOURCE_DIR}/bnlib)
endif()

if (SRTP)
    set (sdes_src
            ${CMAKE_SOURCE_DIR}/zrtp/ZrtpSdesStream.cpp
            ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpSdesStream.h)

    if (SDES AND CRYPTO_STANDALONE)
        add_definitions(-DENABLE_SDES_MIX)  ## SDES mixer currently with standalone crypto (no openSSL)
    endif()

endif()

# **** The following source files are common for all clients ****
#
set(BOTAN_AMAL true)
if (USE_BOTAN)
    set(botan_src
            ${CMAKE_SOURCE_DIR}/botancrypto/ZrtpBotanRng.cpp
            ${CMAKE_SOURCE_DIR}/botancrypto/ZrtpBotanRng.h
            ${CMAKE_SOURCE_DIR}/botancrypto/ZrtpCurve41417.cpp
            ${CMAKE_SOURCE_DIR}/botancrypto/ZrtpCurve41417.h
            ${CMAKE_SOURCE_DIR}/botancrypto/Ec41417Group.cpp
            ${CMAKE_SOURCE_DIR}/botancrypto/Ec41417Group.h
            ${CMAKE_SOURCE_DIR}/botancrypto/Point41417.cpp
            ${CMAKE_SOURCE_DIR}/botancrypto/Point41417.h
            )

    if (BOTAN_AMAL)
        add_definitions(-DBOTAN_AMAL)
        include_directories (${CMAKE_SOURCE_DIR}/botancrypto/x86_64)
        set (botan_src ${botan_src}
                ${CMAKE_SOURCE_DIR}/botancrypto/x86_64/botan_all.cpp
                ${CMAKE_SOURCE_DIR}/botancrypto/x86_64/botan_all.h)
    endif()
endif()

set(zrtp_src_include
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/Base32.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/EmojiBase32.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDCacheDb.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDCacheFile.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDCacheEmpty.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDCache.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDRecordDb.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDRecordFile.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDRecord.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZIDRecordEmpty.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/zrtpB64Decode.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/zrtpB64Encode.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/zrtpCacheDbBackend.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCallback.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCallbackWrapper.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCodes.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpConfigure.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCrc32.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCWrapper.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZRtp.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketBase.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketClearAck.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketCommit.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketConf2Ack.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketConfirm.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketDHPart.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketErrorAck.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketError.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketGoClear.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/zrtpPacket.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketHelloAck.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketHello.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketPingAck.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketPing.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketRelayAck.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpPacketSASrelay.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpStateClass.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpStates.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpTextData.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpUserCallback.h
        )

set(zrtp_src_no_cache
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpCallbackWrapper.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZRtp.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpCrc32.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketCommit.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketConf2Ack.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketConfirm.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketDHPart.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketGoClear.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketClearAck.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketHelloAck.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketHello.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketError.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketErrorAck.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketPingAck.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketPing.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketSASrelay.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpPacketRelayAck.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpStateClass.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpConfigure.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpCWrapper.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/Base32.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/EmojiBase32.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/zrtpB64Encode.c
        ${CMAKE_SOURCE_DIR}/zrtp/zrtpB64Decode.c
        ${CMAKE_SOURCE_DIR}/common/icuUtf8.c
        ${CMAKE_SOURCE_DIR}/common/icuUtf.h
        ${CMAKE_SOURCE_DIR}/common/osSpecifics.c
        ${CMAKE_SOURCE_DIR}/common/osSpecifics.h
        ${CMAKE_SOURCE_DIR}/common/Utilities.cpp
        ${CMAKE_SOURCE_DIR}/common/Utilities.h
        ${CMAKE_SOURCE_DIR}/common/typedefs.h
        ${CMAKE_SOURCE_DIR}/common/ZrtpTimeoutProvider.h
        ${CMAKE_SOURCE_DIR}/common/SecureArray.h
        ${CMAKE_SOURCE_DIR}/common/Constants.h
        ${CMAKE_SOURCE_DIR}/helpers/ZrtpConfigureBuilder.h
        ${CMAKE_SOURCE_DIR}/helpers/ZrtpConfigureBuilder.cpp
        ${CMAKE_SOURCE_DIR}/helpers/ZrtpUserCallbackEmpty.h
        ${CMAKE_SOURCE_DIR}/helpers/ZrtpCodeToString.h
        ${CMAKE_SOURCE_DIR}/helpers/ZrtpCodeToString.cpp
        ${CMAKE_SOURCE_DIR}/logging/Logger.cpp
        ${CMAKE_SOURCE_DIR}/logging/ZrtpLogging.cpp
        ${CMAKE_SOURCE_DIR}/logging/logger_config.h
        ${CMAKE_SOURCE_DIR}/logging/osSpecifics.h
        ${sdes_src} ${zrtp_src_include} ${botan_src} )

set(bnlib_src
        ${CMAKE_SOURCE_DIR}/bnlib/bn00.c
        ${CMAKE_SOURCE_DIR}/bnlib/lbn00.c
        ${CMAKE_SOURCE_DIR}/bnlib/bn.c
        ${CMAKE_SOURCE_DIR}/bnlib/lbnmem.c
        ${CMAKE_SOURCE_DIR}/bnlib/sieve.c
        ${CMAKE_SOURCE_DIR}/bnlib/prime.c
        ${CMAKE_SOURCE_DIR}/bnlib/bnprint.c
        ${CMAKE_SOURCE_DIR}/bnlib/jacobi.c
        ${CMAKE_SOURCE_DIR}/bnlib/germain.c
        ${CMAKE_SOURCE_DIR}/bnlib/ec/ec.c
        ${CMAKE_SOURCE_DIR}/bnlib/ec/ecdh.c
        ${CMAKE_SOURCE_DIR}/bnlib/ec/curve25519-donna.c)

set(zrtp_skein_src
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/skein256.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/skein384.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/skeinMac256.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/skeinMac384.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/skeinMac256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/skein256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/skeinMac384.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/skein384.cpp)

set(zrtp_crypto_includes
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/aesCFB.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/hmac256.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/hmac384.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha2.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha256.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha384.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/twoCFB.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/zrtpDH.h
        )

set(zrtp_standalone_crypto_src
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/zrtpDH.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/hmac256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/sha256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/hmac384.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/sha384.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/aesCFB.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/twoCFB.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/sha2.c
        ${zrtp_crypto_includes})

set(zrtp_botan_crypto_src
        ${botan_src}
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/botan/zrtpDH.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/hmac256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/sha256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/hmac384.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/sha384.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/aesCFB.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/twoCFB.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/standalone/sha2.c
        ${zrtp_crypto_includes})

set(zrtp_src ${zrtp_src_no_cache}
        ${CMAKE_SOURCE_DIR}/zrtp/ZIDCacheEmpty.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZIDRecordEmpty.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZIDCacheFile.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZIDRecordFile.cpp)

if (SQLITE OR SQLCIPHER)
    add_definitions(-DZID_DATABASE)
    set(zrtp_src ${zrtp_src}
        ${CMAKE_SOURCE_DIR}/zrtp/ZIDCacheDb.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZIDRecordDb.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/zrtpCacheSqliteBackend.c)
endif()

if (CCRTP)
    add_subdirectory(clients/ccrtp)
endif()

if (TIVI)
    add_subdirectory(clients/tivi)
endif()

if (CORE_LIB)
    add_subdirectory(clients/genericClient)
endif()

if (WEBRTC)
    add_subdirectory(clients/webrtc)
endif()

if (TESTS)
    # Download and unpack googletest at configure time.
    configure_file(CMakeLists_gtest.txt.in googletest-download/CMakeLists.txt)
    execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
    if(result)
        message(FATAL_ERROR "CMake step for googletest failed: ${result}")
    endif()
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
    if(result)
        message(FATAL_ERROR "Build step for googletest failed: ${result}")
    endif()

    # Prevent overriding the parent project's compiler/linker
    # settings on Windows
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

    # Add googletest directly to our build. This defines
    # the gtest and gtest_main targets.
    add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
            ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
            EXCLUDE_FROM_ALL)

    # The gtest/gtest_main targets carry header search path
    # dependencies automatically when using CMake 2.8.11 or
    # later. Otherwise we have to add them here ourselves.
    if (CMAKE_VERSION VERSION_LESS 2.8.11)
        include_directories("${gtest_SOURCE_DIR}/include")
    endif()

    add_subdirectory(unittests)
    add_subdirectory(demo)
endif()

##very useful for macosx, specially when using gtkosx bundler
if(APPLE)
    if (NOT CMAKE_INSTALL_NAME_DIR)
        set(CMAKE_INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE STRING "CMAKE_INSTALL_NAME_DIR set for macosx" )
    endif (NOT CMAKE_INSTALL_NAME_DIR)
endif(APPLE)
