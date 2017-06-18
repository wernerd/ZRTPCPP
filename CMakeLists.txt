# Copyright (C) 2009 - 2016 Werner Dittman
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
cmake_minimum_required(VERSION 2.6)

PROJECT(libzrtpcpp)

SET(CPACK_PACKAGE_VERSION_MAJOR 4)
SET(CPACK_PACKAGE_VERSION_MINOR 6)
SET(CPACK_PACKAGE_VERSION_PATCH 6)

set (VERSION 4.6.6)
set (SOVERSION 4)

# Define supported command line parameters.
#
# Example to build the tivi client: cmake -DTIVI=true ..
# Without any options cmake generates libzrtpcpp for use with GNU ccRTP
#
option(CCRTP "Build library to use with GNU ccRTP." OFF)
option(CORE_LIB "Build core library only, no spcific client support." OFF)
option(CRYPTO_STANDALONE "Use embedded crypto and big number modules." ON)
option(WEBRTC "Create static lib for webRTC, with SIDH support." OFF)
option(TIVI "Build library for the tivi client, implies '-DCRYPTO_STNDALONE=true'." OFF)
option(SQLITE "Use SQLite DB as backend for ZRTP cache." OFF)
option(SQLCIPHER "Use SQLCipher DB as backend for ZRTP cache." OFF)
option(SDES "Include SDES when not building for CCRTP." OFF)
option(AXO "Include Axolotl support when not building for CCRTP." OFF)
option(UNITTESTS "Build unit tests and/or test logging." OFF)

option(ANDROID "Generate Android makefiles (Android.mk)" OFF)
option(JAVA "Generate Java support files (requires JDK and SWIG)" OFF)

## The foolowing option are used for SIDH mainly
option(SIDH "Include SIDH Post-Quantum algorithm." OFF)

option(X64 "Set this to true to build for a x64 (64 bit) architecture." OFF)
option(X86 "Set this to true to build for a x86 (32 bit) architecture." OFF)
option(ARM "Set this to true to build for a ARM (32 bit) architecture." OFF)
option(ARM64 "Set this to true to build for a ARM64 (64 bit) architecture." OFF)
option(GENERIC "Set this to true to use the portable implementation." OFF)

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

if (WEBRTC AND (CCRTP OR TIVI OR CORE_LIB))
    MESSAGE(FATAL_ERROR "Cannot build more than one client at once. Use different build directories.")
endif()

if (SQLITE AND SQLCIPHER)
    MESSAGE(FATAL_ERROR "Cannot build with two DB backends.")
endif()

if (CCRTP)
    set (PACKAGE libzrtpcpp)
    set(zrtplibName zrtpcpp)
elseif (TIVI)
    set (PACKAGE libzrtptivi)
    set(zrtplibName zrtptivi)
    set(CRYPTO_STANDALONE true)
    set(SQLCIPHER true)
    set(SQLITE false)
    set(SDES true)
elseif (CORE_LIB)
    set (PACKAGE libzrtpcore)
    set(zrtplibName zrtpcppcore)
elseif (WEBRTC)
    set (PACKAGE libzrtpwebrtc)
    set(zrtplibName zrtpcppwebrtc)
    set(SQLITE true)
    set(ANDROID true)
    set(SIDH true)      ## For SIDH testing
else()
    MESSAGE(WARNING "No client defined, building for GNU ccRTP.")
    set (PACKAGE libzrtpcpp)
    set(CCRTP true)
    set(zrtplibName zrtpcpp)
endif()

if (SIDH)
    if(X64)
        set(SIDH_ARCHITECTURE -D_AMD64_)
        set(SIDH_X64 true)
    elseif(X86)
        set (SIDH_ARCHITECTURE -D_X86_)
        set(SIDH_X86 true)
    elseif(ARM)
        set(SIDH_ARCHITECTURE -D_ARM_)
        set(SIDH_ARM true)
    elseif(ARM64)
        set(SIDH_ARCHITECTURE -D_ARM64_)
        set(SIDH_ARM64 true)
    elseif()
        message(FATAL_ERROR "No SIDH architecture selected.")
    endif()
    if (GENERIC OR SIDH_ARM OR SIDH_X86)        # No ASM module available for x86 and ARM, use generic
        set (USE_GENERIC -D_GENERIC_)
        set(SIDH_GENERIC true)
    endif()
endif()


if(MSVC60)
    set(BUILD_STATIC ON CACHE BOOL "static linking only" FORCE)
    MARK_AS_ADVANCED(BUILD_STATIC)
else()
    option(BUILD_STATIC "Set to OFF to build shared libraries" OFF)
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
    # For crypto standalone mode we need to configure the bnlib. In a first step
    # without the tests and demos.
    check_include_files(stdint.h HAVE_STDINT_H)
    check_include_files(stdint.h HAVE_ASSERT_H)
    check_include_files(limits.h HAVE_LIMITS_H)

    check_function_exists(memmove HAVE_MEMMOVE)
    check_function_exists(memcpy HAVE_MEMCPY)

    # TODO: check if we compile the tests for bnlib
    #
    # check_function_exists(clock_gettime HAVE_CLOCK_GETTIME)
    # check_function_exists(getrusage HAVE_GETRUSAGE)
    # check_function_exists(clock HAVE_CLOCK)
    # check_function_exists(time HAVE_TIME)

    # Check if Solaris-style gethrvtime() is available
    # check_function_exists(gethrvtime HAVE_GETHRVTIME)
    #
    # until here

    # necessary and required modules checked, ready to generate config.h
    configure_file(${CMAKE_SOURCE_DIR}/bnlib/bnconfig.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/bnconfig.h)
    MESSAGE(STATUS "Using internal (standalone) crypto functions")

endif()

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
            set(LIBS ${LIBS} -lsqlcipher)
            MESSAGE(STATUS "Using SQlCipher based ZRTP cache")
            add_definitions(-DSQL_CIPHER -DSQLITE_HAS_CODEC)
        else()
            message(FATAL_ERROR "SQLCipher library not found")
        endif()
    else()
        MESSAGE(STATUS "Using file based ZRTP cache")
    endif()
endif()

# necessary and required modules checked, ready to generate config.h in top-level build directory
configure_file(config.h.cmake ${CMAKE_BINARY_DIR}/config.h)

add_definitions(-g -O2 -fno-strict-aliasing ${LOG_MAX_LEVEL})
if(CMAKE_COMPILER_IS_GNUCXX)
    add_definitions(-DNEW_STDCPP)
endif()

if (UNITTESTS)
    add_definitions(-DUNITTESTS)
endif()
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -std=c++11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

if (AXO)
    add_definitions(-DAXO_SUPPORT)
endif()

if (SIDH)
    add_definitions(${SIDH_ARCHITECTURE} ${USE_GENERIC} -D__LINUX__)

    ## The common SIDH sources
    set(sidh751_src
            ${CMAKE_SOURCE_DIR}/cryptcommon/sidhp751/ec_isogeny.c
            ${CMAKE_SOURCE_DIR}/cryptcommon/sidhp751/fpx.c
            ${CMAKE_SOURCE_DIR}/cryptcommon/sidhp751/kex.c
            ${CMAKE_SOURCE_DIR}/cryptcommon/sidhp751/SIDH.c
            ${CMAKE_SOURCE_DIR}/cryptcommon/sidhp751/SIDH_setup.c
            ${CMAKE_SOURCE_DIR}/cryptcommon/sidhp751/keymanagement/SidhKeyManagement.cpp)

    ## Use generic portable variant
    # NOTE: see client specific CMakeLists.txt setting the properties for the *.S files
    if (SIDH_GENERIC)
        set (sidh751_extra_src ${CMAKE_SOURCE_DIR}/cryptcommon/sidhp751/generic/fp_generic.c)
    elseif(SIDH_X64)
        set(sidh751_extra_src ${CMAKE_SOURCE_DIR}/cryptcommon/sidhp751/AMD64/fp_x64.c
                ${CMAKE_SOURCE_DIR}/cryptcommon/sidhp751/AMD64/fp_x64_asm.S)
    elseif(SIDH_ARM64)
        set (sidh751_extra_src ${CMAKE_SOURCE_DIR}/cryptcommon/sidhp751/ARM64/fp_arm64.c
                ${CMAKE_SOURCE_DIR}/cryptcommon/sidhp751/ARM64/fp_arm64_asm.S)
    endif()
    set (has_sidh TRUE)
endif()

include_directories(BEFORE ${CMAKE_BINARY_DIR})
include_directories (${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/zrtp)

if(CRYPTO_STANDALONE)
    add_definitions(-DSUPPORT_NON_NIST)
    include_directories (${CMAKE_SOURCE_DIR}/bnlib)
endif()

if (SDES AND NOT CCRTP)
    set (sdes_src ${CMAKE_SOURCE_DIR}/zrtp/ZrtpSdesStream.cpp)
endif()

# **** The following source files are common for all clients ****
#
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
    ${CMAKE_SOURCE_DIR}/zrtp/ZrtpTextData.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/ZrtpConfigure.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/ZrtpCWrapper.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/Base32.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/EmojiBase32.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/zrtpB64Encode.c
    ${CMAKE_SOURCE_DIR}/zrtp/zrtpB64Decode.c
    ${CMAKE_SOURCE_DIR}/common/icuUtf8.c
    ${CMAKE_SOURCE_DIR}/common/osSpecifics.c
    ${CMAKE_SOURCE_DIR}/logging/Logger.cpp
    ${CMAKE_SOURCE_DIR}/logging/ZrtpLogging.cpp
    ${sdes_src})

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
    ${CMAKE_SOURCE_DIR}/zrtp/crypto/skeinMac256.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/crypto/skein256.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/crypto/skeinMac384.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/crypto/skein384.cpp)

set(zrtp_crypto_src
    ${CMAKE_SOURCE_DIR}/zrtp/crypto/zrtpDH.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/crypto/hmac256.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha256.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/crypto/hmac384.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha384.cpp

    ${CMAKE_SOURCE_DIR}/zrtp/crypto/aesCFB.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/crypto/twoCFB.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha2.c)

if (NOT SQLITE AND NOT SQLCIPHER)
    set(zrtp_src ${zrtp_src_no_cache}
        ${CMAKE_SOURCE_DIR}/zrtp/ZIDCacheFile.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZIDRecordFile.cpp)
else()
    set(zrtp_src ${zrtp_src_no_cache}
        ${CMAKE_SOURCE_DIR}/zrtp/ZIDCacheDb.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/ZIDRecordDb.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/zrtpCacheSqliteBackend.c)

endif()

if (CCRTP)
    add_subdirectory(clients/ccrtp)
    add_subdirectory(demo)
endif()

if (TIVI)
    add_subdirectory(clients/tivi)
endif()

if (CORE_LIB)
    add_subdirectory(clients/no_client)
endif()

if (WEBRTC)
    add_subdirectory(clients/webrtc)
endif()

##very usefull for macosx, specially when using gtkosx bundler
if(APPLE)
    if (NOT CMAKE_INSTALL_NAME_DIR)
        set(CMAKE_INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE STRING "CMAKE_INSTALL_NAME_DIR set for macosx" )
    endif (NOT CMAKE_INSTALL_NAME_DIR)
endif(APPLE)
