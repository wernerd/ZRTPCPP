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

SET(CPACK_PACKAGE_VERSION_MAJOR 4)
SET(CPACK_PACKAGE_VERSION_MINOR 7)
SET(CPACK_PACKAGE_VERSION_PATCH 0)

set (VERSION 4.7.0)
set (SOVERSION 4)

# Define supported command line parameters.
#
# Example to build the tivi client: cmake -DTIVI=true ..
# Without any options cmake generates libzrtpcpp for use with GNU ccRTP
#
option(CCRTP "Build library to use with GNU ccRTP." OFF)
option(CORE_LIB "Build core library only, no spcific client support." OFF)
option(CRYPTO_STANDALONE "Use embedded crypto and big number modules." ON)
option(TIVI "Build library for the tivi client, implies '-DCRYPTO_STNDALONE=true'." OFF)
option(SQLITE "Use SQLite DB as backend for ZRTP cache." OFF)
option(NO_CACHE "Use an always empty cache ZRTP - for testing mainly." OFF)
option(SQLCIPHER "Use SQLCipher DB as backend for ZRTP cache." OFF)
option(SDES "Include SDES when not building for CCRTP." OFF)
option(AXO "Include Axolotl support when not building for CCRTP." OFF)

option(ANDROID "Generate Android makefiles (Android.mk)" OFF)
option(JAVA "Generate Java support files (requires JDK and SWIG)" OFF)

#
# If your project needs SAS relay support (refer to RFC6189 chapter 7.3) then
# uncomment the following add_definitiones statement. Make sure you understand
# the consequences.
## add_definitions(-DZRTP_SAS_RELAY_SUPPORT)

# **** Check what and how to build ****
#
if (CCRTP AND TIVI AND CORE_LIB)
    MESSAGE(FATAL_ERROR "Cannot build more than one client at once. Use different build directories.")
endif()

if (SQLITE AND SQLCIPHER)
    MESSAGE(FATAL_ERROR "Cannot build with multiple DB backends.")
endif()

if ((SQLITE OR SQLCIPHER) AND NO_CACHE)
    MESSAGE(FATAL_ERROR "Cannot build with DB backends and empty cache backend.")
endif()

if (CCRTP)
    set (PACKAGE libzrtpcpp)
    set(zrtplibName zrtpcpp)
elseif (TIVI)
    set (PACKAGE libzrtptivi)
    set(zrtplibName zrtptivi)
    set(CRYPTO_STANDALONE true)
    set(SQLCIPHER true)
    set(SDES true) 
elseif (CORE_LIB)
    set (PACKAGE libzrtpcore)
    set(zrtplibName zrtpcppcore)
else()
    MESSAGE(WARNING "No client defined, building for GNU ccRTP.")
    set (PACKAGE libzrtpcpp)
    set(CCRTP true)
    set(zrtplibName zrtpcpp)
endif()


if(MSVC60)
    set(BUILD_STATIC ON CACHE BOOL "static linking only" FORCE)
    MARK_AS_ADVANCED(BUILD_STATIC)
else()
    option(BUILD_STATIC "Set to OFF to build shared libraries" OFF)
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
    elseif(NO_CACHE)
        MESSAGE(STATUS "Building with always empty cache backend")
    else()
        MESSAGE(STATUS "Using file based ZRTP cache")
    endif()
endif()

# necessary and required modules checked, ready to generate config.h in top-level build directory
configure_file(config.h.cmake ${CMAKE_BINARY_DIR}/config.h)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -std=c++11 -g -O2 -fno-strict-aliasing -Wno-unknown-pragmas")

if(CMAKE_COMPILER_IS_GNUCXX)
    add_definitions(-DNEW_STDCPP)
endif()


if (AXO)
    add_definitions(-DAXO_SUPPORT)
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

# **** The following source files a common for all clients ****
#
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
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpSdesStream.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpSdesStream.h
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
        ${CMAKE_SOURCE_DIR}/zrtp/ZrtpTextData.cpp
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
        ${sdes_src} ${zrtp_src_include})

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

set(zrtp_crypto_includes
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/aesCFB.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/hmac256.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/hmac384.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha2.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha256.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha384.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/skein256.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/skein384.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/twoCFB.h
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/zrtpDH.h
        )

set(zrtp_standalone_crypto_src
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/zrtpDH.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/hmac256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/hmac384.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha384.cpp

        ${CMAKE_SOURCE_DIR}/zrtp/crypto/aesCFB.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/twoCFB.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha2.c
        ${zrtp_crypto_includes})

if (NOT SQLITE AND NOT SQLCIPHER)
    if (NO_CACHE)
        set(zrtp_src ${zrtp_src_no_cache}
                ${CMAKE_SOURCE_DIR}/zrtp/ZIDCacheEmpty.cpp
                ${CMAKE_SOURCE_DIR}/zrtp/ZIDRecordEmpty.cpp)

    else()
        set(zrtp_src ${zrtp_src_no_cache}
                ${CMAKE_SOURCE_DIR}/zrtp/ZIDCacheFile.cpp
                ${CMAKE_SOURCE_DIR}/zrtp/ZIDRecordFile.cpp)
    endif()
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

##very usefull for macosx, specially when using gtkosx bundler
if(APPLE)
    if (NOT CMAKE_INSTALL_NAME_DIR)
        set(CMAKE_INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE STRING "CMAKE_INSTALL_NAME_DIR set for macosx" )
    endif (NOT CMAKE_INSTALL_NAME_DIR)
endif(APPLE)
