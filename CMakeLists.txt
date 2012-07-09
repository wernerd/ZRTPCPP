# Copyright (C) 2009 Werner Dittman
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

SET(CPACK_PACKAGE_VERSION_MAJOR 2)
SET(CPACK_PACKAGE_VERSION_MINOR 3)
SET(CPACK_PACKAGE_VERSION_PATCH 0)

set (VERSION 2.3.0)
set (SOVERSION 2)
set (PACKAGE libzrtpcpp)

if(MSVC60)
    set(BUILD_STATIC ON CACHE BOOL "static linking only" FORCE)
    MARK_AS_ADVANCED(BUILD_STATIC)
else()
    option(BUILD_STATIC "Set to OFF to build shared libraries" OFF)
endif()

# set to true for debug and trace during CMakeLists development
set(CMAKE_VERBOSE_MAKEFILE TRUE)

MESSAGE( STATUS "Configuring GNU ${PROJECT_NAME} ${VERSION}...")

# include most of the fine stuff we need
include(cmake/Modules/FindGcryptConfig.cmake)
include(FindPkgConfig)
include(CheckLibraryExists)
include(CheckIncludeFiles)
include(CheckFunctionExists)
include(cmake/Modules/AutoArgs.cmake)

# check the -Denable-ccrtp setting, defaults to true
enable_arg(ccrtp true "Enable GNU ccRTP support for GNU ZRTP")
enable_arg(crypto_standalone true)
args_help()

if (enable_crypto_standalone)
    set(CRYPTO_STANDALONE TRUE)
endif()

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

if (NOT enable_crypto_standalone)
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
      include_directories(${OPENSSL_INCLUDE_DIRS}) #update includes directory from pkg-config
  else()
      message(FATAL_ERROR "No crypto library found")
  endif()
else()
    # For crypto standalone mode we need to configure the bnlib. In a first step
    # without the tests and demos.
    check_include_files(stdint.h HAVE_STDINT_H)
    check_include_files(stdint.h HAVE_ASSERT_H)
    check_include_files(limits.h HAVE_LIMITS_H)
    check_include_files(stdlib.h HAVE_STDLIB_H)
    check_include_files(string.h HAVE_STRING_H)

    check_function_exists(memmove HAVE_MEMMOVE)
    check_function_exists(memcpy HAVE_MEMCPY)

    # below only if we compile the tests
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
endif()

check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(string.h HAVE_STRING_H)

# necessary and required modules checked, ready to generate config.h in top-level build directory
configure_file(config.h.cmake ${CMAKE_BINARY_DIR}/config.h)

add_definitions(-g -O2 -fno-strict-aliasing)
if(CMAKE_COMPILER_IS_GNUCXX)
  add_definitions(-Wno-long-long -Wno-char-subscripts)
  add_definitions(-Wall -ansi -pedantic)
  add_definitions(-DNEW_STDCPP)
endif()

if (enable_ccrtp)
    add_subdirectory(clients/ccrtp)
    add_subdirectory(demo)
endif()

##very usefull for macosx, specially when using gtkosx bundler
if(APPLE)
    if (NOT CMAKE_INSTALL_NAME_DIR)
        set(CMAKE_INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE STRING "CMAKE_INSTALL_NAME_DIR set for macosx" )
    endif (NOT CMAKE_INSTALL_NAME_DIR)
endif(APPLE)
