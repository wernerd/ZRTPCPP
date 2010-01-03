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
set (VERSION 1.5.0)
set (SOVERSION 1.5)

# set to true for debug and trace during CMakeLists development
set(CMAKE_VERBOSE_MAKEFILE FALSE)

# find project specific modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

# include most of the fine stuff we need 
include(FindGcryptConfig)
include(FindPkgConfig)
include(CheckLibraryExists)
include(CheckIncludeFiles)
include(FindArch)
include(AutoArgs)

# check the -Denable-ccrtp setting, defaults to true
enable_arg(ccrtp true "Enable GNU ccRTP support for GNU ZRTP")
args_help()

# setup the Thread include and lib
find_package(Threads)
if(CMAKE_HAVE_PTHREAD_H)
  set(HAVE_PTHREAD_H TRUE)
endif()
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

if(enable_ccrtp)
  pkg_check_modules(CCRTP libccrtp1>=1.5.0)
  set (LIBS ${LIBS} ${CCRTP_LDFLAGS})
endif()

# now get info about crypto libraries
gcr_check(GCRYPT gcrypt)
if(GCRYPT_FOUND)
  check_include_files(gcrypt.h HAVE_GCRYPT_H)
  set(LIBS ${LIBS} ${GCRYPT_LIBRARIES})
  set(BUILD_REQ "libgcrypt-devel")
  set(CRYPTOBACKEND="")
  set(PACKAGE_REQ "libgcrypt")
else()
  pkg_check_modules(OPENSSL libcrypto>=0.9.8)
  if (OPENSSL_FOUND) 
    check_include_files(openssl/bn.h HAVE_OPENSSL_BN_H)
    check_include_files(openssl/aes.h HAVE_OPENSSL_AES_H)
    check_include_files(openssl/sha.h HAVE_OPENSSL_SHA_H)
    check_library_exists(crypto EVP_CipherInit_ex "" HAVE_SSL_CRYPT)
    set(LIBS ${LIBS} -lcrypto)
    set(CRYPTOBACKEND "libcrypto >= 0.9.8")
    set(BUILD_REQ "libopenssl-devel >= 0.9.8")
    set(PACKAGE_REQ "libopenssl >= 0.9.8")
  else()
    message(FATAL_ERROR "No crypto library found")
  endif()
endif()

check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(string.h HAVE_STRING_H)

# necessary and required modules checked, ready to generate config.h
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# the following set(...) commands are only to have backward
# compatibility with autoconf stuff to generate the pc file
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${prefix}/bin)
set(libdir ${prefix}/lib)
set(includedir ${prefix}/include)
set(PACKAGE pkgconfig)
configure_file(libzrtpcpp.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/libzrtpcpp.pc @ONLY)

configure_file(libzrtpcpp.spec.cmake ${CMAKE_CURRENT_BINARY_DIR}/libzrtpcpp.spec @ONLY)

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR}/src)

include(SourceDistribution)
src_distribution_init()
add_src_dist_files(AUTHORS COPYING INSTALL NEWS README ChangeLog libzrtpcpp.pc.cmake config.h.cmake libzrtpcpp.spec.cmake)

add_definitions(-g)
if(CMAKE_COMPILER_IS_GNUCXX)
  add_definitions(-Wno-long-long -Wno-char-subscripts)
  add_definitions(-Wall -ansi -pedantic)
endif()

add_subdirectory(src)
add_src_dist_dirs(src)

add_subdirectory(demo)
add_src_dist_dirs(demo)

########### install files ###############
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libzrtpcpp.pc DESTINATION ${LIBDIRNAME}/pkgconfig)

########### Add uninstall target ###############
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
   IMMEDIATE @ONLY)
add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake") 

####### define target to build RPM 
include(UseRPMTools)
if(RPMTools_FOUND)
  RPMTools_ADD_RPM_TARGETS(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/libzrtpcpp.spec.cmake)
endif()
