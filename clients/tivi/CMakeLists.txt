#
# Copyright (c) 2019 Silent Circle.  All rights reserved.
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
#
# @author Werner Dittmann <Werner.Dittmann@t-online.de>

cmake_minimum_required (VERSION 3.18)

# setup the Thread include and lib
find_package(Threads)
if(CMAKE_HAVE_PTHREAD_H)
  set(HAVE_PTHREAD_H TRUE)
endif()
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

include_directories (${CMAKE_CURRENT_SOURCE_DIR})

set(zrtp_tivi_src
        ${CMAKE_CURRENT_SOURCE_DIR}/CtZrtpSession.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/CtZrtpStream.cpp)

set(srtp_src
        ${CMAKE_CURRENT_SOURCE_DIR}/../../srtp/CryptoContext.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../srtp/CryptoContextCtrl.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../srtp/SrtpHandler.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../srtp/crypto/hmac.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../srtp/crypto/SrtpSymCrypto.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../srtp/crypto/botan/hmac.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../srtp/crypto/botan/macSkein.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../srtp/crypto/botan/SrtpSymCrypto.cpp)

set(zrtpcpp_src ${zrtp_src} ${zrtp_tivi_src} ${zrtp_botan_crypto_src} ${srtp_src})

# for the Thread classes etc. -  Need to cross-check with Java build in case of static build.
# Beware of undefined symbols - set correct library build parameters in case of shared lib
add_compile_definitions(LINUX NANO_SECOND_SLEEP)

if(BUILD_STATIC AND NOT BUILD_SHARED)
    set(LIBRARY_BUILD_TYPE STATIC)
else()
    set(LIBRARY_BUILD_TYPE SHARED)
endif()

set(buildInfo "${VERSION}:${GIT_COMMIT}:${CMAKE_SYSTEM_PROCESSOR}")
if(NOT EMBEDDED)

    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/buildInfo.h
            COMMAND ${CMAKE_COMMAND} -E echo \"constexpr char zrtpBuildInfo[] = \\\"${buildInfo}\\\"\;\" > ${CMAKE_CURRENT_BINARY_DIR}/buildInfo.h)

    add_compile_definitions(_WITHOUT_TIVI_ENV)
    add_compile_definitions(AXO_SUPPORT)

    add_library(${zrtplibName} ${LIBRARY_BUILD_TYPE} ${zrtpcpp_src} ${CMAKE_CURRENT_BINARY_DIR}/buildInfo.h)
    add_dependencies(${zrtplibName} ${botanlib})
    target_include_directories(${zrtplibName} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    set_target_properties(${zrtplibName} PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
    target_link_libraries(${zrtplibName} ${botanlib} ${sidhLibNameStatic} ${LIBS})

    # **** Test programs ****
    #
    add_executable(testdriver testdriver.cpp)
    target_link_libraries(testdriver ${zrtplibName})
    add_dependencies(testdriver ${zrtplibName})

    add_custom_command(TARGET ${zrtplibName} POST_BUILD COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_CURRENT_BINARY_DIR}/buildInfo.h)
endif()


# **** Setup packing environment ****
#
# The difference is that CMAKE_PROJECT_NAME is the name from the last project call from the root
# CMakeLists.txt, while PROJECT_NAME is from the last project call, regardless from the location
# of the file containing the command.
if(${PROJECT_NAME} STREQUAL ${CMAKE_PROJECT_NAME})
    include(${CMAKE_SOURCE_DIR}/cmake/Modules/GeneratePackage.cmake)
    set(exclude
            "/clients/webrtc/"
            "/clients/ccrtp")

    GENERATE_PACKAGING(${PACKAGE} ${VERSION} "${exclude}")
endif()

if(ANDROID)
    if (SQLITE AND NOT SQLCIPHER)
        set (sqlite_src ${CMAKE_CURRENT_SOURCE_DIR}/android/jni/sqlite3/sqlite3.c)
        set (sql_include ${CMAKE_CURRENT_SOURCE_DIR}/android/jni/sqlite3)
    endif()
    if (SQLCIPHER)
        if ("${SQL_CIPHER_INCLUDE}" STREQUAL "")
            MESSAGE(WARNING "SQL_CIPHER_INCLUDE not set, using internal sqlite3.h header file.")
            set(sqlcipher_include ${CMAKE_CURRENT_SOURCE_DIR}/android/jni/sqlcipher)
        else()
            set(sqlcipher_include ${SQL_CIPHER_INCLUDE})
        endif ()
        add_compile_definitions(SQL_CIPHER SQLITE_HAS_CODEC)
    endif()

    ## Build ANDROID for tivi client: SilentPhone with tivi support
    ## remove _WITHOUT_TIVI_ENV if you compile for/with Tivi modules, maybe build static
    # and include this into Tivi shared lib in the second step.
    ## add_compile_definitions(_WITHOUT_TIVI_ENV)
    add_compile_definitions(AXO_SUPPORT)

    add_library(${zrtplibName} STATIC ${zrtpcpp_src} ${sqlite_src} ${CMAKE_CURRENT_BINARY_DIR}/buildInfo.h)
    add_dependencies(${zrtplibName} ${botanlib})
    target_include_directories(${zrtplibName}
            PRIVATE ${sqlcipher_include} ${CMAKE_CURRENT_BINARY_DIR}
            PUBLIC ${ZRTP_TOP_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${ZRTP_TOP_SOURCE_DIR}/zrtp
            ${ZRTP_TOP_SOURCE_DIR}/srtp
            ${ZRTP_TOP_SOURCE_DIR}/botancrypto/${botan_all})
    target_link_libraries(${zrtplibName} ${botanlib} ${sidhLibNameStatic})

    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/buildInfo.h
            COMMAND ${CMAKE_COMMAND} -E echo \"constexpr char zrtpBuildInfo[] = \\\"${buildInfo}\\\"\;\" > ${CMAKE_CURRENT_BINARY_DIR}/buildInfo.h)

    add_custom_command(TARGET ${zrtplibName} POST_BUILD COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_CURRENT_BINARY_DIR}/buildInfo.h)
endif()
