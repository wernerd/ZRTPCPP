cmake_minimum_required (VERSION 2.6)

#to make sure includes are first taken - it contains config.h
include_directories(BEFORE ${CMAKE_BINARY_DIR})
include_directories (${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/zrtp)

# **** setup the various crypto interface implementations ***
# Twofish is a special case: its always a standalone modlue and thus
# not specific to a library.
# NOTE: the standalone modules live in the 'crypto'
if (GCRYPT_FOUND)
    set(crypto_src
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/gcrypt/gcryptZrtpDH.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/gcrypt/gcrypthmac256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/gcrypt/gcryptsha256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/gcrypt/gcrypthmac384.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/gcrypt/gcryptsha384.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/gcrypt/gcryptAesCFB.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/gcrypt/InitializeGcrypt.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/twoCFB.cpp)
endif()

if (OPENSSL_FOUND)
    set(crypto_src
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/openssl/zrtpDH.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/openssl/hmac256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/openssl/sha256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/openssl/hmac384.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/openssl/sha384.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/openssl/aesCFB.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/openssl/InitializeOpenSSL.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/twoCFB.cpp)
endif()

if (STANDALONE)
    set(crypto_src
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/zrtpDH.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/hmac256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha256.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/hmac384.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/sha384.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/aesCFB.cpp
        ${CMAKE_SOURCE_DIR}/zrtp/crypto/twoCFB.cpp)
endif()

set(cryptcommon_srcs
    ${CMAKE_SOURCE_DIR}/cryptcommon/twofish.c
    ${CMAKE_SOURCE_DIR}/cryptcommon/twofish_cfb.c)

set(zrtp_src
    ${CMAKE_CURRENT_SOURCE_DIR}/ZrtpQueue.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/ZrtpCallbackWrapper.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/ZIDFile.cpp
    ${CMAKE_SOURCE_DIR}/zrtp/ZIDRecord.cpp
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
    ${CMAKE_SOURCE_DIR}/zrtp/Base32.cpp)

set(zrtpcpp_src ${zrtp_src} ${crypto_src} ${cryptcommon_srcs})

if(BUILD_STATIC AND NOT BUILD_SHARED)
    set(LIBRARY_BUILD_TYPE STATIC)
else()
    set(LIBRARY_BUILD_TYPE SHARED)
endif()

add_library(${zrtplib} ${LIBRARY_BUILD_TYPE} ${zrtpcpp_src})
set_target_properties(${zrtplib} PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
target_link_libraries(${zrtplib} ${LIBS})

add_dependencies(${zrtplib} ccrtp)

# **** Setup packing environment ****
#
if(${PROJECT_NAME} STREQUAL ${CMAKE_PROJECT_NAME})
    include(${CMAKE_SOURCE_DIR}/cmake/Modules/GeneratePackage.cmake)

    GENERATE_PACKAGING(${PACKAGE} ${VERSION})
endif()

# **** Create the external files for RPM and pkgconfig ****
#
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${prefix}/bin)
set(libdir ${prefix}/${LIBDIRNAME})
set(includedir ${prefix}/include)
set(PACKAGE pkgconfig)

configure_file(${CMAKE_SOURCE_DIR}/libzrtpcpp.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/lib${zrtplib}.pc @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/libzrtpcpp.spec.cmake ${CMAKE_CURRENT_BINARY_DIR}/libzrtpcpp.spec @ONLY)

# **** install files ****
#
set(ccrtp_inst
    ${CMAKE_CURRENT_SOURCE_DIR}/ZrtpQueue.h
    ${CMAKE_CURRENT_SOURCE_DIR}/zrtpccrtp.h
    ${CMAKE_CURRENT_SOURCE_DIR}/TimeoutProvider.h)

install(FILES
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCodes.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpConfigure.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCallback.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpCWrapper.h
        ${CMAKE_SOURCE_DIR}/zrtp/libzrtpcpp/ZrtpUserCallback.h ${ccrtp_inst} DESTINATION include/libzrtpcpp)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/lib${zrtplib}.pc DESTINATION ${LIBDIRNAME}/pkgconfig)

install(TARGETS ${zrtplib} DESTINATION ${LIBDIRNAME})

if(${PROJECT_NAME} STREQUAL ${CMAKE_PROJECT_NAME})

    ########### Add uninstall target ###############
    configure_file("${CMAKE_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake" IMMEDIATE @ONLY)
    add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake")

endif()


