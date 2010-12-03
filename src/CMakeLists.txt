cmake_minimum_required (VERSION 2.6)

# add_subdirectory(libzrtpcpp)
# add_subdirectory(libzrtpcpp/crypto)

include_directories (${CMAKE_CURRENT_SOURCE_DIR})

set(gcrypt_src
    libzrtpcpp/crypto/gcrypt/gcryptZrtpDH.cpp 
    libzrtpcpp/crypto/gcrypt/gcrypthmac256.cpp 
    libzrtpcpp/crypto/gcrypt/gcryptsha256.cpp 
    libzrtpcpp/crypto/gcrypt/gcrypthmac384.cpp 
    libzrtpcpp/crypto/gcrypt/gcryptsha384.cpp 
    libzrtpcpp/crypto/gcrypt/gcryptAesCFB.cpp 
    libzrtpcpp/crypto/gcrypt/InitializeGcrypt.cpp)

set(openssl_src 
    libzrtpcpp/crypto/openssl/ZrtpDH.cpp
    libzrtpcpp/crypto/openssl/hmac256.cpp
    libzrtpcpp/crypto/openssl/sha256.cpp 
    libzrtpcpp/crypto/openssl/hmac384.cpp
    libzrtpcpp/crypto/openssl/sha384.cpp
    libzrtpcpp/crypto/openssl/AesCFB.cpp
    libzrtpcpp/crypto/openssl/InitializeOpenSSL.cpp)

if (GCRYPT_FOUND)
    set(crypto_src ${gcrypt_src})
endif()

if (OPENSSL_FOUND)
    set(crypto_src ${openssl_src})
endif()

if(enable_ccrtp)
  set(ccrtp_src ZrtpQueue.cpp)
endif()

set(zrtp_src 
    ZrtpCallbackWrapper.cpp
    ZIDFile.cpp
    ZIDRecord.cpp
    ZRtp.cpp
    ZrtpCrc32.cpp
    ZrtpPacketCommit.cpp
    ZrtpPacketConf2Ack.cpp
    ZrtpPacketConfirm.cpp
    ZrtpPacketDHPart.cpp
    ZrtpPacketGoClear.cpp
    ZrtpPacketClearAck.cpp
    ZrtpPacketHelloAck.cpp
    ZrtpPacketHello.cpp
    ZrtpPacketError.cpp
    ZrtpPacketErrorAck.cpp
    ZrtpPacketPingAck.cpp
    ZrtpPacketPing.cpp
    ZrtpStateClass.cpp
    ZrtpTextData.cpp
    ZrtpConfigure.cpp
    ZrtpCWrapper.cpp
    Base32.cpp)

set(zrtpcpp_src ${zrtp_src} ${ccrtp_src} ${crypto_src})

add_library(zrtpcpp SHARED ${zrtpcpp_src})
set_target_properties(zrtpcpp PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
target_link_libraries(zrtpcpp ${LIBS})

src_distribution_init()
add_src_dist_files(${zrtp_src} ZrtpQueue.cpp ${gcrypt_src} ${openssl_src})
add_src_dist_dirs(libzrtpcpp)

add_subdirectory(libzrtpcpp)

install(TARGETS zrtpcpp DESTINATION ${LIBDIRNAME})

