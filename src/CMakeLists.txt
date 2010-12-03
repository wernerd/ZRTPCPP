cmake_minimum_required (VERSION 2.6)

# add_subdirectory(libzrtpcpp)
# add_subdirectory(libzrtpcpp/crypto)

include_directories (${CMAKE_CURRENT_SOURCE_DIR})

set(gcrypt_src
    libzrtpcpp/crypto/gcrypt/gcryptZrtpDH.cxx 
    libzrtpcpp/crypto/gcrypt/gcrypthmac256.cxx 
    libzrtpcpp/crypto/gcrypt/gcryptsha256.cxx 
    libzrtpcpp/crypto/gcrypt/gcrypthmac384.cxx 
    libzrtpcpp/crypto/gcrypt/gcryptsha384.cxx 
    libzrtpcpp/crypto/gcrypt/gcryptAesCFB.cpp 
    libzrtpcpp/crypto/gcrypt/InitializeGcrypt.cxx)

set(openssl_src 
    libzrtpcpp/crypto/openssl/ZrtpDH.cxx
    libzrtpcpp/crypto/openssl/hmac256.cxx
    libzrtpcpp/crypto/openssl/sha256.cxx 
    libzrtpcpp/crypto/openssl/hmac384.cxx
    libzrtpcpp/crypto/openssl/sha384.cxx
    libzrtpcpp/crypto/openssl/AesCFB.cpp
    libzrtpcpp/crypto/openssl/InitializeOpenSSL.cxx)

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
    ZIDFile.cxx
    ZIDRecord.cxx
    ZRtp.cxx
    ZrtpCrc32.cxx
    ZrtpPacketCommit.cxx
    ZrtpPacketConf2Ack.cxx
    ZrtpPacketConfirm.cxx
    ZrtpPacketDHPart.cxx
    ZrtpPacketGoClear.cxx
    ZrtpPacketClearAck.cxx
    ZrtpPacketHelloAck.cxx
    ZrtpPacketHello.cxx
    ZrtpPacketError.cxx
    ZrtpPacketErrorAck.cpp
    ZrtpPacketPingAck.cxx
    ZrtpPacketPing.cxx
    ZrtpStateClass.cxx
    ZrtpTextData.cxx
    ZrtpConfigure.cxx
    ZrtpCWrapper.cpp
    Base32.cxx)

set(zrtpcpp_src ${zrtp_src} ${ccrtp_src} ${crypto_src})

add_library(zrtpcpp SHARED ${zrtpcpp_src})
set_target_properties(zrtpcpp PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
target_link_libraries(zrtpcpp ${LIBS})

src_distribution_init()
add_src_dist_files(${zrtp_src} ZrtpQueue.cpp ${gcrypt_src} ${openssl_src})
add_src_dist_dirs(libzrtpcpp)

add_subdirectory(libzrtpcpp)

install(TARGETS zrtpcpp DESTINATION ${LIBDIRNAME})

