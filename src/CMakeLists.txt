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

set(ccrtp_src ZrtpQueue.cpp)

set(zrtp_src
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
    Base32.cxx)

set(zrtpcpp_src ${zrtp_src} ${ccrtp_src} ${crypto_src})

add_library(zrtpcpp SHARED ${zrtpcpp_src})
set_target_properties(zrtpcpp PROPERTIES VERSION 1.5.0 SOVERSION 1.5)
message("src libraries: ${LIBS}")
target_link_libraries(zrtpcpp ${LIBS})

src_distribution_init()
add_src_dist_files(${zrtp_src} ZrtpQueue.cpp ${gcrypt_src} ${openssl_src})
add_src_dist_dirs(libzrtpcpp)

add_subdirectory(libzrtpcpp)

install(TARGETS zrtpcpp DESTINATION lib${LIB64})

########### install files ###############

#original Makefile.am contents follow:

## Copyright (C) 2006 Werner Dittmann.
#
#LT_VERSION=@LT_CCXX_VERSION@
#RELEASE = $(LT_VERSION) -release $(LT_RELEASE)
##RELEASE = $(LT_VERSION)
#lib_LTLIBRARIES = libzrtpcpp.la
## libzrtpcpp_la_LIBADD = @LIBS@
#
#libzrtpcpp_la_LDFLAGS = $(RELEASE)
#
## http://www.gnu.org/software/libtool/manual.html
#
#if CCRTP_SUPPORT
#ccrtp_src = ZrtpQueue.cpp
#endif
#
