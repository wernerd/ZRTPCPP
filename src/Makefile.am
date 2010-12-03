# Copyright (C) 2006 Werner Dittmann.

LT_VERSION=@LT_CCXX_VERSION@
RELEASE = $(LT_VERSION) -release $(LT_RELEASE)
#RELEASE = $(LT_VERSION)
lib_LTLIBRARIES = libzrtpcpp.la
# libzrtpcpp_la_LIBADD = @LIBS@

libzrtpcpp_la_LDFLAGS = $(RELEASE)

# http://www.gnu.org/software/libtool/manual.html

if ZRTP_OPENSSL
zrtp_src_o =    libzrtpcpp/crypto/openssl/ZrtpDH.cpp \
		libzrtpcpp/crypto/openssl/hmac256.cpp \
		libzrtpcpp/crypto/openssl/sha256.cpp \
		libzrtpcpp/crypto/openssl/hmac384.cpp \
		libzrtpcpp/crypto/openssl/sha384.cpp \
		libzrtpcpp/crypto/openssl/AesCFB.cpp \
		libzrtpcpp/crypto/openssl/InitializeOpenSSL.cpp
endif

if ZRTP_GCRYPT
zrtp_src_g =	libzrtpcpp/crypto/gcrypt/gcryptZrtpDH.cpp \
		libzrtpcpp/crypto/gcrypt/gcrypthmac256.cpp \
		libzrtpcpp/crypto/gcrypt/gcryptsha256.cpp \
		libzrtpcpp/crypto/gcrypt/gcrypthmac384.cpp \
		libzrtpcpp/crypto/gcrypt/gcryptsha384.cpp \
		libzrtpcpp/crypto/gcrypt/gcryptAesCFB.cpp \
		libzrtpcpp/crypto/gcrypt/InitializeGcrypt.cpp
endif

if CCRTP_SUPPORT
ccrtp_src = ZrtpQueue.cpp
endif

libzrtpcpp_la_SOURCES = ZIDFile.cpp \
		ZIDRecord.cpp \
		ZRtp.cpp \
		ZrtpCrc32.cpp \
		ZrtpPacketCommit.cpp \
		ZrtpPacketConf2Ack.cpp \
		ZrtpPacketConfirm.cpp \
		ZrtpPacketDHPart.cpp \
		ZrtpPacketGoClear.cpp \
		ZrtpPacketClearAck.cpp \
		ZrtpPacketHelloAck.cpp \
		ZrtpPacketHello.cpp \
		ZrtpPacketError.cpp \
		ZrtpPacketErrorAck.cpp \
		ZrtpPacketPingAck.cpp \
		ZrtpPacketPing.cpp \
		ZrtpStateClass.cpp \
		ZrtpTextData.cpp \
		ZrtpConfigure.cpp \
		ZrtpCWrapper.cpp \
		ZrtpCallbackWrapper.cpp \
		Base32.cpp $(ccrtp_src) $(zrtp_src_g) $(zrtp_src_o)

SUBDIRS = libzrtpcpp libzrtpcpp/crypto