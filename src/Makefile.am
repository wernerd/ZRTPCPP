# Copyright (C) 2006 Werner Dittmann.

lib_LTLIBRARIES = libzrtpcpp.la
# libzrtpcpp_la_LIBADD = @LIBS@

# http://www.gnu.org/software/libtool/manual.html

if ZRTP_OPENSSL
zrtp_src_o =    libzrtpcpp/crypto/openssl/ZrtpDH.cxx \
		libzrtpcpp/crypto/openssl/hmac256.cxx \
		libzrtpcpp/crypto/openssl/sha256.cxx \
		libzrtpcpp/crypto/openssl/InitializeOpenSSL.cxx
endif

if ZRTP_GCRYPT
zrtp_src_g =	libzrtpcpp/crypto/gcrypt/gcryptZrtpDH.cxx \
		libzrtpcpp/crypto/gcrypt/gcrypthmac256.cxx \
		libzrtpcpp/crypto/gcrypt/gcryptsha256.cxx \
		libzrtpcpp/crypto/gcrypt/InitializeGcrypt.cxx
endif



libzrtpcpp_la_SOURCES = ZIDFile.cxx \
		ZIDRecord.cxx \
		ZRtp.cxx \
		ZrtpPacketCommit.cxx \
		ZrtpPacketConf2Ack.cxx \
		ZrtpPacketConfirm.cxx \
		ZrtpPacketDHPart.cxx \
		ZrtpPacketGoClear.cxx \
		ZrtpPacketClearAck.cxx \
		ZrtpPacketError.cxx \
		ZrtpPacketHelloAck.cxx \
		ZrtpPacketHello.cxx \
		ZrtpStateClass.cxx \
		ZrtpTextData.cxx \
		ZrtpQueue.cpp \
		Base32.cxx $(zrtp_src_g) $(zrtp_src_o)

SUBDIRS = libzrtpcpp libzrtpcpp/crypto