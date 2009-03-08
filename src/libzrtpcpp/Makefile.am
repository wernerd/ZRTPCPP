# Copyright (C) 2006-2009 Werner Dittmann.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AUTOMAKE_OPTIONS = no-dependencies dist-shar
zrtpincludedir=$(includedir)/libzrtpcpp

if CCRTP_SUPPORT
ccrtp_noinst = 
ccrtp_inst = ZrtpQueue.h ZrtpUserCallback.h zrtpccrtp.h TimeoutProvider.h
endif

zrtpinclude_HEADERS = ZrtpCodes.h ZrtpCallback.h $(ccrtp_inst)


noinst_HEADERS =  Base32.h        ZrtpPacketBase.h      ZrtpPacketDHPart.h    ZrtpPacketHello.h \
		  ZIDFile.h       ZrtpPacketClearAck.h  ZrtpStateClass.h      ZrtpCrc32.h \
		  ZIDRecord.h     ZrtpPacketCommit.h    ZrtpPacketGoClear.h   ZrtpStates.h \
		  ZrtpPacketConf2Ack.h  zrtpPacket.h    ZrtpTextData.h \
		  ZRtp.h          ZrtpPacketConfirm.h   ZrtpPacketHelloAck.h  ZrtpPacketError.h \
		  ZrtpPacketErrorAck.h  ZrtpPacketPingAck.h ZrtpPacketPing.h $(ccrtp_noinst)
