# Copyright (C) 2006 Werner Dittmann.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AUTOMAKE_OPTIONS = no-dependencies dist-shar
ccxxincludedir=$(includedir)/libzrtpcpp

if CCRTP_SUPPORT
ccrtp_header = ZrtpQueue.h ZrtpUserCallback.h TimeoutProvider.h  zrtpccrtp.h
endif

ccxxinclude_HEADERS = Base32.h    ZrtpPacketBase.h      ZrtpPacketDHPart.h    ZrtpPacketHello.h \
		  ZIDFile.h       ZrtpPacketClearAck.h  ZrtpStateClass.h      ZrtpCrc32.h \
		  ZIDRecord.h     ZrtpPacketCommit.h    ZrtpPacketGoClear.h   ZrtpStates.h \
		  ZrtpCallback.h  ZrtpPacketConf2Ack.h  zrtpPacket.h          ZrtpTextData.h \
		  ZRtp.h          ZrtpPacketConfirm.h   ZrtpPacketHelloAck.h  $(ccrtp_header)



# kdoc:
#	kdoc -f html -d $(KDOC_DIR) -L$(KDOC_DIR) -n ccrtp $(ccxxinclude_HEADERS)
