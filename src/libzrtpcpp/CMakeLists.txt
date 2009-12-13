
set(src_distribute 
    Base32.h ZrtpPacketBase.h ZrtpPacketDHPart.h ZrtpPacketHello.h
    ZIDFile.h ZrtpPacketClearAck.h ZrtpStateClass.h ZrtpCrc32.h
    ZIDRecord.h ZrtpPacketCommit.h ZrtpPacketGoClear.h ZrtpStates.h
    ZrtpPacketConf2Ack.h zrtpPacket.h ZrtpTextData.h ZrtpCodes.h ZrtpConfigure.h
    ZRtp.h ZrtpPacketConfirm.h ZrtpPacketHelloAck.h ZrtpPacketError.h
    ZrtpPacketErrorAck.h ZrtpPacketPingAck.h ZrtpPacketPing.h ZrtpUserCallback.h
    ZrtpQueue.h ZrtpCallback.h zrtpccrtp.h TimeoutProvider.h)

set(ccrtp_inst
    ZrtpQueue.h
    ZrtpCallback.h
    zrtpccrtp.h
    TimeoutProvider.h)

install(FILES ZrtpCodes.h ZrtpConfigure.h ZrtpUserCallback.h ${ccrtp_inst} DESTINATION include/libzrtpcpp)

include(SourceDistribution)
src_distribution_init()
add_src_dist_dirs(crypto)
add_src_dist_files(${src_distribute})

add_subdirectory(crypto)
