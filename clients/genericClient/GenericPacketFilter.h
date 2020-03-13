//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Created by werner on 06.03.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#ifndef LIBZRTPCPP_GENERICPACKETFILTER_H
#define LIBZRTPCPP_GENERICPACKETFILTER_H

/**
 * @file
 * @brief Generic packet filter
 * @ingroup ZRTP
 * @{
 */

#include <cstdint>
#include <cstddef>
#include <functional>
#include <mutex>

#include "config.h"
#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpConfigure.h>

/**
 * @brief Packet filter and implementation of ZRTP callback functions.
 */
class GenericPacketFilter : public ZrtpCallback, public std::enable_shared_from_this<GenericPacketFilter> {

public:
    /**
     * @brief Result of packet filter function.
     */
    enum FilterResult {
        Processed,              //!< ZRTP processed the data, no further processing
        Discarded,              //!< Filter discarded the data due to some error, no further processing
        NotProcessed            //!< Not a ZRTP packet, caller should process data,
    };

    /**
     * @brief Result of packet data check function.
     */
    enum DataCheckResult {
        Process,              //!< This is valid ZRTP data, process it
        Discard,              //!< Discard the data: no valid transport protocol packet, but also not a ZRTP packet: no further processing
        DontProcess           //!< Not a ZRTP packet, caller should process data,
    };

    /**
     * @brief Filter type.
     *
     * Defines which type of ZRTP stream this filter handles, either a master or a secondary stream. Refer
     * to multi-stream mode, RFC 6189, section 4.4.3.
     *
     * Usually the Audio stream is the master.
     */
     enum FilterType {
         Unknown,
         MasterStream,
         SecondaryStream
     };

     /**
      * @brief Return codes used by several functions.
      *
      * Error codes are always negative, never 0.
      */
     enum PacketFilterReturnCodes {
         Success = 1,
         NoConfiguration = -10,

     };
     /**
      * @brief Returned by the `PrepareToSendFunction` implementation.
      */
    struct ProtocolData {
        std::shared_ptr<void> ptr = nullptr;    //!< Pointer to prepared data
        int32_t length = 0;                     //!< Length of prepare data in bytes
    };

    /**
     * @brief Signature of ZRTP packet check function.
     *
     * This functions checks if `packetData` contains valid ZRTP data and returns the
     * offset to the first byte of the ZRTP packet if it's valid ZRTP data. If this is
     * not a valid ZRTP packet the function must return either `DontProcess` or `Discard`
     * and must not change the `offset` parameter.
     *
     * For an RTP packet this is the first byte after the fixed length RTP
     * header (12 bytes). Other transport protocols may have other offsets into
     * the data.
     *
     * This `GenericPacketFilter` provides a ready-to-use static function to check ZRTP
     * wrapped in an RTP packet.
     *
     * @param[in] packetData Pointer to the packet data
     * @param[in] packetLength Length of the packet data in bytes
     * @param[out] offset Returns offset to first ZRTP byte in packet data if return value is `Process`
     * @param[out] ssrc Returns the other party's RTP SSRC value in host order
     * @return DataCheckResult.
     * @sa checkRtpData(uint8_t const * packetData, size_t packetLength, size_t & offset, uint32_t & ssrc);
     */
    using CheckFunction = std::function<DataCheckResult(uint8_t const * packetData, size_t packetLength, size_t & offset, uint32_t & ssrc)>;

    /**
     * @brief Callback function to prepare a ZRTP packet to send using transport protocol.
     *
     * The function takes the prepared ZRTP data and sets up a transport packet with this
     * data, for example an RTP packet. The function uses the `ProtocolData` structure to
     * return the prepared data. The `std::unique_ptr<void> ptr` member
     *
     * This `GenericPacketFilter` provides a ready-to-use static function to prepare an RTP packet.
     *
     * @param[in] zrtpData ZRTP packet data
     * @param[in] length Length of the ZRTP date in bytes.
     * @sa prepareToSendRtp(const uint8_t *zrtpData, int32_t length);
     */
    using PrepareToSendFunction = std::function<ProtocolData(GenericPacketFilter& thisFilter, const uint8_t *zrtpData, int32_t length)>;

    /**
     * @brief Callback function to actually send the packet.
     *
     * This is a requiered callback fcuntion. The GenericPacketFilter does not implement
     * a functions to send data using a transport protocol.
     *
     * @param[in] protocolData Contains pointer to packet data and its length. Same data as returned
     *        by the prepare to send function.
     *
     * @return `true` if no error occured, `false` in case of failure.
     *
     */
    using DoSendFunction = std::function<bool(ProtocolData& protocolData)>;

    /**
     * @brief Prepare a RTP packet that contains ZRTP data.
     *
     * The functions returns a `ProtocolData` structure. The `ptr` field is a `secUtilities::SecureArrayFlex`
     * which contains the full RTP packet.
     *
     * If the application does not set the prepare to send callback the `GenericPacketFilter` uses this
     * function to setup an RTP packet which contains a ZRTP packet.
     *
     * @param[in] thisFilter Reference to the packet filter instance
     * @param[in] zrtpData pointer to the ZRTP raw data
     * @param[in] length length of the ZRTP raw data including space for CRC (the last `CRC_SIZE` bytes)
     * @return ProtocolData structure, `ptr` holds a `secUtilities::SecureArrayFlex` instance
     */
    static ProtocolData prepareToSendRtp(GenericPacketFilter& thisFilter, uint8_t const *zrtpData, int32_t length);

    /**
     * @brief Check if an RTP packet contains valid ZRTP data.
     *
     * This functions checks if `packetData` contains valid ZRTP data and returns a
     * pointer to the first byte of the ZRTP packet. If this is no a valid ZRTP packet
     * the function returns `NotProcessed`.
     *
     * @param[in] packetData Pointer to the packet data
     * @param[in] packetLength Length of the packet data in bytes
     * @param[out] offset Returns offset to first ZRTP byte in packet data if return value is `Process`
     * @param[out] ssrc Returns the other party's RTP SSRC value in host order
     * @return DataCheckResult.
     */
    static DataCheckResult checkRtpData(uint8_t const * packetData, size_t packetLength, size_t & offset, uint32_t & ssrc);

    /**
     * @brief Create a GenericPacketFilter.
     *
     * Create an genetic packet filter, initializes the timeout helper, and sets
     * some sensible defaults:
     *
     * - filter type is `MasterStream`
     *
     * @return Shared pointer to GenericPacketFilter instance.
     */
    static std::shared_ptr<GenericPacketFilter>
    createGenericFilter() { return std::shared_ptr<GenericPacketFilter>(new GenericPacketFilter()); }

    /**
     * @brief Destructor stops ZRTP engine.
     *
     */
    virtual ~GenericPacketFilter();

    /**
     * @brief Start the ZRTP engine.
     *
     * @return
     */
    virtual PacketFilterReturnCodes
    startZrtpEngine();

    /**
     * @brief Check for ZRTP packet and process it.
     *
     * @param[in] packetData Pointer to the packet data
     * @param[in] packetLength Length of the packet data in bytes
     * @param[in] checkFunction `filterPacket` calls this function to check for ZRTP data.
     * @return FilterResult
     */
    virtual FilterResult
    filterPacket(uint8_t const * packetData, size_t packetLength, CheckFunction const & checkFunction);

    /**
     * @brief Set ZrtpConfiguration.
     *
     * @param[in] config Shared pointer to ZRtpConfiguration
     * @return reference of the current instance.
     */
     virtual GenericPacketFilter&
     setZrtpConfiguration(std::shared_ptr<ZrtpConfigure>& config) { configuration = config; return *this; }

    /**
     * @brief Set prepare to send callback function.
     *
     * If the application does not set the prepare to send callback funtion the `GenericPacketFilter` uses
     * the static function `prepareToSendRtp()` to setup an RTP packet.
     *
     * @param[in] pTS Functions pointer to PrepareToSendFunction.
     * @return reference of the current instance.
     */
    virtual GenericPacketFilter&
    setPrepareToSendFunction(PrepareToSendFunction pTS) { prepareToSend = pTS; return *this; }

    /**
     * @brief Set do send callback function.
     *
     * If the application must set this function and handle the sending of packets.
     *
     * @param[in] dsf Functions pointer to DoSend function.
     * @return reference of the current instance.
     */
    virtual GenericPacketFilter&
    setDoSendFunction(DoSendFunction dsf) { doSend = dsf; return *this; }

    /**
     * @brief Set own RTP SSRC.
     *
     * When using RTP as transport protocol this is a required value.
     *
     * @param[in] ssrc SSRC value in host order
     * @return reference of the current instance.
     */
    virtual GenericPacketFilter&
    setOwnRtpSsrc(uint32_t ssrc) { ownSSRC = ssrc; return *this; }

    /**
     * @brief Get own RTP SSRC.
     *
     * @return Own SSRC in host order.
     */
    virtual uint32_t getOwnRtpSsrc() const { return ownSSRC; }

    /**
    * @brief Get other party's RTP SSRC.
    *
    * @return Other party's (peer's) SSRC in host order.
    */
    virtual uint32_t getPeerRtpSsrc() const { return peerSSRC; }

    /**
     * @brief Set ZRTP packet sequence number.
     *
     * @param[in] sequence number in host order
     */
    virtual void setZrtpSequenceNo(uint16_t sequence) { senderZrtpSeqNo = sequence; }

    /**
     * @brief Get ZRTP packet sequence number.
     * @return sequence number in host order
     */
    virtual uint16_t getZrtpSequenceNo() const { return senderZrtpSeqNo; }

    /*
     * The following methods implement the GNU ZRTP callback interface.
     * See file ZrtpCallback.h
     */
    int32_t sendDataZRTP(const unsigned char* data, int32_t length) override;

    int32_t activateTimer(int32_t time) override;

    int32_t cancelTimer() override;

    void sendInfo(GnuZrtpCodes::MessageSeverity severity, int32_t subCode) override {}

    bool srtpSecretsReady(SrtpSecret_t* secrets, EnableSecurity part) override  {}

    void srtpSecretsOff(EnableSecurity part) override  {}

    void srtpSecretsOn(std::string c, std::string s, bool verified) override {}

    void handleGoClear() override;

    void zrtpNegotiationFailed(GnuZrtpCodes::MessageSeverity severity, int32_t subCode) override {}

    void zrtpNotSuppOther() override  {}

    void synchEnter() override { syncLock.lock(); }

    void synchLeave() override {syncLock.unlock(); }

    void zrtpAskEnrollment(GnuZrtpCodes::InfoEnrollment info) override {}

    void zrtpInformEnrollment(GnuZrtpCodes::InfoEnrollment  info) override {}

    void signSAS(uint8_t* sasHash) override {}

    bool checkSASSignature(uint8_t* sasHash) override {}

private:

    /**
     * @brief Private constructor - force a shared pointer to GenericPacketFilter using `createGenericFilter()`
     *
     * Create an genetic packet filter, initializes the timeout helper, and sets
     * some sensible defaults:
     *
     * - filter type is `MasterStream`
     */
    GenericPacketFilter();


    std::unique_ptr<ZRtp> zrtpEngine = nullptr;
    std::shared_ptr<ZrtpConfigure> configuration = nullptr;
    PrepareToSendFunction prepareToSend = nullptr;
    DoSendFunction doSend = nullptr;

    std::mutex syncLock;

    FilterType filterType = MasterStream;

    int32_t  timeoutId = -1;
    uint32_t ownSSRC = 0;             //!< Our own SSRC, in host order, required when using RTP prepare function
    uint32_t peerSSRC = 0;            //!< Our peer's SSRC, in host order, required when using RTP prepare function

    uint16_t senderZrtpSeqNo = 0;

    bool zrtpStarted = false;

};

/**
 * @}
 */

#endif //LIBZRTPCPP_GENERICPACKETFILTER_H
