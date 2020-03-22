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
#include <srtp/SrtpHandler.h>
#include <helpers/ZrtpCodeToString.h>

/**
 * @brief Packet filter and implementation of ZRTP callback functions.
 */
class GenericPacketFilter : public ZrtpCallback, public std::enable_shared_from_this<GenericPacketFilter> {

public:
    /**
     * @brief Result of packet filter function.
     *
     * After switching to `Secure` state and when handling SRTP packets the filter function may
     * return a specific error code `DecryptionFailedStartup`. This happens because some RTP
     * packets were already sent before ZRTP could negotiate keys and enable SRTP encryption.
     *
     * The application may set this threshold, default is 200 packets, thus about 4 seconds of
     * RTP packets (assuming 50 packets/s). This covers low bandwidth connections.
     */
    enum FilterResult {
        Processed,               //!< ZRTP processed the data
        NotStarted,              //!< Packet contains ZRTP data, however ZRTP was not started
        UnknownData,             //!< Filter could not identify type of data
        NotProcessed,            //!< Legit data packet, caller should handle it
        Decrypted,               //!< processSrtp() is true, keys available and decryption successful
        NotDecrypted,            //!< processSrtp() is true but no keys available yet
        DecryptionFailedStartup, //!< processSrtp() is true, keys available but decryption failed while in SRTP startup
        DecryptionFailed,        //!< processSrtp() is true, keys available but decryption failed
    };

    /**
     * @brief Result of packet data check function.
     */
    enum DataCheckResult {
        IsZrtp,               //!< This is valid ZRTP data, process it
        Discard,              //!< Discard the data: no valid transport protocol packet, but also not a ZRTP packet: no further processing
        NotZrtp               //!< Not a ZRTP packet, caller should check and handle data,
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
      * @brief Generic filter reports state to the caller/application.
      *
      * ZRTP performs its operation in several steps:
      *  - Discovery: check if the other party supports ZRTP
      *  - Key negotiation: exchange data and parameters to negotiate keys and algorithms
      *  - Secure: key negotiation was successful and keys are ready to set up encrypted
      *    communication
      *
      * During key negotiation ZRTP may detect error or warning conditions/states.
      *
      *  Generic filter supports two levels of reporting:
      *   - report error, warning, and major state changes only
      *   - report all state changes, many of them are informational only
      *
      *  The callback function receives state details in `StateData` structure,
      *  except in states `Discovery` and `NoPeer` because no further information available.
      *
      *  @sa StateData
      */
     enum ZrtpAppStates {
         InfoOnly = 1,              //!< This state is informational
         Warning,                   //!< A minor problem detected
         Error,                     //!< An error occurred, `StateData` contains detail information
         Discovery,                 //!< ZRTP entered its discovery state, major state
         KeyNegotiation,            //!< ZRTP entered the key negotiation state, major state
         NoPeer,                    //!< Discovery failed, peer does not support ZRTP or did not answer, major state
         Secure,                    //!< ZRTP switched to secure state, major state
     };

    /**
      * @brief Returned by the `PrepareToSendFunction` implementation.
      */
    struct ProtocolData {
        std::shared_ptr<void> ptr = nullptr;    //!< Pointer to prepared data
        int32_t length = 0;                     //!< Length of prepare data in bytes
    };

    /**
     * @brief ZRTP state change detail information.
     *
     * For all state changes except errors or warnings StateData::severity is set to GnuZrtpCodes::Info.
     * This is also true for the major state changes because these are not errors or warnings.
     *
     * StateData::subCode contains GnuZrtpCodes::InfoCodes and StateData::infoText holds a human readable (english)
     * text which describes the state, warning or error. Application may use this text for logging.
     *
     * When changing to GenericPacketFilter::Secure state then generic filter sets StateData::infoText to the
     * computed Short Authentication String (SAS, may use UTF-8 encoding if SAS contains Emojis). An application
     * may also use getComputedSas() to get the SAS at any time after ZRTP entered GenericPacketFilter::Secure state.
     *
     * In all other cases StateData::severity is set to either GnuZrtpCodes::Warning, GnuZrtpCodes::Severe, or GnuZrtpCodes::ZrtpError.
     *
     * @sa ZrtpAppStates
     * @sa StateChangeFunction
     * @sa GnuZrtpCodes::MessageSeverity
     * @sa GnuZrtpCodes::InfoCodes
     * @sa GnuZrtpCodes::WarningCodes
     * @sa GnuZrtpCodes::SevereCodes
     * @sa GnuZrtpCodes::ZrtpErrorCodes
     */
    struct StateData {
        StateData(GnuZrtpCodes::MessageSeverity sev, int32_t sc, std::string const & t) : severity(sev), subCode(sc), infoText(t) { }
        GnuZrtpCodes::MessageSeverity severity; //!< Contains a MessageSeverity::MessageSeverity code
        int32_t subCode;
        std::string const &infoText;
    };

    /**
     * @brief Negotiated key data and algorithms.
     *
     * The `secUtilities::SecureArray<32>` contains the key data, the `size` of the secure array
     * specifies the key or salt length to use. Lengths/sizes are always in number of bytes.
     *
     * Refer to RFC6189, sec. 4.5.3 on how to use the key based on ZRTP `role` and part (`ForSender`
     * or `ForReceiver`).
     *
     * @sa EnableSecurity
     */
    struct KeysAndAlgorithms {
        NegotiatedAlgorithms symEncAlgorithm;               //!< which symmetrical cipher algorithm to use
        secUtilities::SecureArray<32> keyInitiator;         //!< Initiator's key (up to 256bit key length)
        secUtilities::SecureArray<32> saltInitiator;        //!< Initiator's salt
        secUtilities::SecureArray<32> keyResponder;         //!< Responder's key
        secUtilities::SecureArray<32> saltResponder;        //!< Responder's salt
        NegotiatedAlgorithms authAlgorithm;                 //!< authentication algorithm (HMAC)
        int32_t srtpAuthTagLen;                             //!< SRTP authentication length (length in bytes)
        Role  role;                                         //!< ZRTP role of this client: Initiator or Responder.
    };

    /**
     * @brief Signature of ZRTP packet check function.
     *
     * This functions checks if `packetData` contains valid ZRTP data and returns the
     * offset to the first byte of the ZRTP packet if it's valid ZRTP data. If this is
     * not a valid ZRTP packet the function must return either `NotZrtp` or `Discard`
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
     * @param[out] offset Returns offset to first ZRTP byte in packet data if return value is `IsZrtp`
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
     * This is a required callback function. The GenericPacketFilter does not implement
     * a functions to send data using a transport protocol.
     *
     * @param[in] protocolData Contains pointer to packet data and its length. Same data as returned
     *        by the prepare to send function.
     *
     * @return `true` if no error occurred, `false` in case of failure.
     *
     */
    using DoSendFunction = std::function<bool(ProtocolData& protocolData)>;

    /**
     * @brief ZRTP state change callback function.
     *
     * Generic filter calls this function to report state changes during ZRTP key negotiation.
     *
     * @param[in] state Reported state
     * @param[in] stateData Information for this state report
     *
     * @sa ZrtpAppStates
     * @sa StateData
     */
    using StateChangeFunction = std::function<void(ZrtpAppStates state, StateData& stateData)>;

    /**
     * @brief Callback function to get negotiated key data and algorithm information.
     *
     * If the function returns `false` ZRTP generates an error and does not enter state `Secure`.
     *
     * @param[in] part Defines how to use the key, which direction (RFC 6189, sec. 4.5.3)
     * @param[in] keyData Data and algorithm information.
     * @return `true` if keys processed, `false` if key processing failed
     *
     * @sa EnableSecurity
     * @sa KeysAndAlgorithms
     */
    using KeysReadyFunction = std::function<bool(EnableSecurity part, KeysAndAlgorithms& keyData)>;

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
    static ProtocolData
    prepareToSendRtp(GenericPacketFilter& thisFilter, uint8_t const *zrtpData, int32_t length);

    /**
     * @brief Check if an RTP packet contains valid ZRTP data.
     *
     * This functions checks if `packetData` contains valid ZRTP data and returns a
     * pointer to the first byte of the ZRTP packet. If this is no a valid ZRTP packet
     * the function returns `NotProcessed`.
     *
     * @param[in] packetData Pointer to the packet data
     * @param[in] packetLength Length of the packet data in bytes
     * @param[out] offset Returns offset to first ZRTP byte in packet data if return value is `IsZrtp`
     * @param[out] ssrc Returns the other party's RTP SSRC value in host order
     * @return DataCheckResult.
     */
    static DataCheckResult
    checkRtpData(uint8_t const * packetData, size_t packetLength, size_t & offset, uint32_t & ssrc);

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
     * @brief Release the global, statically allocated time out provider.
     *
     * GenericFilter allocates a global timeout provider to provide the timeout service to ZRTP.
     * To save resources it's a singleton which is usually not released if a ZRTP session stops.
     *
     * Applications may use this function to release the timeout provider.
     */
    virtual void
    releaseTimeoutProvider();

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
     * @param[in, out] packetLength Length of the packet data in bytes. When performing S
     *                 RTP decryption this is the length after decryption.
     * @param[in] checkFunction `filterPacket` calls this function to check for ZRTP data.
     * @return FilterResult
     */
    virtual FilterResult
    filterPacket(uint8_t const * packetData, size_t & packetLength, CheckFunction const & checkFunction);

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
     * If the application does not set the prepare to send callback function the `GenericPacketFilter` uses
     * the static function `prepareToSendRtp()` to setup an RTP packet.
     *
     * @param[in] pTS Functions pointer to PrepareToSendFunction.
     * @return reference of the current instance.
     */
    virtual GenericPacketFilter&
    onPrepareToSend(PrepareToSendFunction pTS) { prepareToSend = pTS; return *this; }

    /**
     * @brief Set do send callback function.
     *
     * If the application must set this function and handle the sending of packets.
     *
     * @param[in] dsf Functions pointer to DoSend function.
     * @return reference of the current instance.
     */
    virtual GenericPacketFilter&
    onDoSend(DoSendFunction dsf) { doSend = dsf; return *this; }

    /**
     * @brief Set own RTP SSRC.
     *
     * When using RTP as transport protocol this is a required value.
     *
     * @param[in] ssrc SSRC value in host order
     * @return reference of the current instance.
     */
    virtual GenericPacketFilter&
    ownRtpSsrc(uint32_t ssrc) { ownSSRC = ssrc; return *this; }

    /**
      * @brief Enable SRTP processing.
      *
      * @param[in] yesNo If set to `true` GenericPacketFilter sets up an SRTP handler, manages keys and
      *        application can forward packet to encrypt or decrypt.
      * @return reference of the current instance.
      */
    virtual GenericPacketFilter&
    processSrtp(bool yesNo) { doProcessSrtp = yesNo; return *this; }

    /**
     * @brief Current value of `processSrtp`.
     *
     * @return Value of `processSrtp`.
     */
    virtual bool
    processSrtp() const { return doProcessSrtp; }

    /**
     * @brief Set to enable full state reports, including Info states.
     *
     * Default is to report only error, warning and major states.
     *
     * @param[in] yesNo If set to `true` GenericPacketFilter reports any state changes which include Info states.
     * @return reference of the current instance.
     */
    virtual GenericPacketFilter&
    allStateReports(bool yesNo) { reportAllStates = yesNo; return *this; }

    /**
     * @brief Set ZRTP state change callback.
     *
     * If this function is not set, caller/application does not receive any state changes.
     * It's strongly advised to set this callback and act on error, warning and possibly
     * major state changes.
     *
     * @param[in] stateHandlerFunction callback function which receives state changes
     * @return reference of the current instance.
     */
    virtual GenericPacketFilter&
    onStateReport(StateChangeFunction stateHandlerFunction) { stateHandler = stateHandlerFunction; return *this; }

    /**
     * @brief Set key data ready callback.
     *
     * If this function is not set _and_ processSrtp() is false, then ZRTP reports an error
     * and does not enter `Secure`.
     *
     * If processSrtp() is true then GenericFilter handles the key data internally and does
     * not perform a callback even if this callback is not null.
     *
     * @param[in] keyDataFunction callback function which receives key data and algorithm information
     * @return reference of the current instance.
     */
    virtual GenericPacketFilter&
    onKeyDataReady(KeysReadyFunction keyDataFunction) { keyDataReady = keyDataFunction; return *this; }

    /**
     * @brief Get the SAS (Short Authentication String).
     *
     * Generic filter also stores the SAS in `StateData::infoText` when changing to `Secure` state.
     *
     * @return Computed SAS, ready to compare with other user.
     */
    virtual std::string const &
    getComputedSas() const { return computedSas; }

    /**
     * @brief Get the cipher information.
     *
     * Information about negotiated cipher, hash algorithm, and SRTP authentication length and algorithm.
     *
     * @return Cipher information.
     */
    virtual std::string const &
    cipherInfo() const { return cipherInfo_; }

    /**
     * @brief Get own RTP SSRC.
     *
     * @return Own SSRC in host order.
     */
    virtual uint32_t
    ownRtpSsrc() const { return ownSSRC; }

    /**
    * @brief Get other party's RTP SSRC.
    *
    * @return Other party's (peer's) SSRC in host order.
    */
    virtual uint32_t
    peerRtpSsrc() const { return peerSSRC; }

    /**
     * @brief Set ZRTP packet sequence number.
     *
     * @param[in] sequence number in host order
     */
    virtual void
    zrtpSequenceNo(uint16_t sequence) { senderZrtpSeqNo = sequence; }

    /**
     * @brief Get ZRTP packet sequence number.
     *
     * @return sequence number in host order
     */
    virtual uint16_t
    zrtpSequenceNo() const { return senderZrtpSeqNo; }

    virtual bool
    sasVerified() const { return sasVerified_; }

    /**
     * @brief Process outgoing RTP data.
     *
     * Depending on ZRTP state the function either encrypts the buffer
     * or returns it unmodified.
     *
     * The function takes a uint8_t buffer that must contain RTP packet data. The
     * function also assumes that the RTP packet contains all protocol relevant fields
     * (SSRC, sequence number etc.) in network order.
     *
     * @param rtpData contains data in RTP packet format
     * @param length length of the RTP packet data in buffer.
     * @return pointer to data, empty pointer if data could not be processed. This
     *         usually happens if the data is not a valid RTP packet (RTP header etc wrong)
     */
    std::unique_ptr<secUtilities::SecureArrayFlex>
    processOutgoingRtp(uint8_t *rtpData, size_t length);

    /*
     * The following methods implement the GNU ZRTP callback interface.
     * See file ZrtpCallback.h
     */
    int32_t
    sendDataZRTP(const unsigned char* data, int32_t length) override;

    int32_t
    activateTimer(int32_t time) override;

    int32_t
    cancelTimer() override;

    void
    sendInfo(GnuZrtpCodes::MessageSeverity severity, int32_t subCode) override;

    bool
    srtpSecretsReady(SrtpSecret_t* secrets, EnableSecurity part) override;

    void
    srtpSecretsOff(EnableSecurity part) override;

    void
    srtpSecretsOn(std::string c, std::string s, bool verified) override;

    void
    handleGoClear() override;

    void
    zrtpNegotiationFailed(GnuZrtpCodes::MessageSeverity severity, int32_t subCode) override;

    void
    zrtpNotSuppOther() override;

    void
    synchEnter() override { syncLock.lock(); }

    void
    synchLeave() override {syncLock.unlock(); }

    void
    zrtpAskEnrollment(GnuZrtpCodes::InfoEnrollment info) override {}

    void
    zrtpInformEnrollment(GnuZrtpCodes::InfoEnrollment  info) override {}

    void
    signSAS(uint8_t* sasHash) override {}

    bool
    checkSASSignature(uint8_t* sasHash) override { return true; }

private:

    /**
     * @brief Private constructor - force a shared pointer to GenericPacketFilter using `createGenericFilter()`
     *
     * Creates a generic packet filter, initializes the timeout helper, and sets
     * some sensible defaults:
     *
     * - filter type is `MasterStream`
     */
    GenericPacketFilter();

    // Some statistic counters
    uint64_t zrtpProtect = 0;
    uint64_t zrtpUnprotect = 0;
    uint64_t unprotectFailed = 0;

    SrtpErrorData srtpErrorDetails = {};

    ZrtpCodeToString codeToString;

    std::unique_ptr<ZRtp> zrtpEngine = nullptr;
    std::shared_ptr<ZrtpConfigure> configuration = nullptr;

    std::unique_ptr<CryptoContext    > recvSrtp;           //!< Receiving SRTP context for this filter
    std::unique_ptr<CryptoContextCtrl> recvSrtcp;          //!< Receiving SRTCP context for this filter
    std::unique_ptr<CryptoContext    > sendSrtp;           //!< Sending SRTP context for this filter
    std::unique_ptr<CryptoContextCtrl> sendSrtcp;          //!< Sending SRTCP context for this filter

    // Callback functions
    PrepareToSendFunction prepareToSend = nullptr;
    DoSendFunction doSend = nullptr;
    StateChangeFunction stateHandler = nullptr;
    KeysReadyFunction keyDataReady = nullptr;

    std::mutex syncLock;

    std::string computedSas;        //!< Short authentication string, possibly UTF-8 code (Emojis)
    std::string cipherInfo_;   //!< Information about negotiated cipher and hash algorithm

    FilterType filterType = MasterStream;

    Role role = NoRole;               //!< Initiator or Responder role

    int32_t  timeoutId = -1;
    uint32_t ownSSRC = 0;             //!< Our own SSRC, in host order, required when using RTP prepare function
    uint32_t peerSSRC = 0;            //!< Our peer's SSRC, in host order, required when using RTP prepare function

    uint32_t suppressCounter = 0;     //!< suppress SRTP warnings for some packets after we switch to SRTP
    uint32_t supressWarn = 200;       //!< Threshold: if reached, start to report errors, below this just discard packets

    uint16_t senderZrtpSeqNo = 0;

    bool zrtpStarted = false;
    bool doProcessSrtp = false;
    bool reportAllStates = false;
    bool sasVerified_ = false;
};

/**
 * @}
 */

#endif //LIBZRTPCPP_GENERICPACKETFILTER_H
