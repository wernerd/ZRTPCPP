/*
 * Copyright 2006 - 2018, Werner Dittmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ZRTPPACKETPINGACK_H_
#define ZRTPPACKETPINGACK_H_

#include <libzrtpcpp/ZrtpPacketBase.h>
/**
 * @file ZrtpPacketPingAck.h
 * @brief The ZRTP PingAck message
 *
 * @ingroup ZRTP
 * @{
 */

/**
 * Implement the PingAck packet.
 *
 * The ZRTP simple message PingAck.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class __EXPORT ZrtpPacketPingAck final : public ZrtpPacketBase {
public:
    /// Creates a PingAck message with default data
    ZrtpPacketPingAck();

    /// Creates a PingAck message from received data
    explicit ZrtpPacketPingAck(const uint8_t* data);

    ~ZrtpPacketPingAck() override = default;

    /// Get SSRC from PingAck message
    [[nodiscard]] uint32_t getSSRC() const { return zrtpNtohl(pingAckHeader->ssrc); }

    // The set functions actually copy into the data array via the pingAckHeader

    /// Set ZRTP protocol version field, fixed ASCII character array
    // ReSharper disable once CppMemberFunctionMayBeConst
    void setVersion(uint8_t const* text) const { memcpy(pingAckHeader->version, text, ZRTP_WORD_SIZE); }

    /// Set SSRC in PingAck message
    // ReSharper disable once CppMemberFunctionMayBeConst
    void setSSRC(uint32_t const dataIn) { pingAckHeader->ssrc = zrtpHtonl(dataIn); }

    /// Set remote endpoint hash, fixed byte array
    // ReSharper disable once CppMemberFunctionMayBeConst
    void setRemoteEpHash(uint8_t const* hash) {
        memcpy(pingAckHeader->remoteEpHash, hash, sizeof(pingAckHeader->remoteEpHash));
    }

    /// Set local endpoint hash, fixed byte array
    // ReSharper disable once CppMemberFunctionMayBeConst
    void setLocalEpHash(uint8_t const* hash) {
        memcpy(pingAckHeader->localEpHash, hash, sizeof(pingAckHeader->localEpHash));
    }

private:
    PingAck_t* pingAckHeader = &data.pingAck; ///< Points to PingAck message
    PingAckPacket_t data = {};
};

/**
 * @}
 */
#endif // ZRTPPACKETPINGACK_H_
