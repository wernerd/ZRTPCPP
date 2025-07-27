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

#ifndef ZRTPPACKETPING_H_
#define ZRTPPACKETPING_H_

/**
 * @file ZrtpPacketPing.h
 * @brief The ZRTP Ping message
 *
 * @ingroup ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the PingAck packet.
 *
 * The ZRTP simple message PingAck.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class __EXPORT ZrtpPacketPing final : public ZrtpPacketBase {
public:
    /// Creates a Ping message with default data
    ZrtpPacketPing();

    /// Creates a Ping message from received data
    explicit ZrtpPacketPing(const uint8_t* data);

    ~ZrtpPacketPing() override = default;

    /// Set ZRTP protocol version field, fixed ASCII character array
    // ReSharper disable once CppMemberFunctionMayBeConst
    void setVersion(uint8_t const* text) { memcpy(pingHeader->version, text, ZRTP_WORD_SIZE); }

    /// Get the endpoit hash, fixed byte array
    [[nodiscard]] uint8_t* getEpHash() const { return pingHeader->epHash; }

private:
    Ping_t* pingHeader = &data.ping;; ///< Point the Ping message
    PingPacket_t data = {};
};

/**
 * @}
 */

#endif // ZRTPPACKETPING_H_
