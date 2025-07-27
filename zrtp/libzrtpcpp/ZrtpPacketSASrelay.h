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
#ifndef ZRTPPACKETSASRELAY_H_
#define ZRTPPACKETSASRELAY_H_

/**
 * @file ZrtpPacketSASrelay.h
 * @brief The ZRTP SAS Relay message
 *
 * @ingroup ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the Confirm packet.
 *
 * The ZRTP message Confirm. The implementation sends this
 * to confirm the switch to SRTP (encrypted) mode. The contents of
 * the Confirm message are encrypted, thus the implementation
 * can check if the secret keys work.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZrtpPacketSASrelay final : public ZrtpPacketBase {

public:
    /// Creates a Confirm packet with default data
    ZrtpPacketSASrelay();

    /// Creates a Confirm packet with default data and a given signature length
    explicit ZrtpPacketSASrelay(uint32_t sl);

    /// Creates a Confirm packet from received data
    explicit ZrtpPacketSASrelay(const uint8_t* data);

    /// Normal destructor
    ~ZrtpPacketSASrelay() override = default;

    /// Check is SAS verify flag is set
    [[nodiscard]] bool isSASFlag() const { return (sasRelayHeader->flags & 0x4U) == 0x4; }

    /// Get pointer to filler bytes (contains one bit of signature length)
    [[nodiscard]] const uint8_t* getFiller() const { return sasRelayHeader->filler; }

    /// Get pointer to IV data, fixed byte array
    [[nodiscard]] const uint8_t* getIv() const { return sasRelayHeader->iv; }

    /// Get pointer to MAC data, fixed byte array
    [[nodiscard]] const uint8_t* getHmac() const { return sasRelayHeader->hmac; }

    /// Get pointer to new SAS rendering algorithm, fixed byte array
    [[nodiscard]] const uint8_t* getSasAlgo() const { return sasRelayHeader->sas; }

    /// Get pointer to new SAS hash data, fixed byte array
    [[nodiscard]] const uint8_t* getTrustedSas() const { return sasRelayHeader->trustedSasHash; }

    /// get the signature length in words
    [[nodiscard]] uint32_t getSignatureLength() const;

    /// Check if packet length makes sense. SAS relay packets are 19 words at minimum, they are similar to Confirm
    [[nodiscard]] bool isLengthOk() const { return getLength() >= 19; }

    /// set SAS verified flag
    // ReSharper disable once CppMemberFunctionMayBeConst
    void setSASFlag() { sasRelayHeader->flags |= 0x4U; }

    // The set functions actually copy into the data array via the sasRelayHeader

    /// Set MAC data, fixed length byte array
    // ReSharper disable once CppMemberFunctionMayBeConst
    void setHmac(uint8_t const* text) { memcpy(sasRelayHeader->hmac, text, sizeof(sasRelayHeader->hmac)); }

    /// Set IV data, fixed length byte array
    // ReSharper disable once CppMemberFunctionMayBeConst
    void setIv(uint8_t const* text) { memcpy(sasRelayHeader->iv, text, sizeof(sasRelayHeader->iv)); }

    /// Set SAS rendering algorithm, fixed length byte array
    // ReSharper disable once CppMemberFunctionMayBeConst
    void setSasAlgo(uint8_t const* text) { memcpy(sasRelayHeader->sas, text, sizeof(sasRelayHeader->sas)); }

    /// Set SAS hash data, fixed length byte array
    // ReSharper disable once CppMemberFunctionMayBeConst
    void setTrustedSas(uint8_t const* text) {
        memcpy(sasRelayHeader->trustedSasHash, text, sizeof(sasRelayHeader->trustedSasHash));
    }

    /// Set signature length in words
    void setSignatureLength(uint32_t sl);

private:
    void initialize();

    SASrelay_t* sasRelayHeader =  &reinterpret_cast<SASrelayPacket_t *>(data)->sasrelay;
    ///< Point to the Confirm message part
    // Confirm packet is of variable length. Its maximum size is 524 words:
    // - 11 words fixed size
    // - up to 513 words variable part, depending on if signature is present and its length.
    // This leads to a maximum of 4*524=2096 bytes.
    uint8_t data[2100] = {}; // large enough to hold a full-blown Confirm packet
};

/**
 * @}
 */
#endif // ZRTPPACKETSASRELAY_H_
