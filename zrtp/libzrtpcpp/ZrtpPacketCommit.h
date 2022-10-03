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

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */
#ifndef _ZRTPPACKETCOMMIT_H_
#define _ZRTPPACKETCOMMIT_H_

/**
 * @file ZrtpPacketCommit.h
 * @brief The ZRTP Commit message
 *
 * @ingroup ZRTP
 * @{
 */

#include "libzrtpcpp/ZrtpPacketBase.h"
#include "common/typedefs.h"
#include "crypto/zrtpKem.h"

// PRSH here only for completeness. We don't support PRSH in the other ZRTP parts.
#define COMMIT_DH_EX      29
#define COMMIT_MULTI      25

/**
 * Implement the Commit packet.
 *
 * The ZRTP message Commit. The ZRTP implementation sends or receives
 * this message to commit the crypto parameters offered during a Hello
 * message.
 *
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class __EXPORT ZrtpPacketCommit : public ZrtpPacketBase {

public:
    typedef enum _commitType {
        DhExchange =  1,
        MultiStream = 2
    } commitType;

    /// Creates a Commit packet with default data
    ZrtpPacketCommit();

    /// Creates a Commit packet from received data
    explicit ZrtpPacketCommit(uint8_t const * data);

    /// Normal destructor
    ~ZrtpPacketCommit() override = default;

    /// Get pointer to hash algorithm type field, a fixed length character array
    [[nodiscard]] uint8_t* getHashType() const   { return commitHeader->hash; };

    /// Get pointer to cipher algorithm type field, a fixed length character array
    [[nodiscard]] uint8_t* getCipherType() const { return commitHeader->cipher; };

    /// Get pointer to SRTP authentication algorithm type field, a fixed length character array
    [[nodiscard]] uint8_t* getAuthLen() const    { return commitHeader->authlengths; };

    /// Get pointer to key agreement algorithm type field, a fixed length character array
    [[nodiscard]] uint8_t* getPubKeysType() const { return commitHeader->pubkey; };

    /// Get pointer to SAS algorithm type field, a fixed length character array
    [[nodiscard]] uint8_t* getSasType() const    { return commitHeader->sas; };

    /// Get pointer to ZID field, a fixed length byte array
    [[nodiscard]] uint8_t* getZid() const        { return commitHeader->zid; };

    /// Get pointer to HVI field, a fixed length byte array
    [[nodiscard]] uint8_t* getHvi() const        { return commitHeader->hvi; };

    /// Get pointer to NONCE field, a fixed length byte array, overlaps HVI field
    [[nodiscard]] uint8_t* getNonce() const      { return commitHeader->hvi; };

    /// Get pointer to hashH2 field, a fixed length byte array
    [[nodiscard]] uint8_t* getH2() const         { return commitHeader->hashH2; };

    /// Get pointer to MAC field, a fixed length byte array
    [[nodiscard]] uint8_t* getHMAC() const       { return pv+roundUp; };

    /// Get pointer to MAC field during multi-stream mode, a fixed length byte array
    [[maybe_unused]] [[nodiscard]] uint8_t* getHMACMulti() const  { return commitHeader->hvi; };

    /// Check if packet length makes sense.
    [[nodiscard]] bool isLengthOk(commitType type) const;

    /// Get pointer to public key value, variable length byte array
    [[nodiscard]] uint8_t* getPv() const            { return pv; }

    /// Set hash algorithm type field, fixed length character field
    void setHashType(uint8_t const * text)    { memcpy(commitHeader->hash, text, ZRTP_WORD_SIZE); };

    /// Set cipher algorithm type field, fixed length character field
    void setCipherType(uint8_t const * text)  { memcpy(commitHeader->cipher, text, ZRTP_WORD_SIZE); };

    /// Set SRTP authentication algorithm algorithm type field, fixed length character field
    void setAuthLen(uint8_t const * text)     { memcpy(commitHeader->authlengths, text, ZRTP_WORD_SIZE); };

    /// Set key agreement algorithm type field, fixed length character field
    void setPubKeyType(uint8_t const * text)  { memcpy(commitHeader->pubkey, text, ZRTP_WORD_SIZE); };

    /// Set SAS algorithm type field, fixed length character field
    void setSasType(uint8_t const * text)     { memcpy(commitHeader->sas, text, ZRTP_WORD_SIZE); };

    /// Set ZID field, a fixed length byte array
    void setZid(uint8_t const * text)         { memcpy(commitHeader->zid, text, sizeof(commitHeader->zid)); };

    /// Set HVI field, a fixed length byte array
    void setHvi(uint8_t const * text)         { memcpy(commitHeader->hvi, text, sizeof(commitHeader->hvi)); };

    /// Set Nonce field, a fixed length byte array, overlapping HVI field
    void setNonce(uint8_t const * text);

    /// Set hashH2 field, a fixed length byte array
    void setH2(uint8_t const * hash)          { memcpy(commitHeader->hashH2, hash, sizeof(commitHeader->hashH2)); };

    /// Set first MAC, fixed length byte array, copied after the PKI (pv) data
    void setHMAC(zrtp::ImplicitDigest const & hmac) { memcpy(pv+roundUp, hmac.data(), HMAC_SIZE); };

    /// Set MAC field during multi-stream mode, a fixed length byte array - triggers compiler warning, but it's OK
    void setHMACMulti(zrtp::ImplicitDigest const & hmac) { uint8_t *p = commitHeader->hvi; memcpy(p, hmac.data(), HMAC_SIZE); };

    /// Set key length and compute overall packet length
    void setPacketLength(size_t pubKeyLen);

    /// Set public key value(s), variable length byte array
    void setPv(uint8_t const * text)         { memcpy(pv, text, pvLength); };


private:
    uint8_t * pv = nullptr;                   ///< points to public key values inside Commit message (after HVI)
    size_t pvLength = 0;                      ///< length of public key data
    size_t roundUp = 0;                       ///< Public key length, rounded up to ZRTP_WORD_SIZE

    Commit_t* commitHeader = nullptr;         ///< Points to Commit message part

    // Commit packet is of variable length.
    // - 26 words fixed size
    // - up to 993 words variable part, depending on algorithm (max: NP12 + EC414)
    //   leads to a maximum of 4*1019=4076 bytes.
    // - CRC (1 word)
    uint8_t data[4100] = {};       // large enough to hold a full-blown commit packet
};

/**
 * @}
 */
#endif // _ZRTPPACKETCOMMIT_H_

