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

#ifndef _ZRTPPACKETHELLO_H_
#define _ZRTPPACKETHELLO_H_

/**
 * @file ZrtpPacketHello.h
 * @brief The ZRTP Hello message
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpPacketBase.h>

#define HELLO_FIXED_PART_LEN  22

/**
 * Implement the Hello packet.
 *
 * The ZRTP Hello message. The implementation sends this
 * to start the ZRTP negotiation sequence. The Hello message
 * offers crypto methods and parameters to the other party. The
 * other party selects methods and parameters it can support
 * and uses the Commit message to commit these.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZrtpPacketHello : public ZrtpPacketBase {

 public:
    /// Creates a Hello packet with default data
    ZrtpPacketHello() = default;

    /// Creates a Hello packet from received data
    explicit ZrtpPacketHello(const uint8_t *data);

    ~ZrtpPacketHello() override = default;

    /**
     * Set configure data and populate Hello message data.
     *
     * Fill in the offered Algorithm names and compute all offset to
     * names and MAC. An application must call this method on Hello message
     * objects created with the standard constructor (with default data)
     * before the application can use most of the getter and setter methods.
     *
     * @param config
     *    Pointer to ZrtpConfigure data.
     */
    void configureHello(ZrtpConfigure& config);

    /// Get version number from Hello message, fixed ASCII character array
    [[nodiscard]] uint8_t* getVersion() const { return helloHeader->version; };

     /// Get version number from Hello message as integer, only relevant digits converted
    [[nodiscard]] int32_t getVersionInt() const;

    /// Get client id from Hello message, fixed ASCII character array
    [[nodiscard]] uint8_t* getClientId() const { return helloHeader->clientId; };

    /// Get H3 hash from Hello message, fixed byte array
    [[nodiscard]] uint8_t* getH3() const      { return helloHeader->hashH3; };

    /// Get client ZID from Hello message, fixed bytes array
    [[nodiscard]] uint8_t* getZid() const     { return helloHeader->zid; };

    /// Set version sting in Hello message, fixed ASCII character array
    void setVersion(uint8_t const *text)     { memcpy(helloHeader->version, text,ZRTP_WORD_SIZE ); }

    /// Set client id in Hello message, fixed ASCII character array
    void setClientId(uint8_t const *t) { memcpy(helloHeader->clientId, t, sizeof(helloHeader->clientId)); }

    /// Set H3 hash in Hello message, fixed byte array
    void setH3(uint8_t const *hash)          { memcpy(helloHeader->hashH3, hash, sizeof(helloHeader->hashH3)); }

    /// Set client ZID in Hello message, fixed bytes array
    void setZid(uint8_t const *text)   { memcpy(helloHeader->zid, text, sizeof(helloHeader->zid)); }

    /// Check passive mode (mode not implemented)
    bool isPassive()       { return (helloHeader->flags & 0x10U) == 0x10 ; };

    /// Check if MitM flag is set
    bool isMitmMode()       { return (helloHeader->flags & 0x20U) == 0x20; };

    /// Check if SAS sign flag is set
    bool isSasSign()       { return (helloHeader->flags & 0x40U) == 0x40; };

    /// Get hash algorithm name at position n, fixed ASCII character array
    [[nodiscard]] uint8_t* getHashType(int32_t n) const  { return ((uint8_t*)helloHeader)+oHash+(n*ZRTP_WORD_SIZE); }

    /// Get ciper algorithm name at position n, fixed ASCII character array
    [[nodiscard]] uint8_t* getCipherType(int32_t n) const{ return ((uint8_t*)helloHeader)+oCipher+(n*ZRTP_WORD_SIZE); }

    /// Get SRTP authentication algorithm name at position n, fixed ASCII character array
    [[nodiscard]] uint8_t* getAuthLen(int32_t n) const   { return ((uint8_t*)helloHeader)+oAuth+(n*ZRTP_WORD_SIZE); }

    /// Get key agreement algorithm name at position n, fixed ASCII character array
    [[nodiscard]] uint8_t* getPubKeyType(int32_t n) const{ return ((uint8_t*)helloHeader)+oPubkey+(n*ZRTP_WORD_SIZE); }

    /// Get SAS algorithm name at position n, fixed ASCII character array
    [[nodiscard]] uint8_t* getSasType(int32_t n) const   { return ((uint8_t*)helloHeader)+oSas+(n*ZRTP_WORD_SIZE); }

    /// Get Hello MAC, fixed byte array
    [[nodiscard]] uint8_t* getHMAC() const               { return ((uint8_t*)helloHeader)+oHmac; }

    /// Set hash algorithm name at position n, fixed ASCII character array
    void setHashType(int32_t n, int8_t const * t)
        { memcpy(((uint8_t*)helloHeader)+oHash+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }

    /// Set ciper algorithm name at position n, fixed ASCII character array
    void setCipherType(int32_t n, int8_t const * t)
        { memcpy(((uint8_t*)helloHeader)+oCipher+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }

    /// Set SRTP authentication algorithm name at position n, fixed ASCII character array
    void setAuthLen(int32_t n, int8_t const * t)
        { memcpy(((uint8_t*)helloHeader)+oAuth+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }

    /// Set key agreement algorithm name at position n, fixed ASCII character array
    void setPubKeyType(int32_t n, int8_t const * t)
        { memcpy(((uint8_t*)helloHeader)+oPubkey+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }

    /// Set SAS algorithm name at position n, fixed ASCII character array
    void setSasType(int32_t n, int8_t const * t)
        { memcpy(((uint8_t*)helloHeader)+oSas+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }

    /// Set Hello MAC, fixed byte array
    void setHMAC(uint8_t const * t)
        { memcpy(((uint8_t*)helloHeader)+oHmac, t, 2*ZRTP_WORD_SIZE); }

    /// Get number of offered hash algorithms
    [[nodiscard]] int32_t getNumHashes() const  {return nHash; }

    /// Get number of offered cipher algorithms
    [[nodiscard]] int32_t getNumCiphers() const {return nCipher; }

    /// Get number of offered key agreement algorithms
    [[nodiscard]] int32_t getNumPubKeys() const {return nPubkey; }

    /// Get number of offered SAS algorithms
    [[nodiscard]] int32_t getNumSas() const     {return nSas; }

    /// Get number of offered SRTP authentication algorithms
    [[nodiscard]] int32_t getNumAuth() const    {return nAuth; }

    /// set MitM flag
    void setMitmMode()       {helloHeader->flags |= 0x20U; }

    /// set SAS sign flag
    void setSasSign()        {helloHeader->flags |= 0x40U; }

    /// Check if packet length matches
    bool isLengthOk()        {return (computedLength == getLength());}

 private:
    Hello_t* helloHeader = nullptr;   ///< Point to the Hello message part

    uint32_t nHash = 0,                 ///< number of hash algorithms offered
            nCipher = 0,                ///< number of cipher algorithms offered
            nPubkey = 0,                ///< number of key agreement algorithms offered
            nSas = 0,                   ///< number of SAS algorithms offered
            nAuth = 0;                  ///< number of SRTP authentication algorithms offered

    int32_t oHash = 0,                  ///< offsets in bytes to hash algorithm names
            oCipher = 0,                ///< offsets in bytes to cipher algorithm names
            oPubkey = 0,                ///< offsets in bytes to key agreement algorithm names
            oSas = 0,                   ///< offsets in bytes to SAS algorithm names
            oAuth = 0,                  ///< offsets in bytes to SRTP authentication algorithm names
            oHmac = 0;                  ///< offsets in bytes to MAC of Hello message

     uint32_t computedLength = 0;

     // Hello packet is of variable length. It maximum size is 46 words:
     // - 20 words fixed size
     // - up to 35 words variable part, depending on number of algorithms
     // leads to a maximum of 4*55=220 bytes.
     uint8_t data[256] = {0};       // large enough to hold a full blown Hello packet
};

/**
 * @}
 */
#endif // ZRTPPACKETHELLO

