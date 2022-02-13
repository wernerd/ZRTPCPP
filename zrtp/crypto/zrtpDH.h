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

#ifndef _ZRTPDH_H__
#define _ZRTPDH_H__


/**
 * @file zrtpDH.h
 * @brief Class that implements Diffie-Hellman key agreement for ZRTP
 * 
 * @ingroup ZRTP
 * @{
 */

/**
 * Generates a number of random bytes.
 *
 * @param buf
 *    Pointer to a buffer that receives the random data. Must have a size
 *    of at least <code>length</code> bytes.
 *
 * @param length
 *    Number of random bytes to produce.
 */
#if defined(__cplusplus)
#include <cstdint>
extern "C"
{
#else
#include <stdint.h>
#endif
void randomZRTP(uint8_t *buf, int32_t length);
#if defined(__cplusplus)
}
#endif

// Exclude the whole code if not compiled with c++ - needed for C-wrapper code.
#if defined(__cplusplus)

#include "libzrtpcpp/ZrtpConfigure.h"
#ifdef SIDH_SUPPORT
#include "cpp/SidhWrapper.h"
#endif
#include "../common/SecureArray.h"

static const uint32_t DH2K_LENGTH_BYTES = 2048 / 8;
static const uint32_t DH3K_LENGTH_BYTES = 3072 / 8;
static const uint32_t EC25_LENGTH_BYTES = 2*(256 / 8);
static const uint32_t EC38_LENGTH_BYTES = 2*(384 / 8);
static const uint32_t E255_LENGTH_BYTES = 32 ;
static const uint32_t E414_LENGTH_BYTES = 2*((414+7) / 8);  // -> computes to 104 byte for x and y coordinate of curve

/**
 * Implementation of Diffie-Helman for ZRTP
 *
 * This class defines functions to generate and compute the
 * Diffie-Helman public and secret data and the shared secret. According to
 * the ZRTP specification we use the MODP groups as defined by RFC 3526 for
 * length 3072 and 4096.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpDH {

public:

    enum ProtocolState {
        Commit,
        DhPart1
    };

    enum ErrorCode {
        SUCCESS = 0,
        ILLEGAL_ARGUMENT = -5,
        UNKNOWN_ALGORITHM = -6,
    };

    /**
     * Create a Diffie-Hellman key agreement algorithm
     * 
     * @param type
     *     Name of the DH algorithm to use
     * @param state
     *     At which protocol state ZRTP needs a new DH
     */
    explicit ZrtpDH(const char* type, ProtocolState state);
    
    ~ZrtpDH();

    /**
     * Fill in the bytes of computed secret key.
     *
     * Computes length of the public key, copies data to pubKey in network
     * (big endian) order and sets correct size.
     *
     * @param pubKey
     *    Reference to a SecureArray with a capacity of at least <code>getPubKeySize()</code> bytes.
     *
     * @return Size in bytes.
     */
    size_t fillInPubKeyBytes(secUtilities::SecureArray<1000>& pubKey) const;

    /**
     * Compute the secret key and returns it to caller.
     *
     * This method computes the secret key based on the DH parameters, the
     * private key and the peer's public key.
     *
     * @param pubKeyBytes
     *    Pointer to the peer's public key bytes. Must be in big endian order.
     *
     * @param secret
     *    Pointer to a buffer that receives the secret key.
     *
     * @return the size of the shared secret on success, -1 on error.
     */
    size_t computeSecretKey(uint8_t *pubKeyBytes, secUtilities::SecureArray<1000>& secret);

    /**
     * Check and validate the public key received from peer.
     *
     * Check if this is a correct Diffie-Helman public key. If the public
     * key value is either one or (P-1) then this is a wrong public key
     * value.
     *
     * @param pubKeyBytes
     *     Pointer to the peer's public key bytes. Must be in big endian order.
     *
     * @return 0 if check failed, 1 if public key value is ok.
     */
    int32_t checkPubKey([[maybe_unused]] uint8_t* pubKeyBytes);

    /**
     * Get type of DH algorithm.
     * 
     * @return
     *     Pointer to DH algorithm name
     */
    [[nodiscard]] const char* getDHtype() const;

    [[nodiscard]] ErrorCode getErrorCode() const { return errorCode; }

    [[nodiscard]] static std::string version() ;

private:

    enum Algorithm {
        DH2K,
        DH3K,
        EC25,
        EC38,
        E255,
        E414,
        SDH5,
        SDH7,
        PQ54,
        PQ64,
        PQ74
    };
#ifdef SIDH_SUPPORT
    SidhWrapper::SidhType getSidhType() const;
#endif
    /**
     * Returns the size in bytes of the DH parameter p which is the size of the shared secret.
     *
     * @return Size in bytes.
     */
    [[nodiscard]] size_t getSharedSecretSize() const;

    /**
     * Returns the size in bytes of computed public key.
     *
     * @return Size in bytes.
     */
    [[nodiscard]] size_t getPubKeySize() const;


    void generateSidhKeyPair();
    size_t computeSidhSharedSecret(uint8_t *pubKeyBytes, secUtilities::SecureArray<1000>& secret);
    [[nodiscard]] size_t getSidhSharedSecretLength() const ;

    size_t secretKeyComputation(uint8_t *pubKeyBytes, secUtilities::SecureArray<1000>& secret, int algorithm);
    size_t getPubKeyBytes(secUtilities::SecureArray<1000>& pubKey, int algorithm) const;

    struct dhCtx;

    Algorithm pkType;               ///< Which type of DH to use
    ProtocolState protocolState;    ///< Create DH for this protocol state
    ErrorCode errorCode;
    std::unique_ptr<dhCtx> ctx;

};
#endif /*__cpluscplus */
#endif

/**
 * @}
 */

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
