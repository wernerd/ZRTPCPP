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
#include "../common/SecureArray.h"
#include "../common/typedefs.h"
#include "crypto/zrtpKem.h"

constexpr int DH2K_LENGTH_BYTES = 2048 / 8;
constexpr int DH3K_LENGTH_BYTES = 3072 / 8;
constexpr int EC25_LENGTH_BYTES = 2*(256 / 8);
constexpr int EC38_LENGTH_BYTES = 2*(384 / 8);
constexpr int E255_LENGTH_BYTES = 32 ;
constexpr int E414_LENGTH_BYTES = 2*((414+7) / 8);  // -> computes to 104 byte for x and y coordinate of curve
constexpr int E414_LENGTH_BYTES_COMP = (((414+7) / 8) + 1); // -> computes to 53 byte for compressed coordinates

// DH1part packet sends SNTRUP, E414 public key data, and SNTRUP ciphertext
constexpr int NP06_LENGTH_BYTES = SNTRUP_CRYPTO_PUBLICKEYBYTES_653 + SNTRUP_CRYPTO_CIPHERTEXTBYTES_653 + E414_LENGTH_BYTES_COMP;
constexpr int NP09_LENGTH_BYTES = SNTRUP_CRYPTO_PUBLICKEYBYTES_953 + SNTRUP_CRYPTO_CIPHERTEXTBYTES_953 + E414_LENGTH_BYTES_COMP;
constexpr int NP12_LENGTH_BYTES = SNTRUP_CRYPTO_PUBLICKEYBYTES_1277 + SNTRUP_CRYPTO_CIPHERTEXTBYTES_1277 + E414_LENGTH_BYTES_COMP;

// Commit packet sends SNTRUP and E414 public key data only.
constexpr int NP06_LENGTH_BYTES_COMMIT = SNTRUP_CRYPTO_PUBLICKEYBYTES_653 + E414_LENGTH_BYTES_COMP;
constexpr int NP09_LENGTH_BYTES_COMMIT = SNTRUP_CRYPTO_PUBLICKEYBYTES_953 + E414_LENGTH_BYTES_COMP;
constexpr int NP12_LENGTH_BYTES_COMMIT = SNTRUP_CRYPTO_PUBLICKEYBYTES_1277 + E414_LENGTH_BYTES_COMP;

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

    enum MessageType {
        Commit,
        DhPart1,
        Ignore
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
    explicit ZrtpDH(char const * type);
    
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
    size_t getPubKeyBytes(zrtp::SecureArray4k& pubKey, MessageType msgType) const;

    /**
     * Compute the secret key and returns it to caller.
     *
     * This method computes the secret key based on the DH parameters, the
     * private key and the peer's public key.
     *
     * @param pubKeyBytes
     *    Pointer to the peer's public key bytes.
     *
     * @param secret
     *    Pointer to a buffer that receives the secret key.
     *
     * @return the size of the shared secret on success, -1 on error.
     */
    size_t computeSecretKey(uint8_t *pubKeyBytes, zrtp::SecureArray1k& secret,  MessageType msgType);

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
        NP06,
        NP09,
        NP12
    };

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


    void generateSntrupKeyPair() const;
    size_t computeSntrupSharedSecret(uint8_t * pubKeyBytes, zrtp::SecureArray1k& secret, MessageType msgType);

    Algorithm pkType;               ///< Which type of DH to use
    ErrorCode errorCode;
    struct dhCtx;
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
