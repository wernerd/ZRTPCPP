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

#ifndef SRTPSYMCRYPTO_H
#define SRTPSYMCRYPTO_H

/**
 * @file SrtpSymCrypto.h
 * @brief Class which implements SRTP cryptographic functions
 * 
 * @ingroup ZRTP
 * @{
 */

#include <cstdint>
#include <srtp/CryptoContext.h>

#ifdef BOTAN_AMAL
#include <botan_all.h>
#endif

#ifndef SRTP_BLOCK_SIZE
#define SRTP_BLOCK_SIZE 16
#endif

typedef struct _f8_ctx {
    unsigned char *S;           ///< Intermediate buffer
    unsigned char *ivAccent;    ///< second IV
    uint32_t J;                 ///< Counter
} F8_CIPHER_CTX;

/**
 * @brief Implements the SRTP encryption modes as defined in RFC3711
 *
 * The SRTP specification defines two encryption modes, AES-CTR
 * (AES Counter mode) and AES-F8 mode. The AES-CTR is required,
 * AES-F8 is optional.
 *
 * Both modes are designed to encrypt/decrypt data of arbitrary length
 * (with a specified upper limit, refer to RFC 3711). These modes do
 * <em>not</em> require that the amount of data to encrypt is a multiple
 * of the AES block size (16 bytes), no padding is necessary.
 *
 * The implementation uses the openSSL library as its cryptographic
 * backend.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class SrtpSymCrypto {
public:
    /**
     * @brief Constructor that does not initialize key data
     *
     * @param algo
     *    The Encryption algorithm to use.Possible values are <code>
     *    SrtpEncryptionNull, SrtpEncryptionAESCM, SrtpEncryptionAESF8
     *    SrtpEncryptionTWOCM, SrtpEncryptionTWOF8</code>. See chapter 4.1.1
     *    for CM (Counter mode) and 4.1.2 for F8 mode.
     */
    explicit SrtpSymCrypto(int algo = SrtpEncryptionAESCM);

    /**
     * @brief Constructor that initializes key data
     * 
     * @param key
     *     Pointer to key bytes.
     * @param key_length
     *     Number of key bytes.
     * @param algo
     *    The Encryption algorithm to use.Possible values are <code>
     *    SrtpEncryptionNull, SrtpEncryptionAESCM, SrtpEncryptionAESF8
     *    SrtpEncryptionTWOCM, SrtpEncryptionTWOF8</code>. See chapter 4.1.1
     *    for CM (Counter mode) and 4.1.2 for F8 mode.
     */
    SrtpSymCrypto(uint8_t* key, int32_t key_length, int algo = SrtpEncryptionAESCM);

    ~SrtpSymCrypto();

    /**
     * @brief Encrypts the input to the output.
     *
     * Encrypts one input block to one output block. Each block
     * is 16 bytes according to the encryption algorithms used.
     *
     * @param input
     *    Pointer to input block, must be 16 bytes
     *
     * @param output
     *    Pointer to output block, must be 16 bytes
     */
    void encrypt( const uint8_t* input, uint8_t* output );

    /**
     * @brief Set new key
     *
     * @param key
     *   Pointer to key data, must have at least a size of keyLength 
     *
     * @param keyLength
     *   Length of the key in bytes, must be 16, 24, or 32
     *
     * @return
     *   false if key could not set.
     */
    bool setNewKey(const uint8_t* key, int32_t keyLength);

    /**
     * @brief Computes the cipher stream for AES CM mode.
     *
     * @param output
     *    Pointer to a buffer that receives the cipher stream. Must be
     *    at least <code>length</code> bytes long.
     *
     * @param length
     *    Number of cipher stream bytes to produce. Usually the same
     *    length as the data to be encrypted.
     *
     * @param iv
     *    The initialization vector as input to create the cipher stream.
     *    Refer to chapter 4.1.1 in RFC 3711.
     */
    void get_ctr_cipher_stream(uint8_t* output, uint32_t length, uint8_t* iv);

    /**
     * @brief Counter-mode encryption.
     *
     * This method performs the CM encryption.
     *
     * @param input
     *    Pointer to input buffer, must be <code>inputLen</code> bytes.
     *
     * @param inputLen
     *    Number of bytes to process.
     *
     * @param output
     *    Pointer to output buffer, must be <code>inputLen</code> bytes.
     *
     * @param iv
     *    The initialization vector as input to create the cipher stream.
     *    Refer to chapter 4.1.1 in RFC 3711.
     */
    void ctr_encrypt(const uint8_t* input, uint32_t inputLen, uint8_t* output, uint8_t* iv );

    /**
     * @brief Counter-mode encryption, in place.
     *
     * This method performs the CM encryption.
     *
     * @param data
     *    Pointer to input and output block, must be <code>dataLen</code>
     *    bytes.
     *
     * @param data_length
     *    Number of bytes to process.
     *
     * @param iv
     *    The initialization vector as input to create the cipher stream.
     *    Refer to chapter 4.1.1 in RFC 3711.
     */
    void ctr_encrypt(uint8_t* data, uint32_t data_length, uint8_t* iv );

    /**
     * @brief Derive a cipher context to compute the IV'.
     *
     * See chapter 4.1.2.1 in RFC 3711.
     *
     * @param f8Cipher
     *    Pointer to the cipher context that will be used to encrypt IV to IV'
     *
     * @param keyIn
     *    The master key
     *
     * @param keyLen
     *    Length of the master key.
     *
     * @param salt
     *   Master salt.
     *
     * @param saltLen
     *   length of master salt.
     */
    static void f8_deriveForIV(SrtpSymCrypto* f8Cipher, uint8_t* keyIn, int32_t keyLen, uint8_t* salt, int32_t saltLen);

    /**
     * @brief F8 mode encryption, in place.
     *
     * This method performs the F8 encryption, see chapter 4.1.2 in RFC 3711.
     *
     * @param data
     *    Pointer to input and output block, must be <code>dataLen</code>
     *    bytes.
     *
     * @param dataLen
     *    Number of bytes to process.
     *
     * @param iv
     *    The initialization vector as input to create the cipher stream.
     *    Refer to chapter 4.1.1 in RFC 3711.
     *
     * @param f8Cipher
     *   An AES cipher context used to encrypt IV to IV'.
     */
    void f8_encrypt(const uint8_t* data, uint32_t dataLen, uint8_t* iv, SrtpSymCrypto* f8Cipher);

    /**
     * @brief F8 mode encryption.
     *
     * This method performs the F8 encryption, see chapter 4.1.2 in RFC 3711.
     *
     * @param data
     *    Pointer to input and output block, must be <code>dataLen</code>
     *    bytes.
     *
     * @param dataLen
     *    Number of bytes to process.
     *
     * @param out
     *    Pointer to output buffer, must be <code>dataLen</code> bytes.
     *
     * @param iv
     *    The initialization vector as input to create the cipher stream.
     *    Refer to chapter 4.1.1 in RFC 3711.
     *
     * @param f8Cipher
     *   An AES cipher context used to encrypt IV to IV'.
     */
    void f8_encrypt(const uint8_t* data, uint32_t dataLen, uint8_t* out, uint8_t* iv, SrtpSymCrypto* f8Cipher);

private:
    int processBlock(F8_CIPHER_CTX* f8ctx, const uint8_t* in, int32_t length, uint8_t* out);
#ifdef BOTAN_AMAL
    std::unique_ptr<Botan::BlockCipher> crypto = nullptr;
#else
    void* key;
#endif
    int32_t algorithm;
};
/**
 * @}
 */

#endif

