/*
  Copyright (C) 2005, 2004, 2010 Erik Eliasson, Johan Bilien, Werner Dittmann

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
*/



#ifndef AESSRTP_H
#define AESSRTP_H

/**
 * @file AesSrtp.h
 * @brief Class which implements SRTP AES cryptographic functions
 * 
 * @ingroup GNU_ZRTP
 * @{
 */

#include <stdint.h>
#include <CryptoContext.h>

#ifndef SRTP_BLOCK_SIZE
#define SRTP_BLOCK_SIZE 16
#endif

typedef struct _f8_ctx {
    unsigned char *S;           ///< Intermetiade buffer
    unsigned char *ivAccent;    ///< second IV
    uint32_t J;                 ///< Counter
} F8_CIPHER_CTX;

/**
 * Implments the SRTP encryption modes as defined in RFC3711
 *
 * The SRTP specification defines two encryption modes, AES-CTR
 * (AES Counter mode) and AES-F8 mode. The AES-CTR is required,
 * AES-F8 is optional.
 *
 * Both modes are desinged to encrypt/decrypt data of arbitrary length
 * (with a specified upper limit, refer to RFC 3711). These modes do
 * <em>not</em> require that the amount of data to encrypt is a multiple
 * of the AES blocksize (128byte), no padding is necessary.
 *
 * The implementation uses the openSSL library as its cryptographic
 * backend.
 *
 * @author Erik Eliasson <eliasson@it.kth.se>
 * @author Johan Bilien <jobi@via.ecp.fr>
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class AesSrtp {
public:
    AesSrtp(int algo = SrtpEncryptionAESCM);
    
    /**
     * Constructor that initializes key data
     * 
     * @param key
     *     Pointer to key bytes.
     * @param key_length
     *     Number of key bytes.
     */
    AesSrtp(uint8_t* key, int32_t key_length, int algo = SrtpEncryptionAESCM);
    
    ~AesSrtp();

    /**
     * Encrypts the inpout to the output.
     *
     * Encrypts one input block to one output block. Each block
     * is 16 bytes according to the AES encryption algorithm used.
     *
     * @param input
     *    Pointer to input block, must be 16 bytes
     *
     * @param output
     *    Pointer to output block, must be 16 bytes
     */
    void encrypt( const uint8_t* input, uint8_t* output );

    /**
     * Set new key
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
     * Computes the cipher stream for AES CM mode.
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
     * Counter-mode encryption.
     *
     * This method performs the AES CM encryption.
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
    void ctr_encrypt( const uint8_t* input,
		      uint32_t inputLen,
		      uint8_t* output, uint8_t* iv );

    /**
     * Counter-mode encryption, in place.
     *
     * This method performs the AES CM encryption.
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
    void ctr_encrypt( uint8_t* data,
		      uint32_t data_length,
		      uint8_t* iv );

    /**
     * AES F8 mode encryption, in place.
     *
     * This method performs the AES F8 encryption, see chapter 4.1.2
     * in RFC 3711.
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
     * @param key
     *    Pointer to the computed SRTP session key.
     *
     * @param keyLen
     *    The length in bytes of the computed SRTP session key.
     *
     * @param salt
     *    pointer to the computed session salt.
     *
     * @param saltLen
     *    The length in bytes of the computed SRTP session salt.
     *
     * @param f8Cipher
     *   An AES cipher context used for intermediate f8 AES encryption.
     */
    void f8_encrypt( const uint8_t* data,
		     uint32_t dataLen,
		     uint8_t* iv,
		     uint8_t* key,
		     int32_t  keyLen,
		     uint8_t* salt,
		     int32_t  saltLen,
	AesSrtp* f8Cipher);

    /**
     * AES F8 mode encryption.
     *
     * This method performs the AES F8 encryption, see chapter 4.1.2
     * in RFC 3711.
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
     * @param key
     *    Pointer to the computed SRTP session key.
     *
     * @param keyLen
     *    The length in bytes of the computed SRTP session key.
     *
     * @param salt
     *    pointer to the computed session salt.
     *
     * @param saltLen
     *    The length in bytes of the computed SRTP session salt.
     * 
     * @param f8Cipher
     *   An AES cipher context used for intermediate f8 AES encryption.
     */
    void f8_encrypt(const uint8_t* data,
		    uint32_t dataLen,
		    uint8_t* out,
		    uint8_t* iv,
		    uint8_t* key,
		    int32_t  keyLen,
		    uint8_t* salt,
		    int32_t  saltLen,
	AesSrtp* f8Cipher);


private:
    int processBlock(F8_CIPHER_CTX* f8ctx,
		     const uint8_t* in,
		     int32_t length,
		     uint8_t* out);
    void* key;
    int32_t algorithm;
};

/**
 * @}
 */

#endif

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */

