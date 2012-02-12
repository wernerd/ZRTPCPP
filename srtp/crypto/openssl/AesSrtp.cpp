/*
  Copyright (C) 2005, 2004 Erik Eliasson, Johan Bilien

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

/**
 * @author Erik Eliasson <eliasson@it.kth.se>
 * @author Johan Bilien <jobi@via.ecp.fr>
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

extern void initializeOpenSSL();

#include <stdlib.h>
#include <openssl/aes.h>                // the include of openSSL
#include <crypto/AesSrtp.h>
#include <libzrtpcpp/crypto/twofish.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

AesSrtp::AesSrtp(int algo):key(NULL), algorithm(algo) {
}

AesSrtp::AesSrtp( uint8_t* k, int32_t keyLength, int algo ):
    key(NULL), algorithm(algo) {

    setNewKey(k, keyLength);
}

AesSrtp::~AesSrtp() {
    if (key != NULL)
        delete[] (uint8_t*)key;
}

static int twoFishInit = 0;

bool AesSrtp::setNewKey(const uint8_t* k, int32_t keyLength) {
    // release an existing key before setting a new one
    if (key != NULL)
        delete[] (uint8_t*)key;

    if (!(keyLength == 16 || keyLength == 32)) {
        return false;
    }
    if (algorithm == SrtpEncryptionAESCM) {
        key = new uint8_t[sizeof(AES_KEY)];
        memset(key, 0, sizeof(AES_KEY) );
        AES_set_encrypt_key(k, keyLength*8, (AES_KEY *)key);
    }
    else if (algorithm == SrtpEncryptionTWOCM) {
        if (!twoFishInit) {
            Twofish_initialise();
            twoFishInit = 1;
        }
        key = new uint8_t[sizeof(Twofish_key)];
        memset(key, 0, sizeof(Twofish_key));
        Twofish_prepare_key((Twofish_Byte*)k, keyLength,  (Twofish_key*)key);
    }
    else
        return false;
    
    return true;
}


void AesSrtp::encrypt(const uint8_t* input, uint8_t* output ) {
    if (algorithm == SrtpEncryptionAESCM) {
        AES_encrypt(input, output, (AES_KEY *)key);
    }
    else if (algorithm == SrtpEncryptionTWOCM) {
        Twofish_encrypt((Twofish_key*)key, (Twofish_Byte*)input,
                        (Twofish_Byte*)output); 
    }
}

void AesSrtp::get_ctr_cipher_stream(uint8_t* output, uint32_t length,
                                    uint8_t* iv ) {
    uint16_t ctr = 0;
    unsigned char temp[SRTP_BLOCK_SIZE];

    for(ctr = 0; ctr < length/SRTP_BLOCK_SIZE; ctr++) {
        //compute the cipher stream
        iv[14] = (uint8_t)((ctr & 0xFF00) >>  8);
        iv[15] = (uint8_t)((ctr & 0x00FF));

        encrypt(iv, &output[ctr*SRTP_BLOCK_SIZE]);
    }
    if ((length % SRTP_BLOCK_SIZE) > 0) {
        // Treat the last bytes:
        iv[14] = (uint8_t)((ctr & 0xFF00) >>  8);
        iv[15] = (uint8_t)((ctr & 0x00FF));

        encrypt(iv, temp);
        memcpy(&output[ctr*SRTP_BLOCK_SIZE], temp, length % SRTP_BLOCK_SIZE );
    }
}

void AesSrtp::ctr_encrypt(const uint8_t* input, uint32_t input_length,
                           uint8_t* output, uint8_t* iv ) {

    if (key == NULL)
        return;

    uint16_t ctr = 0;
    unsigned char temp[SRTP_BLOCK_SIZE];

    int l = input_length/SRTP_BLOCK_SIZE;
    for (ctr = 0; ctr < l; ctr++ ) {
        iv[14] = (uint8_t)((ctr & 0xFF00) >>  8);
        iv[15] = (uint8_t)((ctr & 0x00FF));

        encrypt(iv, temp);
        for (int i = 0; i < SRTP_BLOCK_SIZE; i++ ) {
            *output++ = temp[i] ^ *input++;
        }

    }
    l = input_length % SRTP_BLOCK_SIZE;
    if (l > 0) {
        // Treat the last bytes:
        iv[14] = (uint8_t)((ctr & 0xFF00) >>  8);
        iv[15] = (uint8_t)((ctr & 0x00FF));

        encrypt(iv, temp);
        for (int i = 0; i < l; i++ ) {
            *output++ = temp[i] ^ *input++;
        }
    }
}

void AesSrtp::ctr_encrypt( uint8_t* data, uint32_t data_length, uint8_t* iv ) {

    if (key == NULL)
        return;
    
    uint16_t ctr = 0;
    unsigned char temp[SRTP_BLOCK_SIZE];

    int l = data_length/SRTP_BLOCK_SIZE;
    for (ctr = 0; ctr < l; ctr++ ) {
        iv[14] = (uint8_t)((ctr & 0xFF00) >>  8);
        iv[15] = (uint8_t)((ctr & 0x00FF));

        encrypt(iv, temp);
        for (int i = 0; i < SRTP_BLOCK_SIZE; i++ ) {
            *data++ ^= temp[i];
        }

    }
    l = data_length % SRTP_BLOCK_SIZE;
    if (l > 0) {
        // Treat the last bytes:
        iv[14] = (uint8_t)((ctr & 0xFF00) >>  8);
        iv[15] = (uint8_t)((ctr & 0x00FF));

        encrypt(iv, temp);
        for (int i = 0; i < l; i++ ) {
            *data++ ^= temp[i];
        }
    }
}

void AesSrtp::f8_encrypt(const uint8_t* data, uint32_t data_length,
			 uint8_t* iv, uint8_t* origKey, int32_t keyLen,
			 uint8_t* salt, int32_t saltLen, AesSrtp* f8Cipher ) {

    f8_encrypt(data, data_length, const_cast<uint8_t*>(data), iv, origKey, keyLen, salt, saltLen, f8Cipher);
}

#define MAX_KEYLEN 32

void AesSrtp::f8_encrypt(const uint8_t* in, uint32_t in_length, uint8_t* out,
			 uint8_t* iv, uint8_t* origKey, int32_t keyLen,
			 uint8_t* salt, int32_t saltLen, AesSrtp* f8Cipher ) {


    unsigned char *cp_in, *cp_in1, *cp_out;
    int i;
    int offset = 0;

    unsigned char ivAccent[SRTP_BLOCK_SIZE];
    unsigned char maskedKey[MAX_KEYLEN];
    unsigned char saltMask[MAX_KEYLEN];
    unsigned char S[SRTP_BLOCK_SIZE];

    F8_CIPHER_CTX f8ctx;

    if (key == NULL)
        return;

    if (keyLen > MAX_KEYLEN)
        return;

    if (saltLen > keyLen)
        return;

    /*
     * Get memory for the derived IV (IV')
     */
    f8ctx.ivAccent = ivAccent;

    /*
     * First copy the salt into the mask field, then fill with 0x55 to
     * get a full key.
     */
    memcpy(saltMask, salt, saltLen);
    memset(saltMask+saltLen, 0x55, keyLen-saltLen);

    /*
     * XOR the original key with the above created mask to
     * get the special key.
     */
    cp_out = maskedKey;
    cp_in = origKey;
    cp_in1 = saltMask;
    for (i = 0; i < keyLen; i++) {
        *cp_out++ = *cp_in++ ^ *cp_in1++;
    }
    /*
     * Prepare the a new AES cipher with the special key to compute IV'
     */
    f8Cipher->setNewKey(maskedKey, keyLen);

    /*
     * Use the masked key to encrypt the original IV to produce IV'.
     *
     * After computing the IV' we don't need this cipher context anymore, free it.
     */
    f8Cipher->encrypt(iv, f8ctx.ivAccent);

    f8ctx.J = 0;                       // initialize the counter
    f8ctx.S = S;		       // get the key stream buffer

    memset(f8ctx.S, 0, SRTP_BLOCK_SIZE); // initial value for key stream

    while (in_length >= SRTP_BLOCK_SIZE) {
        processBlock(&f8ctx, in+offset, SRTP_BLOCK_SIZE, out+offset);
        in_length -= SRTP_BLOCK_SIZE;
        offset += SRTP_BLOCK_SIZE;
    }
    if (in_length > 0) {
        processBlock(&f8ctx, in+offset, in_length, out+offset);
    }
}

int AesSrtp::processBlock(F8_CIPHER_CTX *f8ctx, const uint8_t* in, int32_t length, uint8_t* out) {

    int i;
    const uint8_t *cp_in;
    uint8_t* cp_in1, *cp_out;
    uint32_t *ui32p;

    /*
     * XOR the previous key stream with IV'
     * ( S(-1) xor IV' )
     */
    cp_in = f8ctx->ivAccent;
    cp_out = f8ctx->S;
    for (i = 0; i < SRTP_BLOCK_SIZE; i++) {
        *cp_out++ ^= *cp_in++;
    }
    /*
     * Now XOR (S(n-1) xor IV') with the current counter, then increment the counter
     */
    ui32p = (uint32_t *)f8ctx->S;
    ui32p[3] ^= htonl(f8ctx->J);
    f8ctx->J++;
    /*
     * Now compute the new key stream using AES encrypt
     */
    encrypt(f8ctx->S, f8ctx->S);
    /*
     * as the last step XOR the plain text with the key stream to produce
     * the ciphertext.
     */
    cp_out = out;
    cp_in = in;
    cp_in1 = f8ctx->S;
    for (i = 0; i < length; i++) {
        *cp_out++ = *cp_in++ ^ *cp_in1++;
    }
    return length;
}


/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */

