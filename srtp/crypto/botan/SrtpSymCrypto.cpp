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

/**
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

// #define MAKE_F8_TEST
#include <cstring>

#include <crypto/SrtpSymCrypto.h>
#include <botan_all.h>
#include <common/osSpecifics.h>

SrtpSymCrypto::SrtpSymCrypto(int const algo) : algorithm(algo) {
}

SrtpSymCrypto::SrtpSymCrypto(uint8_t const *key, int32_t const keyLength, int const algo) : algorithm(algo) {
    setNewKey(key, keyLength);
}

SrtpSymCrypto::~SrtpSymCrypto() {
    if (crypto) {
        crypto->clear();
    }
}

bool SrtpSymCrypto::setNewKey(const uint8_t *key, int32_t const keyLength) {
    // release an existing key before setting a new one
    if (crypto) {
        crypto->clear();
    }

    if (!(keyLength == 16 || keyLength == 32)) {
        return false;
    }
    if (algorithm == SrtpEncryptionAESCM || algorithm == SrtpEncryptionAESF8) {
        crypto = keyLength == 32
                     ? Botan::BlockCipher::create_or_throw("AES-256")
                     : Botan::BlockCipher::create_or_throw("AES-128");
    } else if (algorithm == SrtpEncryptionTWOCM || algorithm == SrtpEncryptionTWOF8) {
        crypto = Botan::BlockCipher::create_or_throw("Twofish");
    } else
        return false;

    crypto->set_key(key, keyLength);
    return true;
}

void SrtpSymCrypto::encrypt(const uint8_t *input, uint8_t *output) const {
    crypto->encrypt(input, output);
}

void SrtpSymCrypto::get_ctr_cipher_stream(uint8_t *output, uint32_t const length, uint8_t *iv) const {
    uint32_t ctr = 0;
    unsigned char temp[SRTP_BLOCK_SIZE];

    for (ctr = 0; ctr < length / SRTP_BLOCK_SIZE; ctr++) {
        //compute the cipher stream
        iv[14] = static_cast<uint8_t>((ctr & 0xFF00U) >> 8U);
        iv[15] = static_cast<uint8_t>(ctr & 0x00FFU);

        encrypt(iv, &output[ctr * SRTP_BLOCK_SIZE]);
    }
    if (length % SRTP_BLOCK_SIZE > 0) {
        // handle the last bytes:
        iv[14] = static_cast<uint8_t>((ctr & 0xFF00U) >> 8U);
        iv[15] = static_cast<uint8_t>(ctr & 0x00FFU);

        encrypt(iv, temp);
        memcpy(&output[ctr * SRTP_BLOCK_SIZE], temp, length % SRTP_BLOCK_SIZE);
    }
}

void SrtpSymCrypto::ctr_encrypt(const uint8_t *input, uint32_t const inputLen, uint8_t *output, uint8_t *iv) const {
    if (!crypto)
        return;

    uint32_t ctr = 0;
    unsigned char temp[SRTP_BLOCK_SIZE];

    auto l = inputLen / SRTP_BLOCK_SIZE;
    for (ctr = 0; ctr < l; ctr++) {
        iv[14] = static_cast<uint8_t>((ctr & 0x0000FF00U) >> 8U);
        iv[15] = static_cast<uint8_t>(ctr & 0x000000FFU);

        encrypt(iv, temp);

        for (const auto &t: temp) {
            *output++ = t ^ *input++;
        }
    }
    l = inputLen % SRTP_BLOCK_SIZE;
    if (l > 0) {
        // Treat the last bytes:
        iv[14] = static_cast<uint8_t>((ctr & 0x0000FF00U) >> 8U);
        iv[15] = static_cast<uint8_t>(ctr & 0x000000FFU);

        encrypt(iv, temp);
        for (int i = 0; i < l; i++) {
            *output++ = temp[i] ^ *input++;
        }
    }
}

void SrtpSymCrypto::ctr_encrypt(uint8_t *data, uint32_t const data_length, uint8_t *iv) const {
    if (!crypto)
        return;

    uint32_t ctr = 0;
    unsigned char temp[SRTP_BLOCK_SIZE];

    auto l = data_length / SRTP_BLOCK_SIZE;
    for (ctr = 0; ctr < l; ctr++) {
        iv[14] = static_cast<uint8_t>((ctr & 0x0000FF00U) >> 8U);
        iv[15] = static_cast<uint8_t>(ctr & 0x000000FFU);

        encrypt(iv, temp);
        for (const auto &t: temp) {
            *data++ ^= t;
        }
    }
    l = data_length % SRTP_BLOCK_SIZE;
    if (l > 0) {
        // Treat the last bytes:
        iv[14] = static_cast<uint8_t>((ctr & 0x0000FF00U) >> 8U);
        iv[15] = static_cast<uint8_t>(ctr & 0x000000FFU);

        encrypt(iv, temp);
        for (int i = 0; i < l; i++) {
            *data++ ^= temp[i];
        }
    }
}

void SrtpSymCrypto::f8_encrypt(const uint8_t *data, uint32_t const dataLen,
                               uint8_t const *iv, SrtpSymCrypto const *f8Cipher) const {
    f8_encrypt(data, dataLen, const_cast<uint8_t *>(data), iv, f8Cipher);
}

#define MAX_KEYLEN 32

void SrtpSymCrypto::f8_deriveForIV(SrtpSymCrypto *f8Cipher, uint8_t const *keyIn, int32_t const keyLen,
                                   uint8_t const *salt, int32_t const saltLen) {
    unsigned char maskedKey[MAX_KEYLEN];
    unsigned char saltMask[MAX_KEYLEN];

    if (keyLen > MAX_KEYLEN)
        return;

    if (saltLen > keyLen)
        return;
    /*
     * First copy the salt into the mask field, then fill with 0x55 to
     * get a full key.
     */
    memcpy(saltMask, salt, saltLen);
    memset(saltMask + saltLen, 0x55, keyLen - saltLen);

    /*
     * XOR the original key with the above created mask to
     * get the special key.
     */
    unsigned char *cp_out = maskedKey;
    unsigned char const *cp_in = keyIn;
    unsigned char const *cp_in1 = saltMask;
    for (int i = 0; i < keyLen; i++) {
        *cp_out++ = *cp_in++ ^ *cp_in1++;
    }
    /*
     * Prepare the a new AES cipher with the special key to compute IV'
     */
    f8Cipher->setNewKey(maskedKey, keyLen);
}

void SrtpSymCrypto::f8_encrypt(const uint8_t *data, uint32_t dataLen, uint8_t *out,
                               uint8_t const *iv, SrtpSymCrypto const *f8Cipher) const {
    int offset = 0;

    unsigned char ivAccent[SRTP_BLOCK_SIZE];
    unsigned char S[SRTP_BLOCK_SIZE];

    F8_CIPHER_CTX f8ctx;

    if (!crypto)
        return;
    /*
     * Get memory for the derived IV (IV')
     */
    f8ctx.ivAccent = ivAccent;
    /*
     * Use the derived IV encryption setup to encrypt the original IV to produce IV'.
     */
    f8Cipher->encrypt(iv, f8ctx.ivAccent);

    f8ctx.J = 0; // initialize the counter
    f8ctx.S = S; // get the key stream buffer

    memset(f8ctx.S, 0, SRTP_BLOCK_SIZE); // initial value for key stream

    while (dataLen >= SRTP_BLOCK_SIZE) {
        processBlock(&f8ctx, data + offset, SRTP_BLOCK_SIZE, out + offset);
        dataLen -= SRTP_BLOCK_SIZE;
        offset += SRTP_BLOCK_SIZE;
    }
    if (dataLen > 0) {
        processBlock(&f8ctx, data + offset, dataLen, out + offset);
    }
}

uint32_t SrtpSymCrypto::processBlock(F8_CIPHER_CTX *f8ctx, const uint8_t *in, uint32_t const length,
                                     uint8_t *out) const {
    int i;

    /*
     * XOR the previous key stream with IV'
     * ( S(-1) xor IV' )
     */
    uint8_t const *cp_in = f8ctx->ivAccent;
    uint8_t *cp_out = f8ctx->S;
    for (i = 0; i < SRTP_BLOCK_SIZE; i++) {
        *cp_out++ ^= *cp_in++;
    }
    /*
     * Now XOR (S(n-1) xor IV') with the current counter, then increment the counter
     */
    auto *ui32p = reinterpret_cast<uint32_t *>(f8ctx->S);
    ui32p[3] ^= zrtpHtonl(f8ctx->J);
    f8ctx->J++;
    /*
     * Now compute the new key stream using AES encrypt
     */
    encrypt(f8ctx->S, f8ctx->S);
    /*
     * as the last step XOR the plain text with the key stream to produce
     * the cipher text.
     */
    cp_out = out;
    cp_in = in;
    uint8_t const *cp_in1 = f8ctx->S;
    for (i = 0; i < length; i++) {
        *cp_out++ = *cp_in++ ^ *cp_in1++;
    }
    return length;
}
