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
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <cstdio>
#include <cstring>
#include <cstdint>

#include <common/osSpecifics.h>

#include "srtp/CryptoContext.h"

#include "crypto/hmac.h"
#include "crypto/SrtpSymCrypto.h"
#include "crypto/macSkein.h"

CryptoContext::CryptoContext(
    uint32_t const ssrc,
    int32_t const roc,
    int64_t const keyDerivRate,
    int32_t const ealg,
    int32_t const aalg,
    uint8_t const *masterKey,
    int32_t const masterKeyLength,
    uint8_t const *masterSalt,
    int32_t const masterSaltLength,
    int32_t const ekeyl,
    int32_t const akeyl,
    int32_t const skeyl,
    int32_t const tagLength
): ssrcCtx(ssrc), mkiLength(0), mki(nullptr), roc(roc),
   guessed_roc(0), s_l(0), key_deriv_rate(keyDerivRate),
   labelBase(0), seqNumSet(false), macCtx(nullptr), cipher(nullptr),
   f8Cipher(nullptr) {

    replay_window[0] = replay_window[1] = 0;
    this->ealg = ealg;
    this->aalg = aalg;
    this->ekeyl = ekeyl;
    this->akeyl = akeyl;
    this->skeyl = skeyl;

    this->master_key_length = masterKeyLength;
    this->master_key = new uint8_t[masterKeyLength];
    memcpy(this->master_key, masterKey, masterKeyLength);

    this->master_salt_length = masterSaltLength;
    this->master_salt = new uint8_t[masterSaltLength];
    memcpy(this->master_salt, masterSalt, masterSaltLength);

    switch (ealg) {
        case SrtpEncryptionNull:
            n_e = 0;
            k_e = nullptr;
            n_s = 0;
            k_s = nullptr;
            break;

        case SrtpEncryptionTWOF8:
            f8Cipher = std::make_unique<SrtpSymCrypto>(SrtpEncryptionTWOF8);

        case SrtpEncryptionTWOCM:
            n_e = ekeyl;
            k_e = new uint8_t[n_e];
            n_s = skeyl;
            k_s = new uint8_t[n_s];
            cipher = std::make_unique<SrtpSymCrypto>(SrtpEncryptionTWOCM);
            break;

        case SrtpEncryptionAESF8:
            f8Cipher = std::make_unique<SrtpSymCrypto>(SrtpEncryptionAESF8);

        case SrtpEncryptionAESCM:
            n_e = ekeyl;
            k_e = new uint8_t[n_e];
            n_s = skeyl;
            k_s = new uint8_t[n_s];
            cipher = std::make_unique<SrtpSymCrypto>(SrtpEncryptionAESCM);
            break;

        default:
            break; // throw exception? - cannot handle unknown encryption - what else?
    }

    switch (aalg) {
        case SrtpAuthenticationNull:
            n_a = 0;
            k_a = nullptr;
            this->tagLength = 0;
            break;

        case SrtpAuthenticationSha1Hmac:
        case SrtpAuthenticationSkeinHmac:
            n_a = akeyl;
            k_a = new uint8_t[n_a];
            this->tagLength = tagLength;
            break;

        default:
            break; // throw exception? - cannot handle unknown authentication - what else?
    }
}

/*
 * memset_volatile is a volatile pointer to the memset function.
 * You can call (*memset_volatile)(buf, val, len) or even
 * memset_volatile(buf, val, len) just as you would call
 * memset(buf, val, len), but the use of a volatile pointer
 * guarantees that the compiler will not optimise the call away.
 */
static void * (*volatile memset_volatile)(void *, int, size_t) = memset;

CryptoContext::~CryptoContext() {
    delete [] mki;

    if (master_key_length > 0) {
        memset_volatile(master_key, 0, master_key_length);
        master_key_length = 0;
        delete [] master_key;
    }
    if (master_salt_length > 0) {
        memset_volatile(master_salt, 0, master_salt_length);
        master_salt_length = 0;
        delete [] master_salt;
    }
    if (n_e > 0) {
        memset_volatile(k_e, 0, n_e);
        n_e = 0;
        delete [] k_e;
    }
    if (n_s > 0) {
        memset_volatile(k_s, 0, n_s);
        n_s = 0;
        delete [] k_s;
    }
    if (n_a > 0) {
        memset_volatile(k_a, 0, n_a);
        n_a = 0;
        delete [] k_a;
    }

    if (aalg == SrtpAuthenticationSha1Hmac) {
        freeSha1HmacContext(macCtx);
    } else {
        freeSkeinMacContext(macCtx);
    }
}

void CryptoContext::srtpEncrypt(uint8_t const *pkt, uint8_t *payload, uint32_t const paylen, uint64_t const index,
                                uint32_t const ssrc) const {
    if (ealg == SrtpEncryptionNull) {
        return;
    }
    if (ealg == SrtpEncryptionAESCM || ealg == SrtpEncryptionTWOCM) {
        /* Compute the CM IV (refer to chapter 4.1.1 in RFC 3711):
         *
         * k_s   XX XX XX XX XX XX XX XX XX XX XX XX XX XX
         * SSRC              XX XX XX XX
         * index                         XX XX XX XX XX XX
         * ------------------------------------------------------XOR
         * IV    XX XX XX XX XX XX XX XX XX XX XX XX XX XX 00 00
         */

        unsigned char iv[16];
        memcpy(iv, k_s, 4);

        int i;
        for (i = 4; i < 8; i++) {
            iv[i] = 0xFFU & ssrc >> ((7 - i) * 8U) ^ k_s[i];
        }
        for (i = 8; i < 14; i++) {
            iv[i] = 0xFFU & static_cast<unsigned char>(index >> (13 - i) * 8U) ^ k_s[i];
        }
        iv[14] = iv[15] = 0;

        cipher->ctr_encrypt(payload, paylen, iv);
    }

    if (ealg == SrtpEncryptionAESF8 || ealg == SrtpEncryptionTWOF8) {
        /* Create the F8 IV (refer to chapter 4.1.2.2 in RFC 3711):
         *
         * IV = 0x00 || M || PT || SEQ  ||      TS    ||    SSRC   ||    ROC
         *      8Bit  1bit  7bit  16bit       32bit        32bit        32bit
         * ------------\     /--------------------------------------------------
         *       XX       XX      XX XX   XX XX XX XX   XX XX XX XX  XX XX XX XX
         */

        unsigned char iv[16];

        memcpy(iv, pkt, 12);
        iv[0] = 0;

        // set ROC in network order into IV
        auto *ui32p = reinterpret_cast<uint32_t *>(iv); // well, dirty trick but works
        ui32p[3] = zrtpHtonl(roc);

        cipher->f8_encrypt(payload, paylen, iv, f8Cipher.get());
    }
}

/* Warning: tag must have been initialized */
void CryptoContext::srtpAuthenticate(uint8_t const *pkt, uint32_t const pktlen, uint32_t const rocLocal,
                                     uint8_t *tag) const {
    if (aalg == SrtpAuthenticationNull) {
        return;
    }
    size_t macL;

    unsigned char temp[20];

    std::vector<const uint8_t *> chunks;
    std::vector<uint64_t> chunkLength;
    uint32_t const beRoc = zrtpHtonl(rocLocal);

    chunks.push_back(pkt);
    chunkLength.push_back(pktlen);

    chunks.push_back(reinterpret_cast<unsigned char const *>(&beRoc));
    chunkLength.push_back(4);

    switch (aalg) {
        case SrtpAuthenticationSha1Hmac:
            hmacSha1Ctx(macCtx,
                        chunks, // data chunks to hash
                        chunkLength, // length of the data to hash
                        temp, &macL);
            /* truncate the result */
            memcpy(tag, temp, getTagLength());
            break;
        case SrtpAuthenticationSkeinHmac:
            macSkeinCtx(macCtx,
                        chunks, // data chunks to hash
                        chunkLength, // length of the data to hash
                        temp);
            /* truncate the result */
            memcpy(tag, temp, getTagLength());
            break;

        default:
            ;
    }
}

/* used by the key derivation method */
static void computeIv(unsigned char *iv, uint64_t const label, uint64_t const index, int64_t const kdv,
                      unsigned char const *master_salt) {
    uint64_t key_id;

    if (kdv == 0) {
        key_id = label << 48U;
    } else {
        key_id = label << 48U | index / kdv;
    }

    //printf( "Key_ID: %llx\n", key_id );

    /* compute the IV
       key_id:                           XX XX XX XX XX XX XX
       master_salt: XX XX XX XX XX XX XX XX XX XX XX XX XX XX
       ------------------------------------------------------------ XOR
       IV:          XX XX XX XX XX XX XX XX XX XX XX XX XX XX 00 00
    */

    int i;
    for (i = 0; i < 7; i++) {
        iv[i] = master_salt[i];
    }

    for (i = 7; i < 14; i++) {
        iv[i] = static_cast<unsigned char>(0xFFU & key_id >> 8U * (13 - i)) ^ master_salt[i];
    }
    iv[14] = iv[15] = 0;
}

/* Derive the srtp session keys from the master key */
void CryptoContext::deriveSrtpKeys(uint64_t const index) {
    uint8_t iv[16];

    // prepare cipher to compute derived keys.
    cipher->setNewKey(master_key, master_key_length);
    memset(master_key, 0, master_key_length);

    // compute the session encryption key
    uint64_t label = labelBase + 0;
    computeIv(iv, label, index, key_deriv_rate, master_salt);
    cipher->get_ctr_cipher_stream(k_e, n_e, iv);

    // compute the session authentication key
    label = labelBase + 0x01;
    computeIv(iv, label, index, key_deriv_rate, master_salt);
    cipher->get_ctr_cipher_stream(k_a, n_a, iv);

    // Initialize MAC context with the derived key
    switch (aalg) {
        case SrtpAuthenticationSha1Hmac:
            macCtx = createSha1HmacContext();
            macCtx = initializeSha1HmacContext(macCtx, k_a, n_a);
            break;

        case SrtpAuthenticationSkeinHmac:
            macCtx = createSkeinMacContext(k_a, n_a, tagLength * 8, 0);
            break;

        default:
            ;
    }
    memset(k_a, 0, n_a);

    // compute the session salt
    label = labelBase + 0x02;
    computeIv(iv, label, index, key_deriv_rate, master_salt);
    cipher->get_ctr_cipher_stream(k_s, n_s, iv);
    memset(master_salt, 0, master_salt_length);

    // as last step prepare cipher with derived key.
    cipher->setNewKey(k_e, n_e);
    if (f8Cipher != nullptr)
        SrtpSymCrypto::f8_deriveForIV(f8Cipher.get(), k_e, n_e, k_s, n_s);
    memset(k_e, 0, n_e);
}

/* Based on the algorithm provided in Appendix A - draft-ietf-srtp-05.txt */
uint64_t CryptoContext::guessIndex(uint16_t const newSeqNumber) {
    /*
     * Initialize the sequences number on first call that uses the
     * sequence number. Either GuessIndex() or checkReplay().
     */
    if (!seqNumSet) {
        seqNumSet = true;
        s_l = newSeqNumber;
    }
    if (s_l < 32768) {
        if (newSeqNumber - s_l > 32768) {
            guessed_roc = roc - 1;
        } else {
            guessed_roc = roc;
        }
    } else {
        if (s_l - 32768 > newSeqNumber) {
            guessed_roc = roc + 1;
        } else {
            guessed_roc = roc;
        }
    }

    return static_cast<uint64_t>(guessed_roc) << 16U | newSeqNumber;
}


bool CryptoContext::checkReplay(uint16_t const newSeqNumber) {
    if (aalg == SrtpAuthenticationNull && ealg == SrtpEncryptionNull) {
        /* No security policy, don't use the replay protection */
        return true;
    }

    /*
     * Initialize the sequences number on first call that uses the
     * sequence number. Either guessIndex() or checkReplay().
     */
    if (!seqNumSet) {
        seqNumSet = true;
        s_l = newSeqNumber;
    }
    uint64_t const local_index = static_cast<uint64_t>(roc) << 16U | s_l;

    if (auto delta = static_cast<int64_t>(guessIndex(newSeqNumber) - local_index); delta > 0) {
        return true; /* Packet isn't yet received*/
    } else {
        delta = -delta;
        if (delta >= REPLAY_WINDOW_SIZE) {
            return false; /* Packet too old */
        }

        auto const idx = delta / 64;
        uint64_t const bit = 1UL << static_cast<uint32_t>(delta % 64);

        return (replay_window[idx] & bit) != bit;
    }
}

// This function assumes that it never gets a sequence number that is out of order
// greater or equal than REPLAY_WINDOW_SIZE. Thus an application MUST perform a
// replay check first and discard any packet which fails this check. This restriction
// applies to older packets only, a new (not seen) packet's sequence number can jump
// ahead by more than REPLAY_WINDOW_SIZE.
void CryptoContext::update(uint16_t const newSeqNumber) {
    // Get the index of the new sequence number and compute the delta to the
    // index of the highest sequence number we received so far. If the delta
    // is negative then we received an older packet, thus we will not
    // update the locally stored remote sequence number (s_l) below.

    // Convert the unsigned to a signed (isnt't C/C++ nice ;) ). Next step use delat as a signed value
    auto delta = static_cast<int64_t>(guessIndex(newSeqNumber) - (static_cast<uint64_t>(roc) << 16U | s_l));
    int64_t const rocDelta = delta;

    // update the replay shift register
    // The shift register array stores bits of newer packets (higher sequence numbers) at
    // index 0 and shifts older packets (lower sequence numbers) left to index one
    if (delta > 0) {
        // We got a new packet, no yet seen
        if (delta >= REPLAY_WINDOW_SIZE) {
            replay_window[0] = 1;
            replay_window[1] = 0;
        } else {
            if (delta < REPLAY_WINDOW_SIZE / 2) {
                uint64_t const carry = replay_window[0] >> static_cast<uint32_t>(REPLAY_WINDOW_SIZE / 2 - delta);
                replay_window[0] = replay_window[0] << static_cast<uint32_t>(delta) | 1U;
                replay_window[1] = replay_window[1] << static_cast<uint32_t>(delta) | carry;
            } else {
                replay_window[1] = replay_window[0] << static_cast<uint32_t>(delta - REPLAY_WINDOW_SIZE / 2);
                replay_window[0] = 1;
            }
        }
    } else {
        delta = -delta;
        auto const idx = delta / 64;
        uint64_t const bit = 1UL << static_cast<uint32_t>(delta % 64);
        replay_window[idx] |= bit;
    }

    // update the locally stored ROC and highest sequence number if we received a not
    // yet received packet, i.e. the delta is > 0
    if (rocDelta > 0 && newSeqNumber > s_l) {
        s_l = newSeqNumber;
    }
    // Reset local stored sequence number (low 16 bits) also if ROC increases
    // The guessed_roc is bigger than roc only if we received a not yet seen packet.
    if (guessed_roc > roc) {
        roc = guessed_roc;
        s_l = newSeqNumber;
    }
}

CryptoContext *CryptoContext::newCryptoContextForSSRC(uint32_t const ssrc, int const rocLocal,
                                                      int64_t const keyDerivRate) const {
    auto *pcc = new CryptoContext(
        ssrc,
        rocLocal, // Roll over Counter,
        keyDerivRate, // keyderivation << 48,
        this->ealg, // encryption algo
        this->aalg, // authentication algo
        this->master_key, // Master Key
        this->master_key_length, // Master Key length
        this->master_salt, // Master Salt
        this->master_salt_length, // Master Salt length
        this->ekeyl, // encryption keyl
        this->akeyl, // authentication key len
        this->skeyl, // session salt len
        this->tagLength); // authentication tag len

    return pcc;
}
