/*
Copyright 2017 Werner Dittmann

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//
// Created by werner on 21.05.17.
//

#ifndef PQCRYPTO_SIDH_SIDHKEYMANAGEMENT_H
#define PQCRYPTO_SIDH_SIDHKEYMANAGEMENT_H

/**
 * @file SidhKeyManagement.h
 * @brief 
 * @ingroup ZRTP
 * @{
 */

#include <stdint.h>
#include <cstring>
#include <cstdio>

#include <common/osSpecifics.h>

namespace sidh751KM {
    static const uint16_t KEY_ENTRIES = 2;          //!< Number of precomputed A and B key pairs


    static const uint16_t PRIME_WORD_BITS = 768;    //!< multiple of 32 larger than the prime bit length (from SIDH.c)
    static const uint16_t ORDER_WORD_BITS = 384;    //!< smallest multiple of 32 larger than the order bit length (from SIDH.c)

    static const uint16_t PRIME_LENGTH_BYTES = (PRIME_WORD_BITS + 7) / 8;

    static const uint16_t PRIVATE_KEY_LENGTH_BYTES = (ORDER_WORD_BITS + 7) / 8;
    static const uint16_t PUBLIC_KEY_LENGTH_BYTES = 3*2*PRIME_LENGTH_BYTES;
    static const uint16_t SHARED_SECRET_LENGTH = 2*PRIME_LENGTH_BYTES;

    using PrivateKey = uint8_t [PRIVATE_KEY_LENGTH_BYTES];
    using PublicKey  = uint8_t [PUBLIC_KEY_LENGTH_BYTES];
    using SharedSecret = uint8_t [SHARED_SECRET_LENGTH];

    enum KeyEntryType {
        KeyA,
        KeyB,
        None
    };

    struct KeyPair {
        PrivateKey privateKey;
        PublicKey  publicKey;

        KeyPair () {
            clearKeys();
        }

        ~KeyPair() {
            clearKeys();
        }

        void clearKeys() {
            memset(privateKey, 0, sizeof(privateKey));
            memset(publicKey, 0, sizeof(publicKey));
        }
    };

    class SidhKeyManagement {
    public:
        static __EXPORT bool initialize();

        static bool getKeyPairA(KeyPair* keyPair) { return getKeyPair(KeyA, keyPair); }
        static bool getKeyPairB(KeyPair* keyPair) { return getKeyPair(KeyB, keyPair); }

        static int32_t secretAgreement_A(const unsigned char* pPrivateKeyA, const unsigned char* pPublicKeyB, unsigned char* pSharedSecretA);
        static int32_t secretAgreement_B(const unsigned char* pPrivateKeyB, const unsigned char* pPublicKeyA, unsigned char* pSharedSecretB);

        static void stopKeyGeneration();

    private:
        SidhKeyManagement() {}
        ~SidhKeyManagement() {}

        static bool getKeyPair(KeyEntryType type, KeyPair* keyPair);

        SidhKeyManagement(const SidhKeyManagement& other)  = delete;
        SidhKeyManagement& operator=(const SidhKeyManagement& other)  = delete;
        bool operator==(const SidhKeyManagement& other) const = delete;
    };
}  // namespace
/**
 * @}
 */
#endif //PQCRYPTO_SIDH_SIDHKEYMANAGEMENT_H
