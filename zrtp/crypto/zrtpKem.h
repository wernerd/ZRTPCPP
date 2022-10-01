//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Created by werner on 28.09.22.
// Copyright (c) 2022 Werner Dittmann. All rights reserved.
//

#ifndef LIBZRTPCPP_ZRTPKEM_H
#define LIBZRTPCPP_ZRTPKEM_H

/*
 * sntrup Public Domain, Authors:
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#include <cstdint>
#include "botancrypto/ZrtpBotanRng.h"

using int8 = std::int8_t;
using uint8 = std::uint8_t;
using int16 = std::int16_t;
using uint16 = std::uint16_t;
using int32 = std::int32_t;
using uint32 = std::uint32_t;
using int64 = std::int64_t;
using uint64 = std::uint64_t;

constexpr size_t SNTRUP_CRYPTO_SECRETKEYBYTES_653 = 1518;
constexpr size_t SNTRUP_CRYPTO_PUBLICKEYBYTES_653 = 994;
constexpr size_t SNTRUP_CRYPTO_CIPHERTEXTBYTES_653 = 897;

constexpr size_t SNTRUP_CRYPTO_SECRETKEYBYTES_953 = 2254;
constexpr size_t SNTRUP_CRYPTO_PUBLICKEYBYTES_953 = 1505;
constexpr size_t SNTRUP_CRYPTO_CIPHERTEXTBYTES_953 = 1349;

constexpr size_t SNTRUP_CRYPTO_SECRETKEYBYTES = 3059;
constexpr size_t SNTRUP_CRYPTO_PUBLICKEYBYTES = 2067;
constexpr size_t SNTRUP_CRYPTO_CIPHERTEXTBYTES = 1847;

constexpr size_t CRYPTO_BYTES = 32;


/* from supercop/crypto_sort/int32/portable4/int32_minmax.inc */
#define int32_MINMAX(a,b) \
do { \
  int64_t ab = (int64_t)b ^ (int64_t)a; \
  int64_t c = (int64_t)b - (int64_t)a; \
  c ^= ab & (c ^ b); \
  c >>= 31; \
  c &= ab; \
  a ^= c; \
  b ^= c; \
} while(0)

/* from supercop/crypto_sort/int32/portable4/sort.c */
void crypto_sort_int32(void *array,long long n);

/* from supercop/crypto_sort/uint32/useint32/sort.c */
void crypto_sort_uint32(void *array,long long n);

/* from supercop/crypto_kem/sntrup761/ref/uint32.c */
void uint32_divmod_uint14(uint32 *q,uint16 *r,uint32 x,uint16 m);
uint32 uint32_div_uint14(uint32 x,uint16 m);
uint16 uint32_mod_uint14(uint32 x,uint16 m);

/* from supercop/crypto_kem/sntrup761/ref/int32.c */
void int32_divmod_uint14(int32 *q,uint16 *r,int32 x,uint16 m);
int32 int32_div_uint14(int32 x,uint16 m);
uint16 int32_mod_uint14(int32 x,uint16 m);


int crypto_kem_sntrup653_keypair(unsigned char *pk,unsigned char *sk);
int crypto_kem_sntrup653_enc(unsigned char *c,unsigned char *k,const unsigned char *pk);
int crypto_kem_sntrup653_dec(unsigned char *k,const unsigned char *c,const unsigned char *sk);

int crypto_kem_sntrup953_keypair(unsigned char *pk,unsigned char *sk);
int crypto_kem_sntrup953_enc(unsigned char *c,unsigned char *k,const unsigned char *pk);
int crypto_kem_sntrup953_dec(unsigned char *k,const unsigned char *c,const unsigned char *sk);

int crypto_kem_sntrup1277_keypair(unsigned char *pk,unsigned char *sk);
int crypto_kem_sntrup1277_enc(unsigned char *c,unsigned char *k,const unsigned char *pk);
int crypto_kem_sntrup1277_dec(unsigned char *k,const unsigned char *c,const unsigned char *sk);


// Map some functions used by sntrup implementation to our existing internal functions
inline void randombytes(unsigned char* c, unsigned long length) {
    ZrtpBotanRng::getRandomData(c, length);
}

inline void crypto_declassify(int* result, unsigned long len) { /* no-op */ }

int crypto_hash_sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen);

#endif //LIBZRTPCPP_ZRTPKEM_H
