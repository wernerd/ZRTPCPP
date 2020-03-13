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
 * Methods to compute a Skein256 HMAC.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"
#ifndef HMAC_SKEIN256_H
#define HMAC_SKEIN256_H

/**
 * @file skeinMac256.h
 * @brief Function that provide Skein256 HMAC support
 * 
 * @ingroup ZRTP
 * @{
 */

#include <cstdint>
#include <vector>

#include "common/typedefs.h"

#ifndef SKEIN256_DIGEST_LENGTH
#define SKEIN256_DIGEST_LENGTH 32
#endif

#define SKEIN_SIZE Skein512

/**
 * Compute Skein256 HMAC.
 *
 * This functions takes one data chunk and computes its Skein256 HMAC.
 *
 * @param key
 *    The MAC key.
 * @param key_length
 *    Lneght of the MAC key in bytes
 * @param data
 *    Points to the data chunk.
 * @param dataLength
 *    Length of the data in bytes
 * @param macOut
 *    Reference to a secure array that receives the computed digest.
 */
void macSkein256(const uint8_t* key, uint64_t key_length, const uint8_t* data, uint64_t dataLength, zrtp::RetainedSecArray & macOut);

/**
 * Compute Skein256 HMAC over several data cunks.
 *
 * This functions takes several data chunk and computes the Skein256 HAMAC.
 *
 * @param key
 *    The MAC key.
 * @param key_length
 *    Lneght of the MAC key in bytes
 * @param data
 *    Vector of pointers that point to the data chunks.
 * @param dataLength
 *    Vector of integers that hold the length of each data chunk.
 * @param macOut
 *    Reference to a secure array that receives the computed digest.
 */

void macSkein256(const uint8_t* key, uint64_t key_length, const std::vector<const uint8_t*>& data,
                 const std::vector<uint64_t>& dataLength, zrtp::RetainedSecArray & macOut);
/**
 * @}
 */
#endif

#pragma clang diagnostic pop