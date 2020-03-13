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

#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

/**
 * @file hmac256.h
 * @brief Function that provide SHA256 HMAC support
 * 
 * @ingroup ZRTP
 * @{
 */

#include <cstdint>
#include <vector>

#include "common/typedefs.h"

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

/**
 * Compute SHA256 HMAC.
 *
 * This functions takes one data chunk and computes its SHA256 HMAC.
 *
 * @param key
 *    The MAC key.
 * @param key_length
 *    Length of the MAC key in bytes
 * @param data
 *    Points to the data chunk.
 * @param data_length
 *    Length of the data in bytes
 * @param macOut
 *    Reference to a secure array that receives the computed digest.
 */
void hmac_sha256(const uint8_t* key, uint64_t key_length,
                 const uint8_t* data, uint64_t data_length,
                 zrtp::RetainedSecArray & macOut);

/**
 * Compute SHA256 HMAC over several data chunks.
 *
 * This functions takes several data chunk and computes the SHA256 HMAC. It
 * uses the openSSL HMAC SHA256 implementation.
 *
 * @param key
 *    The MAC key.
 * @param key_length
 *    Length of the MAC key in bytes
 * @param data
 *    Vector of pointers that point to the data chunks. A NULL
 *    pointer in an array element terminates the data chunks.
 * @param dataLength
 *    Vector of integers that hold the length of each data chunk.
 * @param macOut
 *    Reference to a secure array that receives the computed digest.
 */

void hmacSha256(const uint8_t* key, uint64_t key_length,
                const std::vector<const uint8_t*>& data,
                const std::vector<uint64_t>& dataLength,
                zrtp::RetainedSecArray & macOut);
/**
 * @}
 */
#endif
