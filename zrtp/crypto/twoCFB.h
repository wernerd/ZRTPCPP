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

#ifndef TWOCFB_H_
#define TWOCFB_H_

#include <cstdint>

/**
 * @file aesCFB.h
 * @brief Function that provides AES CFB mode support
 * 
 * @ingroup ZRTP
 * @{
 */

#ifndef TWO_BLOCK_SIZE
#define TWO_BLOCK_SIZE 16
#endif

/**
 * Encrypt data with Twofish CFB mode, full block feedback size.
 *
 * This function takes one data chunk and encrypts it with
 * Twofish CFB mode. The length of the data may be arbitrary, and
 * it is unnecessary to be a multiple of Twofish blocksize.
 *
 * @param key
 *    Points to the key bytes.
 * @param keyLength
 *    Length of the key in bytes
 * @param IV
 *    The initialization vector which must be TWO_BLOCKSIZE (16) bytes.
 * @param data
 *    Points to a buffer that contains and receives the computed
 *    the data (in-place encryption).
 * @param dataLength
 *    Length of the data in bytes
 */

void twoCfbEncrypt(uint8_t const* key, size_t keyLength, uint8_t const* IV, uint8_t* data, size_t dataLength);

/**
 * Decrypt data with Twofish CFB mode, full block feedback size.
 *
 * This function takes one data chunk and decrypts it with
 * Twofish CFB mode. The length of the data may be arbitrary, and
 * it is unnecessary to be a multiple of Twofish blocksize.
 *
 * @param key
 *    Points to the key bytes.
 * @param keyLength
 *    Length of the key in bytes
 * @param IV
 *    The initialization vector which must be TWO_BLOCKSIZE (16) bytes.
 * @param data
 *    Points to a buffer that contains and receives the computed
 *    the data (in-place decryption).
 * @param dataLength
 *    Length of the data in bytes
 */

void twoCfbDecrypt(uint8_t const* key, size_t keyLength, uint8_t const* IV, uint8_t* data, size_t dataLength);

/**
 * @}
 */
#endif // TWOCFB_H_
