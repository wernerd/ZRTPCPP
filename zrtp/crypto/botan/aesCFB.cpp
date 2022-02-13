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
 * @author  Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <string>

#include <botan_all.h>
#include <zrtp/crypto/aesCFB.h>

void aesCfbEncrypt(uint8_t *key, size_t keyLength, uint8_t* IV, uint8_t *data, size_t dataLength)
{
    auto enc = Botan::Cipher_Mode::create_or_throw(keyLength == 16 ? "AES-128/CFB" : "AES-256/CFB", Botan::ENCRYPTION);

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt(data, data + dataLength);

    enc->set_key(key, keyLength);
    enc->start(IV, 16);
    enc->finish(pt);

    memcpy(data, pt.data(), pt.size());
}

void aesCfbDecrypt(uint8_t *key, size_t keyLength, uint8_t* IV, uint8_t *data, size_t dataLength)
{
    auto enc = Botan::Cipher_Mode::create_or_throw(keyLength == 16 ? "AES-128/CFB" : "AES-256/CFB", Botan::DECRYPTION);

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt(data, data + dataLength);

    enc->set_key(key, keyLength);
    enc->start(IV, 16);
    enc->finish(pt);

    memcpy(data, pt.data(), pt.size());
}
