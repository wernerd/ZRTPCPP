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

#include <openssl/hmac.h>
#include <zrtp/crypto/hmac384.h>

void hmac_sha384(const uint8_t* key, uint64_t key_length,
                 const uint8_t* data, uint64_t data_length,
                 zrtp::RetainedSecArray & macOut)
{
    unsigned int tmp;
    HMAC( EVP_sha384(), key, static_cast<int>(key_length), data, data_length, macOut.data(), &tmp );
    macOut.size(tmp);
}

void hmacSha384(const uint8_t* key, uint64_t key_length,
                const std::vector<const uint8_t*>& data,
                const std::vector<uint64_t>& dataLength,
                zrtp::RetainedSecArray & macOut)
{
    unsigned int tmp;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
	HMAC_CTX_init( &ctx );
	HMAC_Init_ex( &ctx, key, key_length, EVP_sha384(), NULL );
#else
    HMAC_CTX * ctx;
    ctx = HMAC_CTX_new();
    HMAC_Init_ex( ctx, key, key_length, EVP_sha384(), nullptr );
#endif
    for (size_t i = 0, size = data.size(); i < size; i++) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Update(&ctx, data[i], dataLength[i]);
#else
        HMAC_Update(ctx, data[i], dataLength[i]);
#endif
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_Final( &ctx, macOut.data(), &tmp);
#else
    HMAC_Final( ctx, macOut.data(), &tmp);
#endif
    macOut.size(tmp);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup( &ctx );
#else
    HMAC_CTX_free( ctx );
#endif
}
