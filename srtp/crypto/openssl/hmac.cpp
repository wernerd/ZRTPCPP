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
 * Authors: Werner Dittmann
 */

#include <cstdint>
#include <openssl/hmac.h>
#include <vector>

void hmac_sha1(const uint8_t* key, int64_t keyLength,
               const uint8_t* data, uint64_t dataLength,
               uint8_t* mac, int32_t* macLength)
{
    HMAC(EVP_sha1(), key, static_cast<int>(keyLength),
         data, dataLength, mac,
         reinterpret_cast<uint32_t*>(macLength));
}

void hmac_sha1(const uint8_t* key, uint64_t keyLength,
               const std::vector<const uint8_t*>& data,
               const std::vector<uint64_t>& dataLength,
               uint8_t* mac, int32_t* macLength) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key, key_length, EVP_sha1(), nullptr);
#else
    HMAC_CTX* ctx;
    ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, keyLength, EVP_sha1(), nullptr);
#endif
    for (size_t i = 0, size = data.size(); i < size; i++) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Update(&ctx, data[i], dataLength[i]);
#else
        HMAC_Update(ctx, data[i], dataLength[i]);
#endif
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_Final(&ctx, mac, reinterpret_cast<uint32_t*>(macLength));
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_Final(ctx, mac, reinterpret_cast<uint32_t*>(macLength));
    HMAC_CTX_free( ctx );
#endif
}

void* createSha1HmacContext()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    auto* ctx = (HMAC_CTX*)malloc(sizeof(HMAC_CTX));
    HMAC_CTX_init(ctx);
#else
    auto* ctx = HMAC_CTX_new();
#endif
    return ctx;
}

void* initializeSha1HmacContext(void* ctx, uint8_t* key, uint64_t keyLength)
{
    auto *pctx = (HMAC_CTX*)ctx;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_init(pctx);
#else
    HMAC_CTX_reset(pctx);
#endif
    HMAC_Init_ex(pctx, key, static_cast<int>(keyLength), EVP_sha1(), nullptr);
    return pctx;
}

void hmacSha1Ctx(void* ctx, const uint8_t* data, uint64_t data_length,
                 uint8_t* mac, int32_t* mac_length)
{
    auto* pctx = (HMAC_CTX*)ctx;

    HMAC_Init_ex(pctx, nullptr, 0, nullptr, nullptr);
    HMAC_Update(pctx, data, data_length );
    HMAC_Final(pctx, mac, reinterpret_cast<uint32_t*>(mac_length) );
}

void hmacSha1Ctx(void* ctx,
                 const std::vector<const uint8_t*>& data,
                 const std::vector<uint64_t>& dataLength,
                 uint8_t* mac, uint32_t* macLength)
{
    auto* pctx = (HMAC_CTX*)ctx;

    HMAC_Init_ex(pctx, nullptr, 0, nullptr, nullptr);
    for (size_t i = 0, size = data.size(); i < size; i++) {
        HMAC_Update(pctx, data[i], dataLength[i]);
    }
    HMAC_Final(pctx, mac, reinterpret_cast<uint32_t*>(macLength) );
}

void freeSha1HmacContext(void* ctx)
{
    if (ctx) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_CTX_cleanup((HMAC_CTX*)ctx);
		free(ctx);
#else
        HMAC_CTX_free((HMAC_CTX*)ctx);
#endif
    }
}