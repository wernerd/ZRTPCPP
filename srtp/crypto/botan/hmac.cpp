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

#include "crypto/hmac.h"
#include <botan_all.h>
#include <cstring>

struct macCtx {
    std::unique_ptr<Botan::MessageAuthenticationCode> hmac;
};


void hmac_sha1(const uint8_t *key, uint64_t keyLength, const uint8_t* data, uint32_t dataLength, uint8_t* mac, int32_t* macLength)
{
    auto hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-1)");

    hmac->set_key(key, keyLength);
    hmac->update(data, dataLength);
    hmac->final(mac);
    *macLength = SHA1_BLOCK_SIZE;
}

void hmac_sha1(const uint8_t* key, uint64_t keyLength,
               const std::vector<const uint8_t*>& data,
               const std::vector<uint64_t>& dataLength,
               uint8_t* mac, uint32_t* macLength )
{
    auto hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-1)");

    hmac->set_key(key, keyLength);

    for (size_t i = 0, size = data.size(); i < size; i++) {
        hmac->update(data[i], dataLength[i]);
    }
    hmac->final(mac);
    *macLength = SHA1_BLOCK_SIZE;
}

void* createSha1HmacContext()
{
    auto *ctx = new macCtx;
    ctx->hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-1)");
    return (void*)ctx;
}

void* initializeSha1HmacContext(void* ctx, uint8_t* key, uint64_t keyLength)
{
    auto* hd = reinterpret_cast<macCtx *>(ctx);

    if (hd != nullptr) {
        if (hd->hmac == nullptr) {
            hd->hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-1)");
        }
        else {
            hd->hmac->clear();
        }
        hd->hmac->set_key(key, keyLength);
    }
    return (void*)hd;
}

void hmacSha1Ctx(void* ctx, const uint8_t* data, uint64_t dataLength,
                uint8_t* mac, uint32_t* macLength)
{
    auto *pctx = reinterpret_cast<macCtx *>(ctx);

    pctx->hmac->update(data, dataLength);
    pctx->hmac->final(mac);
    *macLength = SHA1_BLOCK_SIZE;
}

void hmacSha1Ctx(void* ctx,
                 const std::vector<const uint8_t*>& data,
                 const std::vector<uint64_t>& dataLength,
                 uint8_t* mac, uint32_t* macLength )
{
    auto *pctx = reinterpret_cast<macCtx *>(ctx);

    for (size_t i = 0, size = data.size(); i < size; i++) {
        pctx->hmac->update(data[i], dataLength[i]);
    }
    pctx->hmac->final(mac);
    *macLength = SHA1_BLOCK_SIZE;
}

void freeSha1HmacContext(void* ctx)
{
    auto *pctx = reinterpret_cast<macCtx *>(ctx);
    if (pctx != nullptr && pctx->hmac) {
        pctx->hmac->clear();
        pctx->hmac.reset();
        delete pctx;
    }
}