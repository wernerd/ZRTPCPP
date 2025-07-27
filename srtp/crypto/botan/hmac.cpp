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

struct macCtx {
    std::unique_ptr<Botan::MessageAuthenticationCode> hmac;
};


void hmac_sha1(const uint8_t *key, uint64_t const keyLength, const uint8_t *data, uint32_t const dataLength,
               uint8_t *mac, size_t *macLength) {
    auto const hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-1)");

    hmac->set_key(key, keyLength);
    hmac->update(data, dataLength);
    hmac->final(mac);
    *macLength = hmac->output_length();
}

void hmac_sha1(const uint8_t *key, uint64_t const keyLength,
               const std::vector<const uint8_t *> &data,
               const std::vector<uint64_t> &dataLength,
               uint8_t *mac, size_t *macLength) {
    auto const hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-1)");

    hmac->set_key(key, keyLength);

    for (size_t i = 0, size = data.size(); i < size; i++) {
        hmac->update(data[i], dataLength[i]);
    }
    hmac->final(mac);
    *macLength = hmac->output_length();
}

void *createSha1HmacContext() {
    auto *ctx = new macCtx;
    ctx->hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-1)");
    return ctx;
}

void *initializeSha1HmacContext(void *ctx, uint8_t const *key, uint64_t const keyLength) {
    auto *hd = static_cast<macCtx *>(ctx);

    if (hd != nullptr) {
        if (hd->hmac == nullptr) {
            hd->hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-1)");
        } else {
            hd->hmac->clear();
        }
        hd->hmac->set_key(key, keyLength);
    }
    return hd;
}

void hmacSha1Ctx(void *ctx, const uint8_t *data, uint64_t const dataLength,
                 uint8_t *mac, size_t *macLength) {
    auto const *const pctx = static_cast<macCtx *>(ctx);

    pctx->hmac->update(data, dataLength);
    pctx->hmac->final(mac);
    *macLength = pctx->hmac->output_length();
}

void hmacSha1Ctx(void *ctx,
                 const std::vector<const uint8_t *> &data,
                 const std::vector<uint64_t> &dataLength,
                 uint8_t *mac, size_t *macLength) {
    auto const *const pctx = static_cast<macCtx *>(ctx);

    for (size_t i = 0, size = data.size(); i < size; i++) {
        pctx->hmac->update(data[i], dataLength[i]);
    }
    pctx->hmac->final(mac);
    *macLength = pctx->hmac->output_length();
}

void freeSha1HmacContext(void *ctx) {
    if (auto *pctx = static_cast<macCtx *>(ctx); pctx != nullptr && pctx->hmac) {
        pctx->hmac->clear();
        pctx->hmac.reset();
        delete pctx;
    }
}
