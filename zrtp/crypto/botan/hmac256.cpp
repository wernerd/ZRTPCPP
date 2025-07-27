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

#include <botan_all.h>
#include "zrtp/crypto/hmac256.h"

struct shaCtx {
    std::unique_ptr<Botan::MessageAuthenticationCode> mac = nullptr;
};

void hmac_sha256(const uint8_t* key, uint64_t const keyLength, const uint8_t* data, uint64_t const dataLength,
                 zrtp::RetainedSecArray &macOut) {
    auto const hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");

    hmac->set_key(key, keyLength);
    hmac->update(data, dataLength);
    hmac->final(macOut.data());
    macOut.size(hmac->output_length());
}

void hmacSha256(const uint8_t* key, uint64_t const keyLength,
                const std::vector<const uint8_t *> &dataChunks,
                const std::vector<uint64_t> &dataChunkLength,
                zrtp::RetainedSecArray &macOut) {
    auto const hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");

    hmac->set_key(key, keyLength);

    for (size_t i = 0, size = dataChunks.size(); i < size; i++) {
        hmac->update(dataChunks[i], dataChunkLength[i]);
    }
    hmac->final(macOut.data());
    macOut.size(hmac->output_length());
}

void*
createSha256HmacContext(uint8_t const* key, size_t const keyLength) {
    auto* ctx = new shaCtx;
    ctx->mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
    ctx->mac->set_key(key, keyLength);
    return ctx;
}

void hmacSha256Ctx(void* ctx,
                   const std::vector<const uint8_t *> &dataChunks,
                   const std::vector<uint64_t> &dataChunkLength,
                   zrtp::RetainedSecArray &macOut) {
    if (auto const* ctxIntern = static_cast<shaCtx *>(ctx); ctxIntern != nullptr) {
        for (size_t i = 0, size = dataChunks.size(); i < size; i++) {
            ctxIntern->mac->update(dataChunks[i], dataChunkLength[i]);
        }
        ctxIntern->mac->final(macOut.data());
        macOut.size(ctxIntern->mac->output_length());
    }
}

void freeSha256HmacContext(void* ctx) {
    auto const * ctxIntern = static_cast<shaCtx *>(ctx);
    delete ctxIntern;
}
