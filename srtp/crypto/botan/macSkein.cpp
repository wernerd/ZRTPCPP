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


#include "crypto/macSkein.h"
#include <botan_all.h>
#include <cstdlib>

struct macCtx {
    std::unique_ptr<Botan::Skein_512> hmac = nullptr;
};

void macSkein(const uint8_t* key, uint64_t keyLength,
              const uint8_t* data, uint64_t dataLength,
              uint8_t* mac, size_t macLength, int skeinSize)
{
    (void) skeinSize;
    auto hmac = std::make_unique<Botan::Skein_512>(macLength, "" );

    hmac->setMacKey(key, keyLength);
    hmac->update(data, dataLength);
    hmac->final(mac);
}

void macSkein(const uint8_t* key, uint64_t keyLength,
              std::vector<const uint8_t*> data,
              std::vector<uint64_t> dataLength,
              uint8_t* mac, size_t mac_length, int skeinSize)
{
    auto hmac = std::make_unique<Botan::Skein_512>(mac_length, "" );

    hmac->setMacKey(key, keyLength);
    for (size_t i = 0, size = data.size(); i < size; i++) {
        hmac->update(data[i], dataLength[i]);
    }
    hmac->final(mac);
}

void* createSkeinMacContext(const uint8_t* key, uint64_t keyLength,
                            size_t macLength, int skeinSize)
{
    (void) skeinSize;
    auto* ctx = new macCtx;

    ctx->hmac = std::make_unique<Botan::Skein_512>(macLength, "" );
    ctx->hmac->setMacKey(key, keyLength);
    return ctx;
}

void* initializeSkeinMacContext(void* ctx, const uint8_t* key, uint64_t keyLength, size_t macLength, int skeinSize)
{
    (void) skeinSize;
    auto* hd = reinterpret_cast<macCtx *>(ctx);

    if (hd != nullptr) {
        if (hd->hmac == nullptr) {
            hd->hmac = std::make_unique<Botan::Skein_512>(macLength, "" );
        }
        else {
            // clears internal buffer only, keeps current key, MAC length and re-initializes initial block
            hd->hmac->clear();
        }
        hd->hmac->setMacKey(key, keyLength);        // also recomputes initial block with given key and MAC length
    }
    return (void*)hd;
}

void macSkeinCtx(void* ctx, const uint8_t* data, uint64_t dataLength, uint8_t* mac)
{
    auto* pctx = reinterpret_cast<macCtx *>(ctx);

    pctx->hmac->update(data, dataLength);
    pctx->hmac->final(mac);                 // computes MAC, recomputes initial block, ready for another MAC
}

void macSkeinCtx(void* ctx,
                 const std::vector<const uint8_t*>& data,
                 const std::vector<uint64_t>& dataLength,
                 uint8_t* mac)
{
    auto* pctx = reinterpret_cast<macCtx *>(ctx);

    for (size_t i = 0, size = data.size(); i < size; i++) {
        pctx->hmac->update(data[i], dataLength[i]);
    }
    pctx->hmac->final(mac);                 // computes MAC, recomputes initial block, ready for another MAC
}

void freeSkeinMacContext(void* ctx)
{
    auto *pctx = reinterpret_cast<macCtx *>(ctx);
    if (pctx != nullptr && pctx->hmac) {
        pctx->hmac->clear();
        pctx->hmac.reset();
        delete pctx;
    }
}
