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
 * @author: Werner Dittmann
 */

#include <botan_all.h>
#include <zrtp/crypto/sha256.h>

struct shaCtx {
    std::unique_ptr<Botan::HashFunction> hash;
};

void sha256(const uint8_t *data, uint64_t dataLength, uint8_t *digest )
{
    auto hash = Botan::HashFunction::create("SHA-256");
    hash->update(data, dataLength);
    hash->final(digest);
}

void sha256(const std::vector<const uint8_t*>& data, const std::vector<uint64_t>& dataLength, uint8_t *digest)
{
    auto hash = Botan::HashFunction::create("SHA-256");

    for (size_t i = 0, size = data.size(); i < size; i++) {
        hash->update(data[i], dataLength[i]);
    }
    hash->final(digest);
}

void* createSha256Context()
{
    auto *ctx = new shaCtx;
    ctx->hash = Botan::HashFunction::create("SHA-256");
    return (void*)ctx;
}

void closeSha256Context(void* ctx, uint8_t * digest)
{
    auto* hd = reinterpret_cast<shaCtx *>(ctx);

    if (digest != nullptr && hd != nullptr) {
        hd->hash->final(digest);
    }
    hd->hash.reset();
    delete hd;
}

void* initializeSha256Context(void* ctx)
{
    auto* hd = reinterpret_cast<shaCtx *>(ctx);

    if (hd != nullptr) {
        if (hd->hash == nullptr) {
            hd->hash = Botan::HashFunction::create("SHA-256");
        }
        else {
            hd->hash->clear();
        }
    }
    return (void*)hd;
}

void finalizeSha256Context(void* ctx, zrtp::RetainedSecArray & digestOut)
{
    auto* hd = reinterpret_cast<shaCtx *>(ctx);
    hd->hash->final(digestOut.data());
    digestOut.size(SHA256_DIGEST_SIZE);
}

void sha256Ctx(void* ctx, const uint8_t* data, uint64_t dataLength)
{
    auto* hd = reinterpret_cast<shaCtx *>(ctx);

    hd->hash->update(data, dataLength);
}

void sha256Ctx(void* ctx, const std::vector<const uint8_t*>& data, const std::vector<uint64_t>& dataLength)
{
    auto* hd = reinterpret_cast<shaCtx *>(ctx);

    for (size_t i = 0, size = data.size(); i < size; i++) {
        hd->hash->update(data[i], dataLength[i]);
    }
}
