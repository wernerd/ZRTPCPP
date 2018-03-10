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

#include <stdint.h>
#include <openssl/hmac.h>
#include <crypto/hmac.h>

void hmac_sha1(uint8_t * key, int32_t key_length,
               const uint8_t* data, uint32_t data_length,
               uint8_t* mac, int32_t* mac_length )
{
    HMAC(EVP_sha1(), key, key_length,
         data, data_length, mac,
         reinterpret_cast<uint32_t*>(mac_length) );
}

void hmac_sha1( uint8_t* key, int32_t key_length,
                const uint8_t* data_chunks[],
                uint32_t data_chunck_length[],
                uint8_t* mac, int32_t* mac_length ) {
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key, key_length, EVP_sha1(), NULL);
    while (*data_chunks) {
        HMAC_Update(&ctx, *data_chunks, *data_chunck_length);
        data_chunks ++;
        data_chunck_length ++;
    }
    HMAC_Final(&ctx, mac, reinterpret_cast<uint32_t*>(mac_length));
    HMAC_CTX_cleanup(&ctx);
}

void* createSha1HmacContext(uint8_t* key, int32_t key_length)
{
    HMAC_CTX* ctx = (HMAC_CTX*)malloc(sizeof(HMAC_CTX));

    HMAC_CTX_init(ctx);
    HMAC_Init_ex(ctx, key, key_length, EVP_sha1(), NULL);
    return ctx;
}

void* initializeSha1HmacContext(void* ctx, uint8_t* key, int32_t keyLength)
{
    HMAC_CTX *pctx = (HMAC_CTX*)ctx;

    HMAC_CTX_init(pctx);
    HMAC_Init_ex(pctx, key, keyLength, EVP_sha1(), NULL);
    return pctx;
}

void hmacSha1Ctx(void* ctx, const uint8_t* data, uint32_t data_length,
                uint8_t* mac, int32_t* mac_length)
{
    HMAC_CTX* pctx = (HMAC_CTX*)ctx;

    HMAC_Init_ex(pctx, NULL, 0, NULL, NULL );
    HMAC_Update(pctx, data, data_length );
    HMAC_Final(pctx, mac, reinterpret_cast<uint32_t*>(mac_length) );
}

void hmacSha1Ctx(void* ctx, const uint8_t* data[], uint32_t data_length[],
                uint8_t* mac, int32_t* mac_length )
{
    HMAC_CTX* pctx = (HMAC_CTX*)ctx;

    HMAC_Init_ex(pctx, NULL, 0, NULL, NULL );
    while (*data) {
        HMAC_Update(pctx, *data, *data_length);
        data++;
        data_length++;
    }
    HMAC_Final(pctx, mac, reinterpret_cast<uint32_t*>(mac_length) );
}

void freeSha1HmacContext(void* ctx)
{
    if (ctx) {
        HMAC_CTX_cleanup((HMAC_CTX*)ctx);
        free(ctx);
    }
}