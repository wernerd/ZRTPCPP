/*
 Copyright (C) 2010 Werner Dittmann
 
 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.
 
 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.
 
 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
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
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key, key_length, EVP_sha1(), NULL);
#else
    HMAC_CTX* ctx;
    ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, key_length, EVP_sha1(), NULL);
#endif
    while (*data_chunks) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Update(&ctx, *data_chunks, *data_chunck_length);
#else
        HMAC_Update(ctx, *data_chunks, *data_chunck_length);
#endif
        data_chunks ++;
        data_chunck_length ++;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_Final(&ctx, mac, reinterpret_cast<uint32_t*>(mac_length));
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_Final(ctx, mac, reinterpret_cast<uint32_t*>(mac_length));
    HMAC_CTX_reset( ctx );
#endif
}

void* createSha1HmacContext(uint8_t* key, int32_t key_length)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX* ctx = (HMAC_CTX*)malloc(sizeof(HMAC_CTX));
    
    HMAC_CTX_init(ctx);
#else
    HMAC_CTX* ctx = HMAC_CTX_new();
#endif
    HMAC_Init_ex(ctx, key, key_length, EVP_sha1(), NULL);
    return ctx;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
void* initializeSha1HmacContext(void* ctx, uint8_t* key, int32_t key_length)
{
    HMAC_CTX *pctx = (HMAC_CTX*)ctx;
    HMAC_CTX_init(pctx);
    HMAC_Init_ex(pctx, key, key_length, EVP_sha1(), NULL);
    return pctx;
}

#else
// We still need to provide both the double- and single-pointer functions.
void* initializeSha1HmacContext(void** ctx, uint8_t* key, int32_t key_length)
{
    HMAC_CTX **pctx = (HMAC_CTX**)ctx;
    *pctx = HMAC_CTX_new(); // correct (!)
    HMAC_Init_ex(*pctx, key, key_length, EVP_sha1(), NULL);
    return *pctx;
}

void* initializeSha1HmacContext(void* ctx, uint8_t* key, int32_t key_length)
{
    HMAC_CTX *pctx = (HMAC_CTX*)ctx;
    pctx = HMAC_CTX_new();
    HMAC_Init_ex(pctx, key, key_length, EVP_sha1(), NULL);
    return pctx;
}
#endif


void hmacSha1Ctx(void* ctx, const uint8_t* data, uint32_t data_length,
                 uint8_t* mac, int32_t* mac_length)
{
    HMAC_CTX* pctx = (HMAC_CTX*)ctx;
    
    HMAC_Init_ex( pctx, NULL, 0, NULL, NULL );
    HMAC_Update( pctx, data, data_length );
    HMAC_Final( pctx, mac, reinterpret_cast<uint32_t*>(mac_length) );
}

void hmacSha1Ctx(void* ctx, const uint8_t* data[], uint32_t data_length[],
                 uint8_t* mac, int32_t* mac_length )
{
    HMAC_CTX* pctx = (HMAC_CTX*)ctx;
    
    HMAC_Init_ex( pctx, NULL, 0, NULL, NULL );
    while (*data) {
        HMAC_Update( pctx, *data, *data_length );
        data++;
        data_length++;
    }
    HMAC_Final( pctx, mac, reinterpret_cast<uint32_t*>(mac_length) );
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
