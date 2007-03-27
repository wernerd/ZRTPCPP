/*
  Copyright (C) 2005, 2004 Erik Eliasson, Johan Bilien

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
 */

/**
 * @author Erik Eliasson <eliasson@it.kth.se>
 *          Johan Bilien <jobi@via.ecp.fr>
 *	    Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <gcrypt.h>
#include <libzrtpcpp/crypto/sha256.h>

void sha256(unsigned char* data, unsigned int dataLength,
            unsigned char* mac)
{
    gcry_md_hd_t hd;
    gcry_error_t err = 0;

    err = gcry_md_open(&hd, GCRY_MD_SHA256, 0);
    gcry_md_write (hd, data, dataLength);

    uint8_t* p = gcry_md_read (hd, GCRY_MD_SHA256);
    memcpy(mac, p, SHA256_DIGEST_LENGTH);
    gcry_md_close (hd);
}

void sha256(unsigned char* dataChunks[],
            unsigned int dataChunkLength[],
            unsigned char* mac)
{
    gcry_md_hd_t hd;
    gcry_error_t err = 0;

    err = gcry_md_open(&hd, GCRY_MD_SHA256, 0);
    while (*dataChunks) {
        gcry_md_write (hd, *dataChunks, (uint32_t)(*dataChunkLength));
        dataChunks++;
        dataChunkLength++;
    }
    uint8_t* p = gcry_md_read (hd, GCRY_MD_SHA256);
    memcpy(mac, p, SHA256_DIGEST_LENGTH);
    gcry_md_close (hd);
}

void* createSha256Context()
{
    gcry_error_t err = 0;
    gcry_md_hd_t hd;

    err = gcry_md_open(&hd, GCRY_MD_SHA256, 0);
    return (void*)hd;
}

void closeSha256Context(void* ctx, unsigned char* mac)
{
    gcry_error_t err = 0;
    gcry_md_hd_t hd = (gcry_md_hd_t)ctx;

    uint8_t* p = gcry_md_read (hd, GCRY_MD_SHA256);
    memcpy(mac, p, SHA256_DIGEST_LENGTH);
    gcry_md_close (hd);
}

void sha256Ctx(void* ctx, unsigned char* data, 
                unsigned int dataLength)
{
    gcry_md_hd_t hd = (gcry_md_hd_t)ctx;

    gcry_md_write (hd, data, dataLength);
}

void sha256Ctx(void* ctx, unsigned char* dataChunks[],
            unsigned int dataChunkLength[])
{
    gcry_md_hd_t hd = (gcry_md_hd_t)ctx;
    gcry_error_t err = 0;

    err = gcry_md_open(&hd, GCRY_MD_SHA256, 0);
    while (*dataChunks) {
        gcry_md_write (hd, *dataChunks, (uint32_t)(*dataChunkLength));
        dataChunks++;
        dataChunkLength++;
    }
}
