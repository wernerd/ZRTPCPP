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

/*
 * Authors: Erik Eliasson <eliasson@it.kth.se>
 *          Johan Bilien <jobi@via.ecp.fr>
 */
#include <gcrypt.h>

#include <crypto/hmac.h>
#include <stdio.h>

void hmac_sha1(uint8* key, int32 keyLength,
                 const uint8* data, int32 dataLength,
                 uint8* mac, int32* macLength)
{
    gcry_md_hd_t hd;
    gcry_error_t err = 0;

    err = gcry_md_open(&hd, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(hd, key, keyLength);

    gcry_md_write (hd, data, dataLength);

    uint8_t* p = gcry_md_read (hd, GCRY_MD_SHA1);
    memcpy(mac, p, SHA1_DIGEST_LENGTH);
    if (macLength != NULL) {
        *macLength = SHA1_DIGEST_LENGTH;
    }
    gcry_md_close (hd);
}

void hmac_sha1( uint8* key, int32 keyLength,
                  const uint8* dataChunks[],
                  uint32 dataChunkLength[],
                  uint8* mac, int32* macLength )
{
    gcry_md_hd_t hd;
    gcry_error_t err = 0;

    err = gcry_md_open(&hd, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(hd, key, keyLength);

    while (*dataChunks) {
        gcry_md_write (hd, *dataChunks, (uint32)(*dataChunkLength));
        dataChunks++;
        dataChunkLength++;
    }
    uint8_t* p = gcry_md_read (hd, GCRY_MD_SHA1);
    memcpy(mac, p, SHA1_DIGEST_LENGTH);
    if (macLength != NULL) {
        *macLength = SHA1_DIGEST_LENGTH;
    }
    gcry_md_close (hd);
}
