/*
  Copyright (C) 2006, 2007 by Werner Dittmann

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
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

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

/** Copyright (C) 2006, 2007
 *
 * @author  Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <gcrypt.h>
#include <libzrtpcpp/crypto/aesCFB.h>


extern void initializeGcrypt();

void aesCfbEncrypt(unsigned char *key,
            unsigned int keyLength,
            unsigned char* IV,
            unsigned char *data,
            unsigned int dataLength)
{
    gcry_error_t err = 0;
    int algo;

    initializeGcrypt();

    if (keyLength == 16) {
        algo = GCRY_CIPHER_AES;
    }
    else if (keyLength == 32) {
        algo = GCRY_CIPHER_AES256;
    }
    else {
	return;
    }
    gcry_cipher_hd_t tmp;
    err = gcry_cipher_open(&tmp, algo, GCRY_CIPHER_MODE_CFB, 0);
    err = gcry_cipher_setkey(tmp, key, keyLength);
    err = gcry_cipher_setiv (tmp, IV, AES_BLOCK_SIZE);
    err = gcry_cipher_encrypt (tmp, data, dataLength, data, dataLength);
    gcry_cipher_close(tmp);
}

void aesCfbDecrypt(unsigned char *key,
            unsigned int keyLength,
            unsigned char* IV,
            unsigned char *data,
            unsigned int dataLength)
{
    gcry_error_t err = 0;
    int algo;

    initializeGcrypt();

    if (keyLength == 16) {
        algo = GCRY_CIPHER_AES;
    }
    else if (keyLength == 32) {
        algo = GCRY_CIPHER_AES256;
    }
    else {
	return;
    }
    gcry_cipher_hd_t tmp;
    err = gcry_cipher_open(&tmp, algo, GCRY_CIPHER_MODE_CFB, 0);
    err = gcry_cipher_setkey(tmp, key, keyLength);
    err = gcry_cipher_setiv (tmp, IV, AES_BLOCK_SIZE);
    err = gcry_cipher_decrypt (tmp, data, dataLength, data, dataLength);
    gcry_cipher_close(tmp);
}