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

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#ifndef _AESCFB_H__
#define _AESCFB_H__


#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

/**
 * Encrypt data with AES CFB mode, full block feedback size.
 *
 * This functions takes one data chunk and encrypts it with
 * AES CFB mode. The lenght of the data may be arbitrary and
 * it is not needed to be a multiple of AES blocksize.
 *
 * @param key
 *    Points to the key bytes.
 * @param keyLength
 *    Length of the key in bytes
 * @param IV
 *    The initialization vector which must be AES_BLOCKSIZE (16) bytes.
 * @param data
 *    Points to a buffer that contains and receives the computed
 *    the data (in-place encryption).
 * @param dataLength
 *    Length of the data in bytes
 */

void aesCfbEncrypt(unsigned char *key,
            unsigned int keyLength,
            unsigned char* IV,
            unsigned char *data,
            unsigned int dataLength);

/**
 * Decrypt data with AES CFB mode, full block feedback size.
 *
 * This functions takes one data chunk and decrypts it with
 * AES CFB mode. The lenght of the data may be arbitrary and
 * it is not needed to be a multiple of AES blocksize.
 *
 * @param key
 *    Points to the key bytes.
 * @param keyLength
 *    Length of the key in bytes
 * @param IV
 *    The initialization vector which must be AES_BLOCKSIZE (16) bytes.
 * @param data
 *    Points to a buffer that contains and receives the computed
 *    the data (in-place decryption).
 * @param dataLength
 *    Length of the data in bytes
 */

void aesCfbDecrypt(unsigned char *key,
            unsigned int keyLength,
            unsigned char* IV,
            unsigned char *data,
            unsigned int dataLength);
#endif
