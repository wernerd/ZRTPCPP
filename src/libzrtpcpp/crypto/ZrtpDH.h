/*
 Copyright (C) 2006 by Werner Dittmann

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

#ifndef _ZRTPDH_H__
#define _ZRTPDH_H__

#include <stdint.h>

/**
 * Implementation of Diffie-Helman for ZRTP
 *
 * This class defines functions to generate and compute the
 * Diffie-Helman public and secret data and the shared secret. According to
 * the ZRTP specification we use the MODP groups as defined by RFC 3526 for
 * length 3072 and 4096.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class ZrtpDH {

private:
    void* ctx;

public:
    ZrtpDH(int32_t pkLength);
    ~ZrtpDH();

    /**
     * Generates a public key based on the DH parameters and a random
     * private key.
     *
     * @return 1 on success, 0 on failure
     */
    int32_t generateKey();

    /**
     * Returns the size in bytes of computed secret key.
     *
     * @return Size in bytes.
     */
    int32_t getSecretSize() const;

    /**
     * Returns the size in bytes of computed public key.
     *
     * @return Size in bytes.
     */
    int32_t getPubKeySize() const;

    /**
     * Returns the bytes of computed secret key.
     *
     * Returns the bytes of the public key in network (big endian) order.#
     *
     * @param buf
     *    Pointer to a buffer of at least <code>getPubKeySize()</code> bytes.
     *
     * @return Size in bytes.
     */
    int32_t getPubKeyBytes(uint8_t *buf) const;

    /**
     * Compute the secret key and return it to caller.
     *
     * This method computes the secret key based on the DH parameters, the
     * private key and the peer's public key.
     *
     * @param pubKeyBytes
     *    Pointer to the peer's public key bytes. Must be in big endian order.
     *
     * @param length
     *    Length in bytes of the peer's public key.
     *
     * @param secret
     *    Pointer to a buffer that receives the secret key. This buffer must
     *    have a length of at least <code>getSecretSize()</code> bytes.
     *
     * @return the size of the shared secret on success, -1 on error.
     */
    int32_t computeKey(uint8_t *pubKeyBytes, int32_t length, uint8_t *secret);

    /**
     * Check and validate the public key received from peer.
     *
     * Check if this is a correct Diffie-Helman public key. If the public
     * key value is either one or (P-1) then this is a wrong public key
     * value.
     *
     * @param pubKeyBytes
     *     Pointer to the peer's public key bytes. Must be in big endian order.
     *
     * @param length
     *    Length in bytes of the peer's public key.
     *
     * @return 0 if check faild, 1 if public key value is ok.
     */
    int32_t checkPubKey(uint8_t* pubKeyBytes, int32_t length) const;

    /**
     * Generates a number of random bytes.
     *
     * @param buf
     *    Pointer to a buffer that receives the random data. Must have a size
     *    of at least <code>length</code> bytes.
     *
     * @param length
     *    Number of random bytes to produce.
     */
    void random(uint8_t *buf, int32_t length);
};

#endif // ZRTPDH_H

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
