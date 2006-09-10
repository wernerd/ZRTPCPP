/*
  Copyright (C) 2006 Werner Dittmann

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Boston, MA 02111.
*/

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <libzrtpcpp/ZrtpPacketHello.h>


ZrtpPacketHello::ZrtpPacketHello() {
    DEBUGOUT((fprintf(stdout, "Creating Hello packet without data\n")));

    allocated = malloc(sizeof (HelloPacket_t));

    if (allocated == NULL) {
    }
    memset(allocated, 0, sizeof (HelloPacket_t));

    zrtpHeader = (zrtpPacketHeader_t *)&((HelloPacket_t *)allocated)->hdr;	// the standard header
    helloHeader = (Hello_t *)&((HelloPacket_t *)allocated)->hello;

    setZrtpId();
    setLength(HELLO_LENGTH + MESSAGE_LENGTH);
    setMessage((uint8_t*)HelloMsg);

    setVersion((uint8_t*)zrtpVersion);

    setHashType(0, supportedHashes[0]);
    setHashType(1, supportedHashes[1]);
    setHashType(2, supportedHashes[2]);
    setHashType(3, supportedHashes[3]);
    setHashType(4, supportedHashes[4]);

    setCipherType(0, supportedCipher[0]);
    setCipherType(1, supportedCipher[1]);
    setCipherType(2, supportedCipher[2]);
    setCipherType(3, supportedCipher[3]);
    setCipherType(4, supportedCipher[4]);

    setAuthLen(0, supportedAuthLen[0]);
    setAuthLen(1, supportedAuthLen[1]);
    setAuthLen(2, supportedAuthLen[2]);
    setAuthLen(3, supportedAuthLen[3]);
    setAuthLen(4, supportedAuthLen[4]);

    setPubKeyType(0, supportedPubKey[0]);
    setPubKeyType(1, supportedPubKey[1]);
    setPubKeyType(2, supportedPubKey[2]);
    setPubKeyType(3, supportedPubKey[3]);
    setPubKeyType(4, supportedPubKey[4]);

    setSasType(0, supportedSASType[0]);
    setSasType(1, supportedSASType[1]);
    setSasType(2, supportedSASType[2]);
    setSasType(3, supportedSASType[3]);
    setSasType(4, supportedSASType[4]);
}

ZrtpPacketHello::ZrtpPacketHello(uint8_t *data) {
    DEBUGOUT((fprintf(stdout, "Creating Hello packet from data\n")));

    allocated = NULL;
    zrtpHeader = (zrtpPacketHeader_t *)&((HelloPacket_t *)data)->hdr;	// the standard header
    helloHeader = (Hello_t *)&((HelloPacket_t *)data)->hello;
}

ZrtpPacketHello::~ZrtpPacketHello() {
    DEBUGOUT((fprintf(stdout, "Deleting Hello packet: alloc: %x\n", allocated)));
    if (allocated != NULL) {
	free(allocated);
    }
}
