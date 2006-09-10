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

#include <libzrtpcpp/ZrtpPacketDHPart.h>


ZrtpPacketDHPart::ZrtpPacketDHPart(SupportedPubKeys pkt) {
    DEBUGOUT((fprintf(stdout, "Creating DHPart packet without data\n")));

    int length = sizeof(zrtpPacketHeader_t) + sizeof(DHPart_t);

    length += ((pkt == Dh3072) ? 384 : 512); // length according to DH type
    allocated = malloc(length);
    memset(allocated, 0, length);

    if (allocated == NULL) {
	// TODO error handling
    }

    pktype = pkt;

    zrtpHeader = (zrtpPacketHeader_t *)&((DHPartPacket_t *)allocated)->hdr;	// the standard header
    pv = ((uint8_t *)allocated) + sizeof(zrtpPacketHeader_t); 		// point to the public key value
    DHPartHeader = (DHPart_t *)(((char *)allocated)+sizeof(zrtpPacketHeader_t)+((pkt == Dh3072) ? 384 : 512));

    setZrtpId();
    setLength(DHPART_LENGTH + MESSAGE_LENGTH + ((pkt == Dh3072) ? 96 : 128));
}

ZrtpPacketDHPart::ZrtpPacketDHPart(uint8_t *data) {
    DEBUGOUT((fprintf(stdout, "Creating DHPart packet from data\n")));

    allocated = NULL;
    zrtpHeader = (zrtpPacketHeader_t *)&((DHPartPacket_t *)data)->hdr;	// the standard header

    int16_t len = getLength();
    DEBUGOUT((fprintf(stdout, "DHPart length: %d\n", len)));
    SupportedPubKeys pkt;
    if (len == 108) {
	pkt = Dh3072;
    }
    else if (len == 140) {
	pkt = Dh4096;
    }
    else {
	fprintf(stderr, "Wrong DHPart length: %d\n", len);
	pv = NULL;
	return;
    }
    pv = data + sizeof(zrtpPacketHeader_t);
    DHPartHeader = (DHPart_t *)(data + sizeof(zrtpPacketHeader_t) + ((pkt == Dh3072) ? 384 : 512));

    pktype = pkt;
}

ZrtpPacketDHPart::~ZrtpPacketDHPart() {
    DEBUGOUT((fprintf(stdout, "Deleting DHPart packet: alloc: %x\n", allocated)));

    if (allocated != NULL) {
	free(allocated);
    }
}
