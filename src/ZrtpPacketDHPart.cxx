/*
  Copyright (C) 2006-2007 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <libzrtpcpp/ZrtpPacketDHPart.h>


ZrtpPacketDHPart::ZrtpPacketDHPart(SupportedPubKeys pkt) {
    DEBUGOUT((fprintf(stdout, "Creating DHPart packet without data\n")));
#if 0
    int length = sizeof(DHPart_t) + sizeof(zrtpPacketHeader_t) + CRC_SIZE + ((pkt == Dh3072) ? 384 : 512);

    void* allocated = &data;
    memset(allocated, 0, length);

    pktype = pkt;

    zrtpHeader = (zrtpPacketHeader_t *)&((DHPartPacket_t *)allocated)->hdr;	// the standard header
    pv = ((uint8_t *)allocated) + sizeof(zrtpPacketHeader_t);    // point to the public key value
    DHPartHeader = (DHPart_t *)(pv + ((pkt == Dh3072) ? 384 : 512));

    setZrtpId();
    // Subtract one to exclude the CRC word from length in ZRTP message 
    setLength((length / 4) - 1);
    // setLength(DHPART_LENGTH + MESSAGE_LENGTH + ((pkt == Dh3072) ? 96 : 128));
#else
    int length = sizeof(DHPartPacket_t) + CRC_SIZE + ((pkt == Dh3072) ? 384 : 512);

    void* allocated = &data;
    memset(allocated, 0, length);

    pktype = pkt;

    zrtpHeader = (zrtpPacketHeader_t *)&((DHPartPacket_t *)allocated)->hdr;	// the standard header
    DHPartHeader = (DHPart_t *)&((DHPartPacket_t *)allocated)->dhPart;
    pv = ((uint8_t *)allocated) + sizeof(DHPartPacket_t);    // point to the public key value

    setZrtpId();
    // Subtract one to exclude the CRC word from length in ZRTP message 
    setLength((length / 4) - 1);
#endif
}

ZrtpPacketDHPart::ZrtpPacketDHPart(uint8_t *data) {
    DEBUGOUT((fprintf(stdout, "Creating DHPart packet from data\n")));
#if 0
    zrtpHeader = (zrtpPacketHeader_t *)&((DHPartPacket_t *)data)->hdr;	// the standard header

    int16_t len = getLength();
    DEBUGOUT((fprintf(stdout, "DHPart length: %d\n", len)));
    SupportedPubKeys pkt;
    if (len == 109) {
	pkt = Dh3072;
    }
    else if (len == 141) {
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
#else
    zrtpHeader = (zrtpPacketHeader_t *)&((DHPartPacket_t *)data)->hdr;	// the standard header
    DHPartHeader = (DHPart_t *)&((DHPartPacket_t *)data)->dhPart;

    int16_t len = getLength();
    DEBUGOUT((fprintf(stdout, "DHPart length: %d\n", len)));
    SupportedPubKeys pkt;
    if (len == 109) {
	pkt = Dh3072;
    }
    else if (len == 141) {
	pkt = Dh4096;
    }
    else {
	fprintf(stderr, "Wrong DHPart length: %d\n", len);
	pv = NULL;
	return;
    }
    pv = data + sizeof(DHPartPacket_t);    // point to the public key value
    pktype = pkt;
#endif
}

ZrtpPacketDHPart::~ZrtpPacketDHPart() {
    DEBUGOUT((fprintf(stdout, "Deleting DHPart packet: alloc: %x\n", allocated)));
}
