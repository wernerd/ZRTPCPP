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

ZrtpPacketDHPart::ZrtpPacketDHPart() {
    DEBUGOUT((fprintf(stdout, "Creating DHPart packet without data and pkt type\n")));
    initialize();
}

ZrtpPacketDHPart::ZrtpPacketDHPart(SupportedPubKeys pkt) {
    DEBUGOUT((fprintf(stdout, "Creating DHPart packet without data\n")));
    initialize();
    setPubKeyType(pkt);
}

void ZrtpPacketDHPart::initialize() {

    void* allocated = &data;
    memset(allocated, 0, sizeof(data));

    zrtpHeader = (zrtpPacketHeader_t *)&((DHPartPacket_t *)allocated)->hdr;	// the standard header
    DHPartHeader = (DHPart_t *)&((DHPartPacket_t *)allocated)->dhPart;
    pv = ((uint8_t*)allocated) + sizeof(DHPartPacket_t);    // point to the public key value

    setZrtpId();
}

void ZrtpPacketDHPart::setPubKeyType(SupportedPubKeys pkt) {
    int length = sizeof(DHPartPacket_t) + ((pkt == Dh3072) ? 384 : 512);
    pktype = pkt;
    setLength(length / 4);
}

ZrtpPacketDHPart::ZrtpPacketDHPart(uint8_t *data) {
    DEBUGOUT((fprintf(stdout, "Creating DHPart packet from data\n")));

    zrtpHeader = (zrtpPacketHeader_t *)&((DHPartPacket_t *)data)->hdr;	// the standard header
    DHPartHeader = (DHPart_t *)&((DHPartPacket_t *)data)->dhPart;

    int16_t len = getLength();
    DEBUGOUT((fprintf(stdout, "DHPart length: %d\n", len)));
    SupportedPubKeys pkt;
    // TODO: fix check for length if Hash images are enable (+4 words)
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
}

ZrtpPacketDHPart::~ZrtpPacketDHPart() {
    DEBUGOUT((fprintf(stdout, "Deleting DHPart packet: alloc: %x\n", allocated)));
}
