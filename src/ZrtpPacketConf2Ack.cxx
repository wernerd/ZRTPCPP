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

#include <libzrtpcpp/ZrtpPacketConf2Ack.h>

ZrtpPacketConf2Ack::ZrtpPacketConf2Ack() {
    DEBUGOUT((fprintf(stdout, "Creating Conf2Ack packet without data\n")));

    allocated = malloc(sizeof (Conf2Ack_t));
    if (allocated == NULL) {
    }
    zrtpHeader = (zrtpPacketHeader_t *)&((Conf2Ack_t *)allocated)->hdr;	// the standard header

    setZrtpId();
    setLength(MESSAGE_LENGTH);
    setMessage((uint8_t*)Conf2AckMsg);
}

ZrtpPacketConf2Ack::ZrtpPacketConf2Ack(char *data) {
    DEBUGOUT((fprintf(stdout, "Creating Conf2Ack packet from data\n")));

    allocated = NULL;
    zrtpHeader = (zrtpPacketHeader_t *)&((Conf2Ack_t *)data)->hdr;	// the standard header
}

ZrtpPacketConf2Ack::~ZrtpPacketConf2Ack() {
    DEBUGOUT((fprintf(stdout, "Deleting Conf2Ack packet: alloc: %x\n", allocated)));
    if (allocated != NULL) {
	free(allocated);
    }
}
