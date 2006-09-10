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

/* Copyright (C) 2006
 *
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <libzrtpcpp/ZrtpPacketGoClear.h>

ZrtpPacketGoClear::ZrtpPacketGoClear() {
    DEBUGOUT((fprintf(stdout, "Creating GoClear packet without data\n")));

    allocated = malloc(sizeof (GoClearPacket_t));
    if (allocated == NULL) {
    }
    zrtpHeader = (zrtpPacketHeader_t *)&((GoClearPacket_t *)allocated)->hdr;	// the standard header
    clearHeader = (GoClear_t *)&((GoClearPacket_t *)allocated)->goClear;

    setZrtpId();
    setLength(MESSAGE_LENGTH + GOCLEAR_LENGTH);
    setMessage((uint8_t*)GoClearMsg);
}

ZrtpPacketGoClear::ZrtpPacketGoClear(uint8_t *data) {
    DEBUGOUT((fprintf(stdout, "Creating GoClear packet from data\n")));

    allocated = NULL;
    zrtpHeader = (zrtpPacketHeader_t *)&((GoClearPacket_t *)data)->hdr;	// the standard header
    clearHeader = (GoClear_t *)&((GoClearPacket_t *)data)->goClear;
}

ZrtpPacketGoClear::~ZrtpPacketGoClear() {
    DEBUGOUT((fprintf(stdout, "Deleting GoClear packet: alloc: %x\n", allocated)));

    if (allocated != NULL) {
	free(allocated);
    }
}
