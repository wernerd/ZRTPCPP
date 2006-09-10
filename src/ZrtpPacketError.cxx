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

#include <libzrtpcpp/ZrtpPacketError.h>

ZrtpPacketError::ZrtpPacketError() {
    DEBUGOUT((fprintf(stdout, "Creating Error packet without data\n")));

    allocated = malloc(sizeof (ErrorPacket_t));
    if (allocated == NULL) {
    }
    zrtpHeader = (zrtpPacketHeader_t *)&((ErrorPacket_t *)allocated)->hdr;	// the standard header
    errorHeader = (Error_t *)&((ErrorPacket_t *)allocated)->error;

    setZrtpId();
    setLength(MESSAGE_LENGTH + ERROR_LENGTH);
    setMessage((uint8_t*)ErrorMsg);
}

ZrtpPacketError::ZrtpPacketError(char *data) {
    DEBUGOUT((fprintf(stdout, "Creating Error packet from data\n")));

    allocated = NULL;
    zrtpHeader = (zrtpPacketHeader_t *)&((ErrorPacket_t *)data)->hdr;	// the standard header
    errorHeader = (Error_t *)&((ErrorPacket_t *)data)->error;
}

ZrtpPacketError::~ZrtpPacketError() {
    DEBUGOUT((fprintf(stdout, "Deleting Error packet: alloc: %x\n", allocated)));

    if (allocated != NULL) {
	free(allocated);
    }
}
