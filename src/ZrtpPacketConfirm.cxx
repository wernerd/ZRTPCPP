/*
  Copyright (C) 2006, 2007 Werner Dittmann

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

#include <libzrtpcpp/ZrtpPacketConfirm.h>

ZrtpPacketConfirm::ZrtpPacketConfirm(uint8_t sl) {
    DEBUGOUT((fprintf(stdout, "Creating Confirm packet without data\n")));

    int32_t length = sizeof(ConfirmPacket_t) + (sl * ZRTP_WORD_SIZE) + CRC_SIZE;
    allocated = malloc(length);

    if (allocated == NULL) {
    }

    memset(allocated, 0, length);
    zrtpHeader = (zrtpPacketHeader_t *)&((ConfirmPacket_t *)allocated)->hdr;	// the standard header
    confirmHeader = (Confirm_t *)&((ConfirmPacket_t *)allocated)->confirm;

    setZrtpId();
    setLength((sizeof(ConfirmPacket_t) + (sl * ZRTP_WORD_SIZE)) / 4);
}

ZrtpPacketConfirm::ZrtpPacketConfirm(uint8_t* data) {
    DEBUGOUT((fprintf(stdout, "Creating Confirm packet from data\n")));

    allocated = NULL;
    zrtpHeader = (zrtpPacketHeader_t *)&((ConfirmPacket_t *)data)->hdr;	// the standard header
    confirmHeader = (Confirm_t *)&((ConfirmPacket_t *)data)->confirm;
}

ZrtpPacketConfirm::~ZrtpPacketConfirm() {
    DEBUGOUT((fprintf(stdout, "Deleting Confirm packet: alloc: %x\n", allocated)));
    if (allocated != NULL) {
        free(allocated);
    }
}
