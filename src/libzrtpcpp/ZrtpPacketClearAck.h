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
#ifndef _ZRTPPACKETCLEARACK_H_
#define _ZRTPPACKETCLEARACK_H_

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the ClearAck packet.
 *
 * The ZRTP simple message ClearAck. The implementation sends this
 * after switching to clear mode (non-SRTP mode).
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class ZrtpPacketClearAck : public ZrtpPacketBase {

 public:
     ZrtpPacketClearAck();		/* Creates a Conf2Ack packet with default data */
     ZrtpPacketClearAck(uint8_t* data);	/* Creates a Conf2Ack packet from received data */
     virtual ~ZrtpPacketClearAck();

 private:
};

#endif // ZRTPPACKETCLEARACK

