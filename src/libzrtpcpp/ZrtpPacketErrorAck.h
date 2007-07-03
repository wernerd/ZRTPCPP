/*
  Copyright (C) 2007 Werner Dittmann

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

#ifndef _ZRTPPACKETERRORACK_H_
#define _ZRTPPACKETERRORACK_H_

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the ErrorAck packet.
 *
 * The ZRTP simple message ErrorAck. The implementation sends this
 * after receiving and checking the Error message.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */


class ZrtpPacketErrorAck : public ZrtpPacketBase {

 public:
    ZrtpPacketErrorAck();		/* Creates a ErrorAck packet with default data */
    ZrtpPacketErrorAck(char* data);	/* Creates a ErrorAck packet from received data */
    virtual ~ZrtpPacketErrorAck();

 private:
     ErrorAckPacket_t data;
};

#endif  // _ZRTPPACKETERRORACK_H_