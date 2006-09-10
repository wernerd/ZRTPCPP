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

#ifndef _ZRTPPACKETHELLOACK_H_
#define _ZRTPPACKETHELLOACK_H_

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the HelloAck packet.
 *
 * The ZRTP simple message HelloAck. The implementation sends this
 * after receiving a Hello packet. Sending a HelloAck is optional, a
 * Commit can be sent instead.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpPacketHelloAck : public ZrtpPacketBase {

 public:
    ZrtpPacketHelloAck();		/* Creates a HelloAck packet with default data */
    ZrtpPacketHelloAck(char* data);	/* Creates a HelloAck packet from received data */
    virtual ~ZrtpPacketHelloAck();

 private:
};

#endif // ZRTPPACKETHELLOACK

