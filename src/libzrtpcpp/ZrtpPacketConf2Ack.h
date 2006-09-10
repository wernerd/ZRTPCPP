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

#ifndef _ZRTPPACKETCON2FACK_H_
#define _ZRTPPACKETCON2FACK_H_

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the Conf2Ack packet.
 *
 * The ZRTP simple message Conf2Ack. The implementation sends this
 * after receiving and checking the Confirm2 message.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpPacketConf2Ack : public ZrtpPacketBase {

 public:
    ZrtpPacketConf2Ack();		/* Creates a Conf2Ack packet with default data */
    ZrtpPacketConf2Ack(char* data);	/* Creates a Conf2Ack packet from received data */
    virtual ~ZrtpPacketConf2Ack();

 private:
};

#endif // ZRTPPACKETCONF2ACK

