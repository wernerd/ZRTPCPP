/*
  Copyright (C) 2006-2009 Werner Dittmann

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

#ifndef _ZRTPPACKETPING_H_
#define _ZRTPPACKETPING_H_

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the PingAck packet.
 *
 * The ZRTP simple message PingAck.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class ZrtpPacketPing : public ZrtpPacketBase {

 protected:
    Ping_t* pingHeader;

 public:
    ZrtpPacketPing();
    ZrtpPacketPing(uint8_t* data);
    virtual ~ZrtpPacketPing();

    void setVersion(uint8_t *text)     { memcpy(pingHeader->version, text,ZRTP_WORD_SIZE ); }

    uint8_t* getEpHash()               { return pingHeader->epHash; }

 private:
     PingPacket_t data;
};

#endif // ZRTPPACKETCLEARACK

