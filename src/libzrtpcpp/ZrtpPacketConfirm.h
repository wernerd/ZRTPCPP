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

#ifndef _ZRTPPACKETCONFIRM_H_
#define _ZRTPPACKETCONFIRM_H_

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the Confirm packet.
 *
 * The ZRTP message Confirm. The implementation sends this
 * to confirm the switch to SRTP (encrypted) mode. The contents of
 * the Confirm message are encrypted, thus the implementation can
 * check if SRTP work correctly.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpPacketConfirm : public ZrtpPacketBase {

    private:
	Confirm_t* confirmHeader;
 public:
    ZrtpPacketConfirm();		/* Creates a Confirm packet with default data */
    ZrtpPacketConfirm(uint8_t* data, uint8_t* content);	/* Creates a Confirm packet from received data */
    virtual ~ZrtpPacketConfirm();

    const uint8_t* getPlainText()     { return confirmHeader->plaintext; };
    uint8_t getSASFlag()              { return confirmHeader->flag; }
    const uint8_t* getHmac()          { return confirmHeader->hmac; };
    const uint32_t getExpTime()       { return confirmHeader->expTime; };

    void setPlainText(uint8_t* text)  { memcpy(confirmHeader->plaintext, text, 15); };
    void setSASFlag(uint8_t flg)      { confirmHeader->flag = flg; };
    void setHmac(uint8_t* text)       { memcpy(confirmHeader->hmac, text, 32); };
    void setExpTime(uint32_t t)       { confirmHeader->expTime = t; };

};

#endif // ZRTPPACKETCONFIRM

