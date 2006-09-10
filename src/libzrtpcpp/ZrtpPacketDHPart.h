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

#ifndef _ZRTPPACKETDHPART_H_
#define _ZRTPPACKETDHPART_H_

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the DHPart packet.
 *
 * The ZRTP message DHPart. The implementation sends this
 * to exchange the Diffie-Helman public keys and the shared
 * secrets between the two parties.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpPacketDHPart : public ZrtpPacketBase {

 protected:
    uint8_t *pv;
    DHPart_t* DHPartHeader;

 public:
    ZrtpPacketDHPart(SupportedPubKeys pkt);	/* Creates a DHPart packet with default data */
    ZrtpPacketDHPart(uint8_t* data);            /* Creates a DHPart packet from received data */
    virtual ~ZrtpPacketDHPart();

    uint8_t* getPv()             { return pv; }
    uint8_t* getRs1Id()          { return DHPartHeader->rs1Id; };
    uint8_t* getRs2Id()          { return DHPartHeader->rs2Id; };
    uint8_t* getSigsId()         { return DHPartHeader->sigsId; };
    uint8_t* getSrtpsId()        { return DHPartHeader->srtpsId; };
    uint8_t* getOtherSecretId() { return DHPartHeader->otherSecretId; };

    void setPv(uint8_t* text) 	         { memcpy(pv, text, ((pktype == Dh3072) ? 384 :512)); };
    void setRs1Id(uint8_t* text)         { memcpy(DHPartHeader->rs1Id, text, 8); };
    void setRs2Id(uint8_t* text)         { memcpy(DHPartHeader->rs2Id, text, 8); };
    void setSigsId(uint8_t* text)        { memcpy(DHPartHeader->sigsId, text, 8); };
    void setSrtpsId(uint8_t* text)       { memcpy(DHPartHeader->srtpsId, text, 8); };
    void setOtherSecretId(uint8_t* text) { memcpy(DHPartHeader->otherSecretId, text, 8); };

 private:
    SupportedPubKeys pktype;
};

#endif // ZRTPPACKETDHPART

