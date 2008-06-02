/*
  Copyright (C) 2006-2007 Werner Dittmann

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
    int32_t dhLength;

 public:
    ZrtpPacketDHPart();	                        /* Creates a DHPart packet no data, must use setPubKeyType(...) */
    ZrtpPacketDHPart(SupportedPubKeys pkt);	/* Creates a DHPart packet with default data */
    ZrtpPacketDHPart(uint8_t* data);            /* Creates a DHPart packet from received data */
    virtual ~ZrtpPacketDHPart();

    uint8_t* getPv()             { return pv; }
    uint8_t* getRs1Id()          { return DHPartHeader->rs1Id; };
    uint8_t* getRs2Id()          { return DHPartHeader->rs2Id; };
    uint8_t* getAuxSecretId()    { return DHPartHeader->auxSecretId; };
    uint8_t* getPbxSecretId()    { return DHPartHeader->pbxSecretId; };
    uint8_t* getH1()             { return DHPartHeader->hashH1; };
    uint8_t* getHMAC()           { return pv+dhLength; };

    void setPv(uint8_t* text) 	      { memcpy(pv, text, dhLength); };
    void setRs1Id(uint8_t* text)      { memcpy(DHPartHeader->rs1Id, text, sizeof(DHPartHeader->rs1Id)); };
    void setRs2Id(uint8_t* text)      { memcpy(DHPartHeader->rs2Id, text, sizeof(DHPartHeader->rs2Id)); };
    void setAuxSecretId(uint8_t* t)   { memcpy(DHPartHeader->auxSecretId, t, sizeof(DHPartHeader->auxSecretId)); };
    void setPbxSecretId(uint8_t* t)   { memcpy(DHPartHeader->pbxSecretId,t, sizeof(DHPartHeader->pbxSecretId)); };
    void setH1(uint8_t* t)            { memcpy(DHPartHeader->hashH1, t, sizeof(DHPartHeader->hashH1)); };
    void setPubKeyType(SupportedPubKeys pkt);
    void setHMAC(uint8_t* t) 	      { memcpy(pv+dhLength, t, 2*ZRTP_WORD_SIZE); };

 private:
    void initialize();
    // SupportedPubKeys pktype;
     // DHPart packet is of variable length. It maximum size is 141 words:
     // - 13 words fixed sizze 
     // - up to 128 words variable part, depending on DH algorithm 
     //   leads to a maximum of 4*141=564 bytes.
     uint8_t data[768];       // large enough to hold a full blown DHPart packet
};

#endif // ZRTPPACKETDHPART

