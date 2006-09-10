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

#ifndef _ZRTPPACKETHELLO_H_
#define _ZRTPPACKETHELLO_H_

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the Hello packet.
 *
 * The ZRTP message Hello. The implementation sends this
 * to start the ZRTP negotiation sequence. The Hello message
 * offers crypto methods and parameters to the other party. The
 * other party selects methods and parameters it can support
 * and uses the Commit message to commit these.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpPacketHello : public ZrtpPacketBase {

 protected:
    Hello_t* helloHeader;

 public:
    ZrtpPacketHello();		 /* Creates a Hello packet with default data */
    ZrtpPacketHello(uint8_t *data); /* Creates a Hello packet from received data */
    virtual ~ZrtpPacketHello();

    uint8_t* getVersion()  { return helloHeader->version; };
    uint8_t* getClientId() { return helloHeader->clientId; };
    bool isPassive()       { return ((helloHeader->flag & 0x1) == 0x1); };

    uint8_t* getHashType(uint32_t number)    { return helloHeader->hashes[number]; };
    uint8_t* getCipherType(uint32_t number)  { return helloHeader->ciphers[number]; };
    uint8_t* getAuthLen(uint32_t number)     { return helloHeader->authlengths[number]; };
    uint8_t* getPubKeysType(uint32_t number) { return helloHeader->pubkeys[number]; };
    uint8_t* getSasType(uint32_t number)     { return helloHeader->sas[number]; };
    uint8_t* getZid()                        { return helloHeader->zid; };

    void setVersion(uint8_t *text)                   { memcpy(helloHeader->version, text, 4); }
    void setClientId(const uint8_t *text)            { memcpy(helloHeader->clientId, text, 15); }
    void setHashType(uint32_t number, char *text)    { memcpy(helloHeader->hashes[number], text, 8); };
    void setCipherType(uint32_t number, char *text)  { memcpy(helloHeader->ciphers[number], text, 8); };
    void setAuthLen(uint32_t number, char *text)     { memcpy(helloHeader->authlengths[number], text, 8); };
    void setPubKeyType(uint32_t number, char *text)  { memcpy(helloHeader->pubkeys[number], text, 8); };
    void setSasType(uint32_t number, char *text)     { memcpy(helloHeader->sas[number], text, 8); };
    void setZid(uint8_t *text)                       { memcpy(helloHeader->zid, text, 12); };
 private:
};

#endif // ZRTPPACKETHELLO

