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
    bool passive;
    // number of the algorithms
    int32_t nHash, nCipher, nPubkey, nSas, nAuth;
    // offsets in bytes into hello packet where algo names are stored
    int32_t oHash, oCipher, oPubkey, oSas, oAuth, oHmac;

 public:
    ZrtpPacketHello();              /* Creates a Hello packet with default data */
    ZrtpPacketHello(uint8_t *data); /* Creates a Hello packet from received data */
    virtual ~ZrtpPacketHello();

    void configureHello(ZrtpConfigure* config);

    uint8_t* getVersion()  { return helloHeader->version; };
    uint8_t* getClientId() { return helloHeader->clientId; };
    uint8_t* getH3()       { return helloHeader->hashH3; };
    uint8_t* getZid()      { return helloHeader->zid; };

    void setVersion(uint8_t *text)     { memcpy(helloHeader->version, text,ZRTP_WORD_SIZE ); }
    void setClientId(const uint8_t *t) { memcpy(helloHeader->clientId, t, sizeof(helloHeader->clientId)); }
    void setH3(uint8_t *hash)          { memcpy(helloHeader->hashH3, hash, sizeof(helloHeader->hashH3)); }
    void setZid(uint8_t *text)         { memcpy(helloHeader->zid, text, sizeof(helloHeader->zid)); }

    bool isPassive()       { return passive; };

    uint8_t* getHashType(int32_t n)   { return ((uint8_t*)helloHeader)+oHash+(n*ZRTP_WORD_SIZE); }
    uint8_t* getCipherType(int32_t n) { return ((uint8_t*)helloHeader)+oCipher+(n*ZRTP_WORD_SIZE); }
    uint8_t* getAuthLen(int32_t n)    { return ((uint8_t*)helloHeader)+oAuth+(n*ZRTP_WORD_SIZE); }
    uint8_t* getPubKeyType(int32_t n) { return ((uint8_t*)helloHeader)+oPubkey+(n*ZRTP_WORD_SIZE); }
    uint8_t* getSasType(int32_t n)    { return ((uint8_t*)helloHeader)+oSas+(n*ZRTP_WORD_SIZE); }

    uint8_t* getHMAC()                { return ((uint8_t*)helloHeader)+oHmac; }

    void setHashType(int32_t n, int8_t* t)
        { memcpy(((uint8_t*)helloHeader)+oHash+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }
    void setCipherType(int32_t n, int8_t* t)
        { memcpy(((uint8_t*)helloHeader)+oCipher+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }
    void setAuthLen(int32_t n, int8_t* t)
        { memcpy(((uint8_t*)helloHeader)+oAuth+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }
    void setPubKeyType(int32_t n, int8_t* t)
        { memcpy(((uint8_t*)helloHeader)+oPubkey+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }
    void setSasType(int32_t n, int8_t* t)
        { memcpy(((uint8_t*)helloHeader)+oSas+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE); }

    void setHMAC(uint8_t* t)
        { memcpy(((uint8_t*)helloHeader)+oHmac, t, 2*ZRTP_WORD_SIZE); }

    int32_t getNumHashes()   {return nHash; }
    int32_t getNumCiphers()  {return nCipher; }
    int32_t getNumPubKeys()  {return nPubkey; }
    int32_t getNumSas()      {return nSas; }
    int32_t getNumAuth()     {return nAuth; }


 private:
     // Hello packet is of variable length. It maximum size is 46 words:
     // - 11 words fixed sizze 
     // - up to 35 words variable part, depending on number of algorithms 
     // leads to a maximum of 4*46=184 bytes.
     uint8_t data[256];       // large enough to hold a full blown Hello packet
};

#endif // ZRTPPACKETHELLO

