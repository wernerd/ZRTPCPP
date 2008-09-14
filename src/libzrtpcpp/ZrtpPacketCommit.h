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

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */
#ifndef _ZRTPPACKETCOMMIT_H_
#define _ZRTPPACKETCOMMIT_H_

#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * Implement the Commit packet.
 *
 * The ZRTP message Commit. The ZRTP implementation sends or receives
 * this message to commit the crypto parameters offered during a Hello
 * message.
 *
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpPacketCommit : public ZrtpPacketBase {

 protected:
    Commit_t* commitHeader;

 public:
    ZrtpPacketCommit();		 /* Creates a Commit packet with default data */
    ZrtpPacketCommit(uint8_t* data); /* Creates a Commit packet from received data */
    virtual ~ZrtpPacketCommit();

    uint8_t* getHashType()    { return commitHeader->hash; };
    uint8_t* getCipherType()  { return commitHeader->cipher; };
    uint8_t* getAuthLen()     { return commitHeader->authlengths; };
    uint8_t* getPubKeysType() { return commitHeader->pubkey; };
    uint8_t* getSasType()     { return commitHeader->sas; };
    uint8_t* getZid()         { return commitHeader->zid; };
    uint8_t* getHvi()         { return commitHeader->hvi; };
    uint8_t* getNonce()       { return commitHeader->hvi; };
    uint8_t* getH2()          { return commitHeader->hashH2; };
    uint8_t* getHMAC()        { return commitHeader->hmac; };
    uint8_t* getHMACMulti()   { return commitHeader->hmac-4*ZRTP_WORD_SIZE; };

    void setHashType(uint8_t* text)    { memcpy(commitHeader->hash, text, ZRTP_WORD_SIZE); };
    void setCipherType(uint8_t* text)  { memcpy(commitHeader->cipher, text, ZRTP_WORD_SIZE); };
    void setAuthLen(uint8_t* text)     { memcpy(commitHeader->authlengths, text, ZRTP_WORD_SIZE); };
    void setPubKeyType(uint8_t* text)  { memcpy(commitHeader->pubkey, text, ZRTP_WORD_SIZE); };
    void setSasType(uint8_t* text)     { memcpy(commitHeader->sas, text, ZRTP_WORD_SIZE); };
    void setZid(uint8_t* text)         { memcpy(commitHeader->zid, text, sizeof(commitHeader->zid)); };
    void setHvi(uint8_t* text)         { memcpy(commitHeader->hvi, text, sizeof(commitHeader->hvi)); };
    void setNonce(uint8_t* text);
    void setH2(uint8_t* hash)          { memcpy(commitHeader->hashH2, hash, sizeof(commitHeader->hashH2)); };
    void setHMAC(uint8_t* hash)        { memcpy(commitHeader->hmac, hash, sizeof(commitHeader->hmac)); };
    void setHMACMulti(uint8_t* hash)   { memcpy(commitHeader->hmac-4*ZRTP_WORD_SIZE, hash, sizeof(commitHeader->hmac)); };

 private:
     CommitPacket_t data;
};

#endif // ZRTPPACKETCOMMIT

