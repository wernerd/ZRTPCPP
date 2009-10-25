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

#ifndef _ZRTPPACKETBASE_H_
#define _ZRTPPACKETBASE_H_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

#include <libzrtpcpp/zrtpPacket.h>
#include <libzrtpcpp/ZrtpTextData.h>
#include <libzrtpcpp/ZrtpConfigure.h>
#include <libzrtpcpp/ZrtpCrc32.h>

// #define DEBUGOUT(deb)   deb
#define DEBUGOUT(deb)

/*
 * This is the unique ZRTP ID in network order (PZ)
 */
const uint16_t zrtpId = 0x505a;

/**
 * This is the base class for all ZRTP packets
 *
 * All other ZRTP packet classes inherit from this class. It does not have
 * an implementation of its own.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpPacketBase {

  private:

  protected:
      void* allocated;
      zrtpPacketHeader_t* zrtpHeader;

  public:
      virtual ~ZrtpPacketBase() {};

    const uint8_t* getHeaderBase() { return (const uint8_t*)zrtpHeader; };
    bool isZrtpPacket()            { return (ntohs(zrtpHeader->zrtpId) == zrtpId); };
    uint16_t getLength()           { return ntohs(zrtpHeader->length); };
    uint8_t* getMessageType()      { return zrtpHeader->messageType; };

    void setLength(uint16_t len)  { zrtpHeader->length = htons(len); };
    void setMessageType(uint8_t *msg) 
        { memcpy(zrtpHeader->messageType, msg, sizeof(zrtpHeader->messageType)); };
    void setZrtpId()              { zrtpHeader->zrtpId = htons(zrtpId); }
};

#endif // ZRTPPACKETBASE
