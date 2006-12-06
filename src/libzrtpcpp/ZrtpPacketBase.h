/*
 Copyright (C) 2006 Werner Dittmann

 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#ifndef _ZRTPPACKETBASE_H_
#define _ZRTPPACKETBASE_H_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <netinet/in.h>

#include <libzrtpcpp/zrtpPacket.h>
#include <libzrtpcpp/ZrtpTextData.h>
#include <libzrtpcpp/ZrtpCrc32.h>

// #define DEBUGOUT(deb)   deb
#define DEBUGOUT(deb)

/*
 * This is the unique ZRTP ID in network order (PZ)
 */
const uint16_t zrtpId = ZRTP_EXT_PACKET;

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
    uint8_t* getMessage()          { return zrtpHeader->message; };

    void setLength(uint16_t len)  { zrtpHeader->length = htons(len); };
    void setMessage(uint8_t *msg) { memcpy(zrtpHeader->message, msg, ZRTP_MSG_SIZE); };
    void setZrtpId()              { zrtpHeader->zrtpId = htons(zrtpId); }

    /**
     * Check the CRC 32 value included in ZRTP packet.
     *
     * The CRC field is always the last field in the ZRTP packet. Thus take
     * - the length of the packet
     * - add 1 for the extension id and length,
     * - add 2 for the packet message and
     * - subtract 1 for the CRC field. 
     * These values are the number or words, thus multiply by 4 to get the 
     * length of the data in bytes. Compute the CRC over these number of bytes.
     */
    bool checkCrc32()
    {
      // Get CRC value into temp (see above how to compute the offset)
      uint32_t temp = *(uint32_t*)(((uint8_t*)zrtpHeader) + ((zrtpHeader->length + 3 - 1) * 4));
      // temp = ntohl(temp);

      return zrtpCheckCksum((uint8_t*)zrtpHeader, (zrtpHeader->length + 3 - 1) * 4, temp); 
    }

    void computeSetCrc32()
    {
      uint32_t temp = zrtpGenerateCksum((uint8_t*)zrtpHeader, (zrtpHeader->length + 3 - 1) * 4);
      // convert and store CRC in crc field of ZRTP packet.
      *(uint32_t*)(((uint8_t*)zrtpHeader) + ((zrtpHeader->length + 3 - 1) * 4)) = zrtpEndCksum(temp);
    }
};

#endif // ZRTPPACKETBASE
