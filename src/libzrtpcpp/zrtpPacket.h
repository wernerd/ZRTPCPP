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

#ifndef ZRTPPACKET_H
#define ZRTPPACKET_H

#include <stdio.h>

#define	ZRTP_MAGIC		0x5a525450

#define ZRTP_WORD_SIZE		4
#define CRC_SIZE                4

// The ZRTP Message header, refer to chapter 6.2ff
typedef struct zrtpPacketHeader {
    uint16_t    zrtpId;
    uint16_t    length;
    uint8_t     messageType[2*ZRTP_WORD_SIZE];
} zrtpPacketHeader_t;

typedef struct Hello {
    uint8_t	version[ZRTP_WORD_SIZE];
    uint8_t	clientId[3*ZRTP_WORD_SIZE];
//  uint8_t     hashH3[4*ZRTP_WORD_SIZE];
    uint8_t     zid[3*ZRTP_WORD_SIZE];
    uint32_t	flagLength;
} Hello_t;

typedef struct HelloPacket {
    zrtpPacketHeader_t hdr;
    Hello_t hello;
} HelloPacket_t;


typedef struct HelloAckPacket {
    zrtpPacketHeader_t hdr;
    uint8_t crc[ZRTP_WORD_SIZE];
} HelloAckPacket_t;

typedef struct Commit {
//  uint8_t     hashH2[4*ZRTP_WORD_SIZE];
    uint8_t	zid[3*ZRTP_WORD_SIZE];
    uint8_t     hash[ZRTP_WORD_SIZE];
    uint8_t     cipher[ZRTP_WORD_SIZE];
    uint8_t     authlengths[ZRTP_WORD_SIZE];
    uint8_t	pubkey[ZRTP_WORD_SIZE];
    uint8_t	sas[ZRTP_WORD_SIZE];
    uint8_t	hvi[8*ZRTP_WORD_SIZE];
} Commit_t;

typedef struct CommitPacket {
    zrtpPacketHeader_t hdr;
    Commit_t commit;
    uint8_t crc[ZRTP_WORD_SIZE];
} CommitPacket_t;

typedef struct DHPart {
//  uint8_t     hashH1[4*ZRTP_WORD_SIZE];
    uint8_t rs1Id[2*ZRTP_WORD_SIZE];
    uint8_t rs2Id[2*ZRTP_WORD_SIZE];
    uint8_t sigsId[2*ZRTP_WORD_SIZE];
    uint8_t srtpsId[2*ZRTP_WORD_SIZE];
    uint8_t otherSecretId[2*ZRTP_WORD_SIZE];
}  DHPart_t;

typedef struct DHPartPacket {
    zrtpPacketHeader_t hdr;
    DHPart_t dhPart;           // Since 0.4a
} DHPartPacket_t;

typedef struct Confirm {
    uint8_t	hmac[2*ZRTP_WORD_SIZE];
    uint8_t     iv[4*ZRTP_WORD_SIZE];
    uint8_t     filler[2];
    uint8_t     sigLength;
    uint8_t	flags;
    uint32_t    expTime;
    uint8_t     SASRenderScheme[ZRTP_WORD_SIZE];
    uint32_t    trustedSASValue;
} Confirm_t;

typedef struct ConfirmPacket {
    zrtpPacketHeader_t hdr;
    Confirm_t confirm;
} ConfirmPacket_t;

typedef struct Conf2AckPacket {
    zrtpPacketHeader_t hdr;
    uint8_t     crc[ZRTP_WORD_SIZE];
} Conf2AckPacket_t;

typedef struct GoClear {
    uint8_t clearHmac[2*ZRTP_WORD_SIZE];
} GoClear_t;

typedef struct GoClearPacket {
    zrtpPacketHeader_t hdr;
    GoClear_t goClear;
    uint8_t crc[ZRTP_WORD_SIZE];
} GoClearPacket_t;

typedef struct ClearAckPacket {
    zrtpPacketHeader_t hdr;
    uint8_t crc[ZRTP_WORD_SIZE];
} ClearAckPacket_t;

typedef struct Error {
    uint32_t errorCode;
} Error_t;

typedef struct ErrorPacket {
    zrtpPacketHeader_t hdr;
    Error_t error;
    uint8_t crc[ZRTP_WORD_SIZE];
} ErrorPacket_t;

typedef struct ErrorAckPacket {
    zrtpPacketHeader_t hdr;
    uint8_t crc[ZRTP_WORD_SIZE];
} ErrorAckPacket_t;

/* big/little endian conversion */

#if 0

static inline uint16_t U16_AT( void const * _p )
{
    const uint8_t * p = (const uint8_t *)_p;
    return ( ((uint16_t)p[0] << 8) | p[1] );
}
static inline uint32_t U32_AT( void const * _p )
{
    const uint8_t * p = (const uint8_t *)_p;
    return ( ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
              | ((uint32_t)p[2] << 8) | p[3] );
}
static inline uint64_t U64_AT( void const * _p )
{
    const uint8_t * p = (const uint8_t *)_p;
    return ( ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
              | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
              | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
              | ((uint64_t)p[6] << 8) | p[7] );
}
#if defined WORDS_BIGENDIAN
#   define hton16(i)   ( i )
#   define hton32(i)   ( i )
#   define hton64(i)   ( i )
#   define ntoh16(i)   ( i )
#   define ntoh32(i)   ( i )
#   define ntoh64(i)   ( i )
#else
#   define hton16(i)   U16_AT(&i)
#   define hton32(i)   U32_AT(&i)
#   define hton64(i)   U64_AT(&i)
#   define ntoh16(i)   U16_AT(&i)
#   define ntoh32(i)   U32_AT(&i)
#   define ntoh64(i)   U64_AT(&i)
#endif

#endif //hton16

#endif // ZRTPPACKET_H


/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
