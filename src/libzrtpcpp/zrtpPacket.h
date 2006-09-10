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

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#ifndef ZRTPPACKET_H
#define ZRTPPACKET_H

#include <stdio.h>

#define	ZRTP_EXT_PACKET		0x505a

#define ZRTP_WORD_SIZE		4
#define ZRTP_MSG_SIZE		8 	// 2 * WORD_SIZE

#define MESSAGE_LENGTH		2
typedef struct zrtpPacketHeader {
    uint16_t    zrtpId;
    uint16_t    length;
    uint8_t     message[8];
} zrtpPacketHeader_t;


#define HELLO_LENGTH            62 /* plus the MESSAGE_LENGTH = 64 */
typedef struct Hello {
    uint8_t	version[4];
    uint8_t	clientId[31];
    uint8_t	flag;
    uint8_t     hashes[5][8];
    uint8_t     ciphers[5][8];
    uint8_t     authlengths[5][8];
    uint8_t	pubkeys[5][8];
    uint8_t	sas[5][8];
    uint8_t     zid[12];
} Hello_t;

typedef struct HelloPacket {
    zrtpPacketHeader_t hdr;
    Hello_t hello;
} HelloPacket_t;

typedef struct HelloAck {	/* Length is MESSAGE_LENGTH */
    zrtpPacketHeader_t hdr;
} HelloAck_t;

#define COMMIT_LENGTH           21 /* plus MESSAGE_LENGTH = 23 */
typedef struct Commit {
    uint8_t	zid[12];
    uint8_t     hash[8];
    uint8_t     cipher[8];
    uint8_t     authlengths[8];
    uint8_t	pubkey[8];
    uint8_t	sas[8];
    uint8_t	hvi[32];
} Commit_t;

typedef struct CommitPacket {
    zrtpPacketHeader_t hdr;
    Commit_t commit;
} CommitPacket_t;

#define DHPART_LENGTH		10 /* plus MESSAGE_LENGTH + pvr length */
typedef struct DHPart {
    uint8_t rs1Id[8];
    uint8_t rs2Id[8];
    uint8_t sigsId[8];
    uint8_t srtpsId[8];
    uint8_t otherSecretId[8];
}  DHPart_t;

typedef struct DHPartPacket {
    zrtpPacketHeader_t hdr;
} DHPartPacket_t;


#define CONFIRM_LENGTH		2 /* the rest of Confirm data goes into payload */
typedef struct Confirm {
    uint8_t	plaintext[15];
    uint8_t	flag;
    uint32_t    expTime;
    uint8_t	hmac[32];
} Confirm_t;

typedef struct ConfirmPacket {
    zrtpPacketHeader_t hdr;
    Confirm_t confirm;
} ConfirmPacket_t;

#define CONF2ACK_LENGTH         2
typedef struct Conf2Ack {
    zrtpPacketHeader_t hdr;
} Conf2Ack_t;

#define ERROR_LENGTH		2 /* plus MESSAGE_LENGTH = 4 */
typedef struct Error {
    uint8_t type[8];
} Error_t;

typedef struct ErrorPacket {
    zrtpPacketHeader_t hdr;
    Error_t error;
} ErrorPacket_t;

typedef struct GoClear {
    uint8_t clearHmac[32];
} GoClear_t;

#define GOCLEAR_LENGTH         8 /* plus MESSAGE_LENGTH = 10 */
typedef struct GoClearPacket {
    zrtpPacketHeader_t hdr;
    GoClear_t goClear;
} GoClearPacket_t;

#define CLEARACK_LENGTH         2
typedef struct ClearAck {
    zrtpPacketHeader_t hdr;
} ClearAck_t;


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

