/*
  Copyright (C) 2006-2009 Werner Dittmann

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

#define ZRTP_MAGIC       0x5a525450

#define ZRTP_WORD_SIZE   4
#define CRC_SIZE         4

#define TYPE_SIZE        (2*ZRTP_WORD_SIZE)
#define CLIENT_ID_SIZE   (4*ZRTP_WORD_SIZE)
#define HASH_IMAGE_SIZE  (8*ZRTP_WORD_SIZE)
#define ZID_SIZE         (3*ZRTP_WORD_SIZE)
#define HVI_SIZE         (8*ZRTP_WORD_SIZE)
#define HMAC_SIZE        (2*ZRTP_WORD_SIZE)
#define ID_SIZE          (2*ZRTP_WORD_SIZE)
#define IV_SIZE          (4*ZRTP_WORD_SIZE)
#define PING_HASH_SIZE   (2*ZRTP_WORD_SIZE)

/**
 * This include file defines the ZRTP message structures. Refer to chapter
 * 6 of the ZRTP specification for detailled information about the messages,
 * the fileds and their lengths.
 */

// The ZRTP Message header, refer to chapter 5ff
typedef struct zrtpPacketHeader {
    uint16_t    zrtpId;
    uint16_t    length;
    uint8_t     messageType[TYPE_SIZE];
} zrtpPacketHeader_t;

typedef struct Hello {
    uint8_t	version[ZRTP_WORD_SIZE];
    uint8_t	clientId[CLIENT_ID_SIZE];
    uint8_t     hashH3[HASH_IMAGE_SIZE];
    uint8_t     zid[ZID_SIZE];
    uint32_t	flagLength;
} Hello_t;

// The Hello packet has variable length. The following struct
// defines the fixed part only. The Hello class initializes the
// variable part.
typedef struct HelloPacket {
    zrtpPacketHeader_t hdr;
    Hello_t hello;
} HelloPacket_t;


typedef struct HelloAckPacket {
    zrtpPacketHeader_t hdr;
    uint8_t crc[ZRTP_WORD_SIZE];
} HelloAckPacket_t;

typedef struct Commit {
    uint8_t     hashH2[HASH_IMAGE_SIZE];
    uint8_t	zid[ZID_SIZE];
    uint8_t     hash[ZRTP_WORD_SIZE];
    uint8_t     cipher[ZRTP_WORD_SIZE];
    uint8_t     authlengths[ZRTP_WORD_SIZE];
    uint8_t	pubkey[ZRTP_WORD_SIZE];
    uint8_t	sas[ZRTP_WORD_SIZE];
    uint8_t	hvi[HVI_SIZE];
    uint8_t	hmac[HMAC_SIZE];
} Commit_t;

typedef struct CommitPacket {
    zrtpPacketHeader_t hdr;
    Commit_t commit;
    uint8_t crc[ZRTP_WORD_SIZE];
} CommitPacket_t;

typedef struct DHPart {
    uint8_t hashH1[HASH_IMAGE_SIZE];
    uint8_t rs1Id[ID_SIZE];
    uint8_t rs2Id[ID_SIZE];
    uint8_t auxSecretId[ID_SIZE];
    uint8_t pbxSecretId[ID_SIZE];
}  DHPart_t;

// The DHPart packet has variable length. The following struct
// defines the fixed part only. The DHPart class initializes the
// variable part.
typedef struct DHPartPacket {
    zrtpPacketHeader_t hdr;
    DHPart_t dhPart;
} DHPartPacket_t;

typedef struct Confirm {
    uint8_t	hmac[HMAC_SIZE];
    uint8_t     iv[IV_SIZE];
    uint8_t     hashH0[HASH_IMAGE_SIZE];
    uint8_t     filler[2];
    uint8_t     sigLength;
    uint8_t	flags;
    uint32_t    expTime;
} Confirm_t;

// The Confirm packet has variable length. The following struct
// defines the fixed part only. The Confirm class initializes the
// variable part.
typedef struct ConfirmPacket {
    zrtpPacketHeader_t hdr;
    Confirm_t confirm;
} ConfirmPacket_t;

typedef struct Conf2AckPacket {
    zrtpPacketHeader_t hdr;
    uint8_t     crc[ZRTP_WORD_SIZE];
} Conf2AckPacket_t;

// The GoClear and ClearAck packet are currently not used in
//GNU ZRTP C++ - not support for GoClear
typedef struct GoClear {
    uint8_t clearHmac[HMAC_SIZE];
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

typedef struct Ping {
    uint8_t version[ZRTP_WORD_SIZE];
    uint8_t epHash[PING_HASH_SIZE];
} Ping_t;

typedef struct PingPacket {
    zrtpPacketHeader_t hdr;
    Ping_t ping;
    uint8_t crc[ZRTP_WORD_SIZE];
} PingPacket_t;

typedef struct PingAck {
    uint8_t version[ZRTP_WORD_SIZE];
    uint8_t localEpHash[PING_HASH_SIZE];
    uint8_t remoteEpHash[PING_HASH_SIZE];
    uint32_t ssrc;
} PingAck_t;

typedef struct PingAckPacket {
    zrtpPacketHeader_t hdr;
    PingAck_t pingAck;
    uint8_t crc[ZRTP_WORD_SIZE];
} PingAckPacket_t;

#endif // ZRTPPACKET_H


/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
