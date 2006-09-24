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

#ifndef _ZIDRECORD_H_
#define _ZIDRECORD_H_

#include <string.h>

#define IDENTIFIER_LEN  12
#define RS_LENGTH       32

typedef struct zidrecord {
    char recValid,		// if 1 record is valid, if 0: invalid
	ownZid,			// if 1 record contains associated ZID, usually 1st record
	rs1Valid,			// if 1 RS1 contains valid data
	rs2Valid;			// if 1 RS2 contains valid data
    unsigned char identifier[IDENTIFIER_LEN]; // the peer's ZID
    unsigned char rs1Data[RS_LENGTH], rs2Data[RS_LENGTH]; // the peer's RS data
} zidrecord_t;

/**
 * This class implements the ZID record.
 *
 * The ZID record holds data about a peer. According to ZRTP specification
 * we use a ZID to identify a peer. ZRTP uses the RS (Retained Secret) data
 * to construct shared secrets.
 * <p/>
 * NOTE: ZIDRecord has ZIDFile as friend. ZIDFile knows about the private
 *	 data of ZIDRecord - please keep both classes synchronized.
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

static const int valid = 0x1;
static const int SASVerified = 0x2;

class ZIDRecord {
    friend class ZIDFile;

 private:
    zidrecord_t record;
    unsigned long position;

 public:
    ZIDRecord(unsigned char *idData) {
	memset(&record, 0, sizeof(zidrecord_t));
	memcpy(record.identifier, idData, IDENTIFIER_LEN);
    }

    int isRs1Valid() { return (record.rs1Valid & valid); }
    int isRs2Valid() { return (record.rs2Valid & valid); }

    void setSasVerified()   { record.rs1Valid |= SASVerified; }
    void resetSasVerified() { record.rs1Valid &= ~SASVerified; }
    int isSasVerified()     { return (record.rs1Valid & SASVerified); }

    const unsigned char *getRs1() { return record.rs1Data; }
    const unsigned char *getRs2() { return record.rs2Data; }

    void setNewRs1(const unsigned char*data);
};

#endif // ZIDRECORD


/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
