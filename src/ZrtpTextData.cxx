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
#include <stdint.h>
/**
 *
 */
char *clientId = "GNUccRTP      "; // must be 15 chars
char *zrtpVersion = "0.02";	// must be 4 chars

/**
 *
 */
char *HelloMsg =    "Hello   ";
char *HelloAckMsg = "HelloACK";
char *CommitMsg =   "Commit  ";
char *DHPart1Msg =  "DHPart1 ";
char *DHPart2Msg =  "DHPart2 ";
char *Confirm1Msg = "Confirm1";
char *Confirm2Msg = "Confirm2";
char *Conf2AckMsg = "Conf2ACK";
char *ErrorMsg =    "Error   ";
char *GoClearMsg =  "GoClear ";
char *ClearAckMsg = "ClearACK";

/**
 *
 */
char *responder = "Responder";
char *initiator = "Initiator";
char *iniMasterKey = "Initiator SRTP master key";
char *iniMasterSalt = "Initiator SRTP master salt";
char *respMasterKey = "Responder SRTP master key";
char *respMasterSalt = "Responder SRTP master salt";

char *hmacKey = "HMAC key";
char *retainedSec = "retained secret";
char *knownPlain = "known plaintext";

char *sasString = "Short Authentication String";

/**
 * The arrays are sorted: the most secure / best algorithm is first in the
 * array
 */
char *supportedHashes[] = { "SHA256  ",
			    "        ",
			    "        ",
			    "        ",
			    "        " };

char *supportedCipher[] = { "AES256  ",
			    "AES128  ",
			    "        ",
			    "        ",
			    "        " };

char *supportedPubKey[] = { "DH4096  ",
			    "DH3072  ",
			    "        ",
			    "        ",
			    "        " };

char *supportedSASType[] = { "libase32",
			    "        ",
			    "        ",
			    "        ",
			    "        " };

char *supportedAuthLen[] = { "80      ",
                             "32      ",
                             "        ",
                             "        ",
                             "        " };
