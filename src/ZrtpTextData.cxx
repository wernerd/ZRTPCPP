/*
  Copyright (C) 2006-2008 Werner Dittmann

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
#include <stdint.h>
/**
 *
 */
//                                  1
//                         1234567890123456
const char *clientId =    "GNU ZRTP 1.4.3  "; // 16 chars
const char *zrtpVersion = "1.10";	// must be 4 chars
/**
 *
 */
const char* HelloMsg =    "Hello   ";
const char* HelloAckMsg = "HelloACK";
const char* CommitMsg =   "Commit  ";
const char* DHPart1Msg =  "DHPart1 ";
const char* DHPart2Msg =  "DHPart2 ";
const char* Confirm1Msg = "Confirm1";
const char* Confirm2Msg = "Confirm2";
const char* Conf2AckMsg = "Conf2ACK";
const char* ErrorMsg =    "Error   ";
const char* ErrorAckMsg = "ErrorACK";
const char* GoClearMsg =  "GoClear ";
const char* ClearAckMsg = "ClearACK";
const char* PingMsg =     "Ping    ";
const char* PingAckMsg =  "PingACK ";

/**
 *
 */
const char* responder = "Responder";
const char* initiator = "Initiator";
const char* iniMasterKey = "Initiator SRTP master key";
const char* iniMasterSalt = "Initiator SRTP master salt";
const char* respMasterKey = "Responder SRTP master key";
const char* respMasterSalt = "Responder SRTP master salt";

const char* iniHmacKey = "Initiator HMAC key";
const char* respHmacKey = "Responder HMAC key";
const char* retainedSec = "retained secret";

const char* iniZrtpKey = "Initiator ZRTP key";
const char* respZrtpKey = "Responder ZRTP key";

const char* sasString = "SAS";

const char* KDFString = "ZRTP-HMAC-KDF";

const char* zrtpSessionKey = "ZRTP Session Key";

const char* zrtpMsk = "ZRTP MSK";

/**
 * The arrays are sorted: the most secure / best algorithm is first in the
 * array. If we add an algorithm here then we need to adjust the corresponding
 * value in ZrtpTextData.h as well.
 */
const char *supportedHashes[] =  {"S256"};

const char *supportedCipher[] =  {"AES3",
                                  "AES1"};

const char *supportedPubKey[] =  {"DH2k",
                                  // "EC25"
                                  "DH3k",
                                  // "EC38"
                                  "Mult"};

const char *supportedSASType[] = {"B32 "};

const char *supportedAuthLen[] = {"HS32",
                                  "HS80"};
