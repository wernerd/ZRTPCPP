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

#ifndef _ZRTPTEXTDATA_H_
#define _ZRTPTEXTDATA_H_

#include <libzrtpcpp/ZrtpConfigure.h>

/**
 * The extern references to the global data.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
extern char clientId[];
extern char zrtpVersion[];

/**
 *
 */
extern char HelloMsg[];
extern char HelloAckMsg[];
extern char CommitMsg[];
extern char DHPart1Msg[];
extern char DHPart2Msg[];
extern char Confirm1Msg[];
extern char Confirm2Msg[];
extern char Conf2AckMsg[];
extern char ErrorMsg[];
extern char ErrorAckMsg[];
extern char GoClearMsg[];
extern char ClearAckMsg[];
extern char PingMsg[];
extern char PingAckMsg[];

/**
 *
 */
extern char responder[];
extern char initiator[];
extern char iniMasterKey[];
extern char iniMasterSalt[];
extern char respMasterKey[];
extern char respMasterSalt[];

extern char iniHmacKey[];
extern char respHmacKey[];
extern char retainedSec[];

extern char iniZrtpKey[];
extern char respZrtpKey[];

extern char sasString[];

extern char KDFString[];
extern char zrtpSessionKey[];
extern char zrtpMsk[];


extern char s256[];
extern char s384[];
extern const char* mandatoryHash;

extern char aes3[];
extern char aes1[];
extern const char* mandatoryCipher;

extern char dh2k[];
                                  // "EC25"
extern char dh3k[];
                                  // "EC38"
extern char mult[];

extern const char* mandatoryPubKey;

extern char b32[];
extern const char* mandatorySasType;

extern char hs32[];
extern char hs80[];
extern const char* mandatoryAuthLen_1;
extern const char* mandatoryAuthLen_2;
#endif     // _ZRTPTEXTDATA_H_

