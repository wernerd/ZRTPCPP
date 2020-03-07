/*
 * Copyright 2006 - 2018, Werner Dittmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#ifndef _ZRTPTEXTDATA_H_
#define _ZRTPTEXTDATA_H_

/**
 * @file ZrtpTextData.h
 * @brief The ZRTP ASCII texts - extern references
 *  
 * @ingroup GNU_ZRTP
 * @{
 */

#include <common/osSpecifics.h>

/**
 * The extern references to the global data.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

extern char zrtpBuildInfo[];

extern char clientId[];
extern char zrtpVersion_11[];
extern char zrtpVersion_12[];

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
extern char SasRelayMsg[];
extern char RelayAckMsg[];

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
extern char zrtpExportedKey[];
extern char zrtpMsk[];
extern char zrtpTrustedMitm[];

// Make these constants accessible to external functions
__EXPORT constexpr char s256[] = "S256";
__EXPORT constexpr char s384[] = "S384";
__EXPORT constexpr char skn2[] = "SKN2";
__EXPORT constexpr char skn3[] = "SKN3";
constexpr const char* mandatoryHash = s256;

__EXPORT constexpr char aes3[] = "AES3";
__EXPORT constexpr char aes2[] = "AES2";
__EXPORT constexpr char aes1[] = "AES1";
__EXPORT constexpr char two3[] = "2FS3";
__EXPORT constexpr char two2[] = "2FS2";
__EXPORT constexpr char two1[] = "2FS1";
constexpr const char* mandatoryCipher = aes1;

__EXPORT constexpr char dh2k[] = "DH2k";
__EXPORT constexpr char ec25[] = "EC25";
__EXPORT constexpr char dh3k[] = "DH3k";
__EXPORT constexpr char ec38[] = "EC38";
__EXPORT constexpr char e255[] = "E255";
__EXPORT constexpr char e414[] = "E414";
__EXPORT constexpr char sdh5[] = "SDH5";
__EXPORT constexpr char sdh7[] = "SDH7";
__EXPORT constexpr char mult[] = "Mult";
constexpr const char* mandatoryPubKey = dh3k;

__EXPORT constexpr char b32[] =  "B32 ";
__EXPORT constexpr char b256[] = "B256";
__EXPORT constexpr char b32e[] = "B32E";       // Use Emojis instead of letters/digits
__EXPORT constexpr char b10d[] = "B10D";       // Use 6 digits, this may be used for international SAS values
constexpr const char* mandatorySasType = b32;

__EXPORT constexpr char hs32[] = "HS32";
__EXPORT constexpr char hs80[] = "HS80";
__EXPORT constexpr char sk32[] = "SK32";
__EXPORT constexpr char sk64[] = "SK64";
constexpr const char* mandatoryAuthLen_1 = hs32;
constexpr const char* mandatoryAuthLen_2 = hs80;

extern const char* sas256WordsOdd[];
extern const char* sas256WordsEven[];

/**
 * @}
 */
#endif     // _ZRTPTEXTDATA_H_

