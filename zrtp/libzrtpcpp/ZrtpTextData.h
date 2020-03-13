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
 * @ingroup ZRTP
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
__EXPORT constexpr char s256[] = "S256";        //!< SHA-256 hash
__EXPORT constexpr char s384[] = "S384";        //!< SHA-384 hash
__EXPORT constexpr char skn2[] = "SKN2";        //!< Skein-256 hash (https://en.wikipedia.org/wiki/Skein_(hash_function))
__EXPORT constexpr char skn3[] = "SKN3";        //!< Skein-384 hash (https://en.wikipedia.org/wiki/Skein_(hash_function))
constexpr const char* mandatoryHash = s256;

__EXPORT constexpr char aes3[] = "AES3";        //!< AES symmetric cipher with 256 bit key length, use to enrypt/decrypt media data (also defined in SRTP, RFC3711)
__EXPORT constexpr char aes2[] = "AES2";        //!< AES symmetric cipher with 192 bit key length, use to enrypt/decrypt media data (also defined in SRTP, RFC3711)
__EXPORT constexpr char aes1[] = "AES1";        //!< AES symmetric cipher with 128 bit key length, use to enrypt/decrypt media data (also defined in SRTP, RFC3711)
__EXPORT constexpr char two3[] = "2FS3";        //!< Twofish symmetric cipher with 256 bit key length, use to enrypt/decrypt media data
__EXPORT constexpr char two2[] = "2FS2";        //!< Twofish symmetric cipher with 192 bit key length, use to enrypt/decrypt media data
__EXPORT constexpr char two1[] = "2FS1";        //!< Twofish symmetric cipher with 128 bit key length, use to enrypt/decrypt media data
constexpr const char* mandatoryCipher = aes1;

__EXPORT const char dh2k[] = "DH2k";        //!< Diffie-Hellman using a 2048 bit finite field, see RFC3526 - not recommended anymore
__EXPORT const char ec25[] = "EC25";        //!< Diffie-Hellman using the NIST Elliptic Curve defined by FIPS 186-2, P-256
__EXPORT const char dh3k[] = "DH3k";        //!< Diffie-Hellman using a 3072 bit finite field, see RFC3526
__EXPORT const char ec38[] = "EC38";        //!< Diffie-Hellman using the NIST Elliptic Curve defined by FIPS 186-2, P-384
__EXPORT const char e255[] = "E255";        //!< Diffie-Hellman using Curve EC25519 (see https://safecurves.cr.yp.to/equation.html)
__EXPORT const char e414[] = "E414";        //!< Diffie-Hellman using Curve41417 (see https://safecurves.cr.yp.to/equation.html), optional
__EXPORT const char sdh5[] = "SDH5";        //!< SIDH 503 algorithm, allegedly Quantum safe (see https://github.com/microsoft/PQCrypto-SIDH), optional, experimental
__EXPORT const char sdh7[] = "SDH7";        //!< SIDH 751 algorithm, allegedly Quantum safe (see https://github.com/microsoft/PQCrypto-SIDH), optional, experimental
__EXPORT const char mult[] = "Mult";        //!< Multi-stream, required if applications like to avoid additional key negotiation when using several encrypted media streams
constexpr const char* mandatoryPubKey = dh3k;

__EXPORT constexpr char b32[] =  "B32 ";        //!< Use 4 characters to show the SAS
__EXPORT constexpr char b256[] = "B256";        //!< Use two words to show the SAS
__EXPORT constexpr char b32e[] = "B32E";        //!< Use selected Emojis instead of letters/digits
__EXPORT constexpr char b10d[] = "B10D";        //!< Use 6 digits, this may be used for international SAS values
constexpr const char* mandatorySasType = b32;

__EXPORT constexpr char hs32[] = "HS32";        //!< Use 32-bits of HMAC-SHA1 as authentication tag for SRTP (see RFC3711, sections 3.1, 3.4)
__EXPORT constexpr char hs80[] = "HS80";        //!< Use 80-bits of HMAC-SHA1 as authentication tag for SRTP (see RFC3711, sections 3.1, 3.4)
__EXPORT constexpr char sk32[] = "SK32";        //!< Use 32-bits of HMAC-Skein as authentication for tag SRTP (non-standard)
__EXPORT constexpr char sk64[] = "SK64";        //!< Use 80-bits of HMAC-Skein as authentication for tag SRTP (non-standard)
constexpr const char* mandatoryAuthLen_1 = hs32;
constexpr const char* mandatoryAuthLen_2 = hs80;

extern const char* sas256WordsOdd[];
extern const char* sas256WordsEven[];

/**
 * @}
 */
#endif     // _ZRTPTEXTDATA_H_

