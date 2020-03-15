//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Created by werner on 15.03.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#include "ZrtpCodeToString.h"

static std::string noString("No string found.");

using namespace GnuZrtpCodes;

std::string const &
ZrtpCodeToString::getStringForCode(GnuZrtpCodes::MessageSeverity sev, int32_t subCode)
{

    switch (sev) {
        case GnuZrtpCodes::Info: {
            auto info = infoMap.find(subCode);
            if (info != infoMap.end()) {
                return info->second;
            }
            break;
        }
        case GnuZrtpCodes::Warning: {
            auto warn = warningMap.find(subCode);
            if (warn != warningMap.end()) {
                return warn->second;
            }
            break;
        }
        case GnuZrtpCodes::Severe: {
            auto severe = severeMap.find(subCode);
            if (severe != severeMap.end()) {
                return severe->second;
            }
            break;

        }
        case GnuZrtpCodes::ZrtpError: {
            if (subCode < 0) {  // received an error packet from peer
                subCode *= -1;
                auto zrtpError = zrtpMapR.find(subCode);
                if (zrtpError != zrtpMapR.end()) {
                    return zrtpError->second;
                }
            } else {
                auto zrtpError = zrtpMapS.find(subCode);
                if (zrtpError != zrtpMapS.end()) {
                    return zrtpError->second;
                }
            }
            break;
        }

        default:
            break;
    }
    return noString;
}

void ZrtpCodeToString::initialize()
{
    infoMap.insert(std::pair<int32_t, std::string>(InfoHelloReceived,      std::string("s1_c001: Hello received, preparing a Commit")));
    infoMap.insert(std::pair<int32_t, std::string>(InfoCommitDHGenerated,  std::string("s1_c002: Commit: Generated a public DH key")));
    infoMap.insert(std::pair<int32_t, std::string>(InfoRespCommitReceived, std::string("s1_c003: Responder: Commit received, preparing DHPart1")));
    infoMap.insert(std::pair<int32_t, std::string>(InfoDH1DHGenerated,     std::string("s1_c004: DH1Part: Generated a public DH key")));
    infoMap.insert(std::pair<int32_t, std::string>(InfoInitDH1Received,    std::string("s1_c005: Initiator: DHPart1 received, preparing DHPart2")));
    infoMap.insert(std::pair<int32_t, std::string>(InfoRespDH2Received,    std::string("s1_c006: Responder: DHPart2 received, preparing Confirm1")));
    infoMap.insert(std::pair<int32_t, std::string>(InfoInitConf1Received,  std::string("s1_c007: Initiator: Confirm1 received, preparing Confirm2")));
    infoMap.insert(std::pair<int32_t, std::string>(InfoRespConf2Received,  std::string("s1_c008: Responder: Confirm2 received, preparing Conf2Ack")));
    infoMap.insert(std::pair<int32_t, std::string>(InfoRSMatchFound,       std::string("s1_c009: At least one retained secrets matches - security OK")));
    infoMap.insert(std::pair<int32_t, std::string>(InfoSecureStateOn,      std::string("s1_c010: Entered secure state")));
    infoMap.insert(std::pair<int32_t, std::string>(InfoSecureStateOff,     std::string("s1_c011: No more security for this session")));

    warningMap.insert(std::pair<int32_t, std::string>(WarningDHAESmismatch,   std::string("s2_c001: Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096")));
    warningMap.insert(std::pair<int32_t, std::string>(WarningGoClearReceived, std::string("s2_c002: Received a GoClear message")));
    warningMap.insert(std::pair<int32_t, std::string>(WarningDHShort,         std::string("s2_c003: Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096")));
    warningMap.insert(std::pair<int32_t, std::string>(WarningNoRSMatch,       std::string("s2_c004: No retained secret matches - verify SAS")));
    warningMap.insert(std::pair<int32_t, std::string>(WarningCRCmismatch,     std::string("s2_c005: Internal ZRTP packet CRC mismatch - packet dropped")));
    warningMap.insert(std::pair<int32_t, std::string>(WarningSRTPauthError,   std::string("s2_c006: Dropping packet because SRTP authentication failed!")));
    warningMap.insert(std::pair<int32_t, std::string>(WarningSRTPreplayError, std::string("s2_c007: Dropping packet because SRTP replay check failed!")));
    warningMap.insert(std::pair<int32_t, std::string>(WarningNoExpectedRSMatch,
                                                       std::string("s2_c008: You MUST check SAS with your partner. If it doesn't match, it indicates the presence of a wiretapper.")));
    warningMap.insert(std::pair<int32_t, std::string>(WarningNoExpectedAuxMatch, std::string("s2_c009: Expected auxiliary secret match failed")));

    severeMap.insert(std::pair<int32_t, std::string>(SevereHelloHMACFailed,  std::string("s3_c001: Hash HMAC check of Hello failed!")));
    severeMap.insert(std::pair<int32_t, std::string>(SevereCommitHMACFailed, std::string("s3_c002: Hash HMAC check of Commit failed!")));
    severeMap.insert(std::pair<int32_t, std::string>(SevereDH1HMACFailed,    std::string("s3_c003: Hash HMAC check of DHPart1 failed!")));
    severeMap.insert(std::pair<int32_t, std::string>(SevereDH2HMACFailed,    std::string("s3_c004: Hash HMAC check of DHPart2 failed!")));
    severeMap.insert(std::pair<int32_t, std::string>(SevereCannotSend,       std::string("s3_c005: Cannot send data - connection or peer down?")));
    severeMap.insert(std::pair<int32_t, std::string>(SevereProtocolError,    std::string("s3_c006: Internal protocol error occurred!")));
    severeMap.insert(std::pair<int32_t, std::string>(SevereNoTimer,          std::string("s3_c007: Cannot start a timer - internal resources exhausted?")));
    severeMap.insert(std::pair<int32_t, std::string>(SevereTooMuchRetries,   std::string("s3_c008: Too many retries during ZRTP negotiation - connection or peer down?")));

    zrtpMapR.insert(std::pair<int32_t, std::string>(MalformedPacket,   std::string("s4_c016: Received: Malformed packet (CRC OK, but wrong structure)")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(CriticalSWError,   std::string("s4_c020: Received: Critical software error")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(UnsuppZRTPVersion, std::string("s4_c048: Received: Unsupported ZRTP version")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(HelloCompMismatch, std::string("s4_c064: Received: Hello components mismatch")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(UnsuppHashType,    std::string("s4_c081: Received: Hash type not supported")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(UnsuppCiphertype,  std::string("s4_c082: Received: Cipher type not supported")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(UnsuppPKExchange,  std::string("s4_c083: Received: Public key exchange not supported")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(UnsuppSRTPAuthTag, std::string("s4_c084: Received: SRTP auth. tag not supported")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(UnsuppSASScheme,   std::string("s4_c085: Received: SAS scheme not supported")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(NoSharedSecret,    std::string("s4_c086: Received: No shared secret available, DH mode required")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(DHErrorWrongPV,    std::string("s4_c097: Received: DH Error: bad pvi or pvr ( == 1, 0, or p-1)")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(DHErrorWrongHVI,   std::string("s4_c098: Received: DH Error: hvi != hashed data")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(SASuntrustedMiTM,  std::string("s4_c099: Received: Received relayed SAS from untrusted MiTM")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(ConfirmHMACWrong,  std::string("s4_c112: Received: Auth. Error: Bad Confirm pkt HMAC")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(NonceReused,       std::string("s4_c128: Received: Nonce reuse")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(EqualZIDHello,     std::string("s4_c144: Received: Duplicate ZIDs in Hello Packets")));
    zrtpMapR.insert(std::pair<int32_t, std::string>(GoCleatNotAllowed, std::string("s4_c160: Received: GoClear packet received, but not allowed")));

    zrtpMapS.insert(std::pair<int32_t, std::string>(MalformedPacket,   std::string("s4_c016: Sent: Malformed packet (CRC OK, but wrong structure)")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(CriticalSWError,   std::string("s4_c020: Sent: Critical software error")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(UnsuppZRTPVersion, std::string("s4_c048: Sent: Unsupported ZRTP version")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(HelloCompMismatch, std::string("s4_c064: Sent: Hello components mismatch")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(UnsuppHashType,    std::string("s4_c081: Sent: Hash type not supported")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(UnsuppCiphertype,  std::string("s4_c082: Sent: Cipher type not supported")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(UnsuppPKExchange,  std::string("s4_c083: Sent: Public key exchange not supported")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(UnsuppSRTPAuthTag, std::string("s4_c084: Sent: SRTP auth. tag not supported")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(UnsuppSASScheme,   std::string("s4_c085: Sent: SAS scheme not supported")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(NoSharedSecret,    std::string("s4_c086: Sent: No shared secret available, DH mode required")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(DHErrorWrongPV,    std::string("s4_c097: Sent: DH Error: bad pvi or pvr ( == 1, 0, or p-1)")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(DHErrorWrongHVI,   std::string("s4_c098: Sent: DH Error: hvi != hashed data")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(SASuntrustedMiTM,  std::string("s4_c099: Sent: Received relayed SAS from untrusted MiTM")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(ConfirmHMACWrong,  std::string("s4_c112: Sent: Auth. Error: Bad Confirm pkt HMAC")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(NonceReused,       std::string("s4_c128: Sent: Nonce reuse")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(EqualZIDHello,     std::string("s4_c144: Sent: Duplicate ZIDs in Hello Packets")));
    zrtpMapS.insert(std::pair<int32_t, std::string>(GoCleatNotAllowed, std::string("s4_c160: Sent: GoClear packet received, but not allowed")));
}
