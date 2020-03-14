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
// Created by werner on 14.03.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#ifndef LIBZRTPCPP_ZRTPUSERCALLBACKEMPTY_H
#define LIBZRTPCPP_ZRTPUSERCALLBACKEMPTY_H

/**
 * @file
 * @brief ZRTP UserCallback class with empty functions
 * 
 * An application may derive from this class and implement (override) only thos functions
 * it is interessted in.
 *
 * @ingroup ZRTP
 * @{
 */

#include <libzrtpcpp/ZrtpUserCallback.h>

class __EXPORT ZrtpUserCallbackEmpty {

public:

    /// Create the standard user callback class.
    ZrtpUserCallback() = default;

    ~ZrtpUserCallback() = default;

    /**
     * Inform user interface that security is active now.
     *
     * ZRTP calls this method if the sender and the receiver are
     * in secure mode now.
     *
     * @param cipher
     *    Name and mode of cipher used to encrypt the SRTP stream
     */
    void secureOn(std::string cipher) {}
    /**
     * Inform user interface that security is not active any more.
     *
     * ZRTP calls this method if either the sender or the receiver
     * left secure mode.
     *
     */
    void secureOff() {}

    /**
     * Show the Short Authentication String (SAS) on user interface.
     *
     * ZRTP calls this method to display the SAS and inform about the SAS
     * verification status. The user interface shall enable a SAS verfication
     * button (or similar UI element). The user shall click on this UI
     * element after he/she confirmed the SAS code with the partner.
     *
     * @param sas
     *     The string containing the SAS.
     * @param verified
     *    If <code>verified</code> is true then SAS was verified by both
     *    parties during a previous call, otherwise it is set to false.
     */
    void showSAS(std::string sas, bool verified) {}

    /**
     * Inform the user that ZRTP received "go clear" message from its peer.
     *
     * On receipt of a go clear message the user is requested to confirm
     * a switch to unsecure (clear) modus. Until the user confirms ZRTP
     * (and the underlying RTP) does not send any data.
     */
    void confirmGoClear() {}

    /**
     * Show some information to user.
     *
     * ZRTP calls this method to display some information to the user.
     * Along with the message ZRTP provides a severity indicator that
     * defines: Info, Warning, Error, and Alert. Refer to the <code>
     * MessageSeverity</code> enum in <code>ZrtpCodes.h</code>. The
     * UI may use this indicator to highlight messages or alike.
     *
     * @param sev
     *     Severity of the message.
     * @param subCode
     *     The subcode identifying the reason.
     */
    void showMessage(GnuZrtpCodes::MessageSeverity sev, int32_t subCode) {}

    /**
     * ZRTPQueue calls this if the negotiation failed.
     *
     * ZRTPQueue calls this method in case ZRTP negotiation failed. The
     * parameters show the severity as well as some explanatory text.
     * Refer to the <code>MessageSeverity</code> enum above.
     *
     * @param severity
     *     This defines the message's severity
     * @param subCode
     *     The subcode identifying the reason.
     */
    void zrtpNegotiationFailed(GnuZrtpCodes::MessageSeverity severity, int32_t subCode) {}

    /**
     * ZRTPQueue calls this method if the other side does not support ZRTP.
     *
     * If the other side does not answer the ZRTP <em>Hello</em> packets then
     * ZRTP calls this method.
     *
     */
    void zrtpNotSuppOther() {}

    /**
     * ZRTPQueue calls this method to inform about a PBX enrollment request.
     *
     * Please refer to chapter 8.3 ff to get more details about PBX enrollment
     * and SAS relay.
     *
     * @param info
     *    Give some information to the user about the PBX requesting an
     *    enrollment.
     *
     */
    void zrtpAskEnrollment(GnuZrtpCodes::InfoEnrollment info) {}

    /**
     * ZRTPQueue calls this method to inform about PBX enrollment result.
     *
     * Informs the use about the acceptance or denial of an PBX enrollment
     * request
     *
     * @param info
     *    Give some information to the user about the result of an
     *    enrollment.
     *
     */
    void zrtpInformEnrollment(GnuZrtpCodes::InfoEnrollment info) {}

    /**
     * ZRTPQueue calls this method to request a SAS signature.
     *
     * After ZRTP core was able to compute the Short Authentication String
     * (SAS) it calls this method. The client may now use an approriate
     * method to sign the SAS. The client may use
     * setSignatureData() of ZrtpQueue to store the signature
     * data an enable signature transmission to the other peer. Refer
     * to chapter 8.2 of ZRTP specification.
     *
     * @param sasHash
     *    Pointer to the 32 byte SAS hash to be signed.
     * @see ZrtpQueue#setSignatureData
     *
     */
    void signSAS(uint8_t* sasHash) {}

    /**
     * ZRTPQueue calls this method to request a SAS signature check.
     *
     * After ZRTP received a SAS signature in one of the Confirm packets it
     * call this method. The client may use <code>getSignatureLength()</code>
     * and <code>getSignatureData()</code>of ZrtpQueue to get the signature
     * data and perform the signature check. Refer to chapter 8.2 of ZRTP
     * specification.
     *
     * If the signature check fails the client may return false to ZRTP. In
     * this case ZRTP signals an error to the other peer and terminates
     * the ZRTP handshake.
     *
     * @param sasHash
     *    Pointer to the 32 byte SAS hash that was signed by the other peer.
     * @return
     *    true if the signature was ok, false otherwise.
     *
     */
    bool checkSASSignature(uint8_t* sasHash) {
        return true;
    }
};

/**
 * @}
 */

#endif //LIBZRTPCPP_ZRTPUSERCALLBACKEMPTY_H
