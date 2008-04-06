/*
  Copyright (C) 2006-2007 Werner Dittmann

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

#ifndef _ZRTPUSERCALLBACK_H_
#define _ZRTPUSERCALLBACK_H_

#include <stdint.h>
#include <string>

// For message severity codes
#include <libzrtpcpp/ZrtpCallback.h>
#include <libzrtpcpp/ZrtpQueue.h>

/**
 * This class defines the user callback functions used by ZRTP.
 *
 * This class specifies the user callback functions used by the ZRTP 
 * implementation to communicate with the application that requires ZRTP
 * support.
 *
 * <p/>
 *
 * This ZRTP user callback class defines the methods that an application may
 * implement (overwrite) to trigger own activities, for example to inform about
 * security state, display information or error messages, and so on.
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpUserCallback {

    public:

        ZrtpUserCallback() {}

        virtual ~ZrtpUserCallback() {};

        /**
         * Inform user interface that security is active now.
         *
         * ZRTP calls this method if the sender and the receiver are
         * in secure mode now.
         *
         * @param cipher
         *    Name and mode of cipher used to encrypt the SRTP stream
         */
        virtual void secureOn(std::string cipher) {
            return;
        }
        /**
         * Inform user interface that security is not active any more.
         *
         * ZRTP calls this method if either the sender or the receiver
         * left secure mode.
         *
         */
        virtual void secureOff() {
            return;
        }

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
        virtual void showSAS(std::string sas, bool verified) {
            return;
        }

        /**
         * Inform the user that ZRTP received "go clear" message from its peer.
         *
         * On receipt of a go clear message the user is requested to confirm
         * a switch to unsecure (clear) modus. Until the user confirms ZRTP
         * (and the underlying RTP) does not send any data.
         */
        virtual void confirmGoClear() {
            return;
        }

        /**
         * Show some information to user.
         *
         * ZRTP calls this method to display some information to the user.
         * Along with the message ZRTP provides a severity indicator that
         * defines: Info, Warning, Error, and Alert. Refer to the <code>
         * MessageSeverity</code> enum in <code>ZrtpCallback.h</code>. The
         * UI may use this indicator to highlight messages or alike.
         *
         * @param sev
         *     Severity of the message.
         * @param message
         *     The string containing the SAS.
         */
        virtual void showMessage(MessageSeverity sev, std::string message) {
            return;
        }

        /**
         * ZRTPQueue calls this if the negotiation failed.
         *
         * ZRTPQueue calls this method in case ZRTP negotiation failed. The
         * parameters show the severity as well as some explanatory text.
         * Refer to the <code>MessageSeverity</code> enum above.
         *
         * @param severity
         *     This defines the message's severity
         * @param msg
         *     The message string, terminated with a null byte.
         */
        virtual void zrtpNegotiationFailed(MessageSeverity severity, std::string message) {
            return;
        }

        /**
         * ZRTPQueue calls this method if the other side does not support ZRTP.
         *
         * If the other side does not answer the ZRTP <em>Hello</em> packets then
         * ZRTP calls this method.
         *
         */
        virtual void zrtpNotSuppOther() {
            return;
        }

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
        virtual void zrtpAskEnrollment(std::string info) {
            return;
        }

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
        virtual void zrtpInformEnrollment(std::string info) {
            return;
        }

        /**
         * ZRTPQueue calls this method to request a SAS signature.
         *
         * After ZRTP was able to compute the Short Authentication String
         * (SAS) it calls this method. The client may now use an approriate
         * method to sign the SAS. The client may use 
         * <code>setSignatureData()</code> of ZrtpQueue to store the signature
         * data an enable signature transmission to the other peer. Refer
         * to chapter 8.2 of ZRTP specification.
         *
         * @param sas
         *    The SAS string to sign.
         *
         */
        virtual void signSAS(std::string sas) {
            return;
        }

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
         * @param sas
         *    The SAS string that was signed by the other peer.
         * @return
         *    true if the signature was ok, false otherwise.
         *
         */
        virtual bool checkSASSignature(std::string sas) {
            return true;
        }
};

#endif
