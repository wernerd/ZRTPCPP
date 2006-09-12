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

#ifndef _ZRTPUSERCALLBACK_H_
#define _ZRTPUSERCALLBACK_H_

#include <stdint.h>
#include <string>

// For message severity codes
#include <libzrtpcpp/ZrtpCallback.h>
#include <libzrtpcpp/ZrtpQueue.h>

/**
 * This class defines the user callback functions supported by ZRTP.
 *
 * This class is a pure abstract class, aka Interface in Java, that specifies
 * the user callback interface for the ZRTP implementation. The ZRTP
 * implementation uses these functions to communicate with a user interface
 * environment, for example to inform about security state, display messages,
 * and so on.
 *
 * <p/>
 *
 * This ZRTP interface defines five abstract callback methods to be
 * implemented by the user interface environment.
 *
 * This class also defines standard methods to interact with the ZrtpQueue
 * to control ZRTP behaviour.
 *
 * The destructor does not destroy any objects, it only sets pointers to
 * referenced classes to <ode>NULL</code>.
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpUserCallback {

    public:
        ZrtpUserCallback(ost::ZrtpQueue* queue) : zrtpQueue(queue) {}

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
        virtual void secureOn(std::string cipher) =0;

        /**
         * Inform user interface that security is not active any more.
         *
         * ZRTP calls this method if either the sender or the receiver
         * left secure mode.
         *
         */
        virtual void secureOff() =0;

        /**
         * Show the Short Authentication String (SAS) on user interface.
         *
         * ZRTP calls this method to display the SAS. After the SAS was
         * displayed the user interface code shall enable a SAS verfication
         * button (or similar UI element). The user shall click on this UI
         * element after he/she confirmed the SAS code with the partner.
         *
         * @param sas
         *     The string containing the SAS.
         */
        virtual void showSAS(std::string sas) =0;

        /**
         * Inform the user that ZRTP received "go clear" message from its peer.
         *
         * On receipt of a go clear message the user is requested to confirm
         * a switch to unsecure (clear) modus. Until the user confirms ZRTP
         * (and the underlying RTP) does not send any data.
         */
        virtual void confirmGoClear() =0;

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
        virtual void showMessage(MessageSeverity sev, std::string message) =0;

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
        virtual void zrtpNegotiationFailed(MessageSeverity severity, char* msg) =0;

        /**
         * ZRTPQueue calls this methof if the other side does not support ZRTP.
         *
         * If the other side does not answer the ZRTP <em>Hello</em> packets then
         * ZRTP calls this method,
         *
         */
        virtual void zrtpNotSuppOther() =0;

        /**
         * A user interface implementation uses the following methods to
         * control ZRTP. The standard methods are just proxies to the
         * according ZrtpQueue methods. An inheriting class may override
         * this implementation.
         */

        /**
         * Enable overall ZRTP processing.
         *
         * Call this method to enable ZRTP processing and switch to secure
         * mode eventually. This can be done before a call or at any time
         * during a call.
         *
         * @param onOff
         *     If set to true enable ZRTP, disable otherwise
         */
        virtual void enableZrtp(bool onOff) {
            zrtpQueue->setEnableZrtp(onOff);
        }

        /**
         * Set SAS as verified.
         *
         * Call this method if the user confirmed (verfied) the SAS. ZRTP
         * remembers this together with the retained secrets data.
         */
        virtual void SASVerified() {
            zrtpQueue->SASVerified();
        }

        /**
         * Confirm a go clear request.
         *
         * Call this method if the user confirmed a go clear (secure mode off).
         */
        virtual void goClearOk() {
            zrtpQueue->goClearOk();
        }

        /**
         * Request to switch off secure mode.
         *
         * Call this method is the user itself wants to switch off secure
         * mode (go clear). After sending the "go clear" request to the peer
         * ZRTP immediatly switch off SRTP processing. Every RTP data is sent
         * in clear after the go clear request.
         */
        virtual void requestGoClear()  {
            zrtpQueue->requestGoClear();
        }

        /**
         * Set the sigs secret.
         *
         * Use this method to set the sigs secret data. Refer to ZRTP
         * specification, chapter 3.2.1
         *
         * @param data
         *     Points to the sigs secret data. The data must have a length
         *     of 32 bytes (length of SHA256 hash)
         */
        virtual void setSigsSecret(uint8* data)  {
            zrtpQueue->setSigsSecret(data);
        }

        /**
         * Set the srtps secret.
         *
         * Use this method to set the srtps secret data. Refer to ZRTP
         * specification, chapter 3.2.1
         *
         * @param data
         *     Points to the srtps secret data. The data must have a length
         *     of 32 bytes (length of SHA256 hash)
         */
        virtual void setSrtpsSecret(uint8* data)  {
            zrtpQueue->setSrtpsSecret(data);
        }

        /**
         * Set the other secret.
         *
         * Use this method to set the other secret data. Refer to ZRTP
         * specification, chapter 3.2.1
         *
         * @param data
         *     Points to the other secret data.
         * @param length
         *     The length in bytes of the data.
         */
        virtual void setOtherSecret(uint8* data, int32 length)  {
            zrtpQueue->setOtherSecret(data, length);
        }

    private:
        ost::ZrtpQueue* zrtpQueue;

};

#endif
