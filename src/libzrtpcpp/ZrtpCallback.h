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

#ifndef _ZRTPCALLBACK_H_
#define _ZRTPCALLBACK_H_

#include <string>
#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * This class defines the callback functions required by ZRTP.
 *
 * This class is a pure abstract class, aka Interface in Java, that specifies
 * the callback interface for the ZRTP implementation. The ZRTP implementation
 * uses these functions to communicate with the host environment, for example
 * to send data via the RTP/SRTP stack, to set timers and cancel timer and so
 * on.
 *
 * <p/>
 *
 * This ZRTP needs only ten callback methods to be implemented by the host
 * environment.
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

/**
 * This enum defines the information message severity.
 *
 * The ZRTP implementation issues information messages to inform the user
 * about ongoing processing, unusual behavior, or alerts in case of severe
 * problems. The severity levels and their meaning are:
 *
 * <dl>
 * <dt>Info</dt> <dd>keeps the user informed about ongoing processing and
 *     security setup.
 * </dd>
 * <dt>Warning</dt> <dd>is an information about some security issues, e.g. if
 *     an AES 256 encryption is request but only DH 3072 as public key scheme
 *     is supported. ZRTP will establish a secure session (SRTP).
 * </dd>
 * <dt>Error</dt> <dd>is used if an error occured during ZRTP protocol usage. For
 *     example if an unknown or unsupported alogrithm is offerd. In case of
 *     <em>Error</em> ZRTP will <b>not</b> establish a secure session.
 * </dd>
 * <dt>Alert</dt> <dd>shows a real security problem. This probably falls into
 *     a <em>MitM</em> category. ZRTP of course will <b>not</b> establish a
 *     secure session.
 * </dd>
 * </dl>
 *
 */
enum MessageSeverity {
    Info = 1,
    Warning,
    Error,
    Alert
};

/**
 * This enum defines which role a ZRTP peer has.
 *
 * According to the ZRTP specification the role determines which keys to
 * use to encrypt or decrypt SRTP data.
 *
 * <ul>
 * <li> The Initiator encrypts SRTP data using the <em>keyInitiator</em> and the
 *      <em>saltInitiator</em> data, the Responder uses these data to decrypt.
 * </li>
 * <li> The Responder encrypts SRTP data using the <em>keyResponder</em> and the
 *      <em>saltResponder</em> data, the Initiator uses these data to decrypt.
 * </li>
 * </ul>
 */
typedef enum  {
    Responder = 1,
    Initiator
} Role;

/**
 * This structure contains pointers to the SRTP secrets and the role info.
 *
 * About the role and what the meaning of the role is refer to the
 * of the enum Role. The pointers to the secrets are valid as long as
 * the ZRtp object is active. To use these data after the ZRtp object's
 * lifetime you may copy the data into a save place. The destructor
 * of ZRtp clears the data.
 */
typedef struct srtpSecrets {
    const uint8_t* keyInitiator;
    int32_t initKeyLen;
    const uint8_t* saltInitiator;
    int32_t initSaltLen;
    const uint8_t* keyResponder;
    int32_t respKeyLen;
    const uint8_t* saltResponder;
    int32_t respSaltLen;
    int32_t srtpAuthTagLen;
    std::string sas;
    Role  role;
} SrtpSecret_t;

enum EnableSecurity {
    ForReceiver = 1,
    ForSender   = 2
};


class ZrtpCallback {

 public:
    virtual ~ZrtpCallback() {};
    /**
     * Send a ZRTP packet via RTP.
     *
     * ZRTP call this method if it needs to send data via RTP. The
     * data must not be encrypted before transfer.
     *
     * @param data
     *    Points to ZRTP packet to send as RTP extension header.
     * @param length
     *    The length in bytes of the data
     * @return
     *    zero if sending failed, one if packet was send
     */
    virtual int32_t sendDataZRTP(const uint8_t* data, int32_t length) =0;

    /**
     * Activate timer.
     *
     * @param time
     *    The time in ms for the timer
     * @return
     *    zero if activation failed, one if timer was activated
     */
    virtual int32_t activateTimer(int32_t time) =0;

    /**
     * Cancel the active timer.
     *
     * @return
     *    zero if activation failed, one if timer was activated
     */
    virtual int32_t cancelTimer() =0;

    /**
     * Send information messages to the hosting environment.
     *
     * The ZRTP implementation uses this method to send information
     * messages to the host. Along with the message ZRTP provides a
     * severity indicator that defines: Info, Warning, Error,
     * Alert. Refer to the <code>MessageSeverity</code> enum above.
     *
     * @param severity
     *     This defines the message's severity
     * @param msg
     *     The message string, terminated with a null byte.
     * @see #MessageSeverity
     */
    virtual void sendInfo(MessageSeverity severity, const char* msg) =0;

    /**
     * This method gets call by ZRTP as soon as the SRTP secrets are available.
     *
     * The ZRTP implementation calls this method right after all SRTP
     * secrets are computed and ready to be used. The parameter points
     * to a structure that contains pointers to the SRTP secrets and a
     * <code>enum Role</code>. The called host method (the
     * implementation of this abstract method) must copy the pointers
     * to the SRTP secrets it needs into a save place. The
     * SrtpSecret_t structure is destroyed when the callback method
     * returns to the ZRTP implementation.
     *
     * The SRTP secrets themselfs are ontained in the ZRtp object and
     * are valid as long as the ZRtp object is active. TheZRtp's
     * destructor clears the secrets.
     *
     * @param secrets
     *     A pointer to a SrtpSecret_t structure that contains all necessary
     *     data.
     * @param part
     *    Defines for which part (sender or receiver) to switch on security
     * @return
     *    Returns false if something went wrong during initialization of SRTP
     *    context, for example memory shortage.
     */
    virtual bool srtpSecretsReady(SrtpSecret_t* secrets, EnableSecurity part) =0;

    /**
     * This method shall clear the SRTP Context and switch off GUI inidicators.
     *
     * @param part
     *    Defines for which part (sender or receiver) to switch on security
     */
    virtual void srtpSecretsOff(EnableSecurity part) =0;

    /**
     * This method shall switch on GUI inidicators.
     *
     * @param c
     *    The name of the used cipher algorithm and mode, or NULL
     * @param s
     *    The SAS string
     * @param verified
     *    if <code>verified</code> is true then SAS was verified by both
     *    parties during a previous call.
     */
    virtual void srtpSecretsOn(std::string c, std::string s, bool verified) =0;

    /**
     * This method shall handle GoClear requests.
     *
     * According to the ZRTP specification the user must be informed about
     * this message because the ZRTP implementation switches off security
     * if it could authenticate the GoClear packet.
     *
     */
    virtual void handleGoClear() =0;

    /**
     * ZRTP calls this if the negotiation failed.
     *
     * ZRTP calls this method in case ZRTP negotiation failed. The parameters
     * show the severity as well as some explanatory text.
     * Refer to the <code>MessageSeverity</code> enum above.
     *
     * @param severity
     *     This defines the message's severity
     * @param msg
     *     The message string, terminated with a null byte.
     */
    virtual void zrtpNegotiationFailed(MessageSeverity severity, const char* msg) =0;

    /**
     * ZRTP calls this method if the other side does not support ZRTP.
     *
     * If the other side does not answer the ZRTP <em>Hello</em> packets then
     * ZRTP calls this method,
     *
     */
    virtual void zrtpNotSuppOther() =0;

    /**
     * ZRTP calls these methods to enter or leave its synchronization mutex.
     */
    virtual void synchEnter() =0;
    virtual void synchLeave() =0;

    /**
     * ZRTP uses this method to inform about a PBX enrollment request.
     *
     * Please refer to chapter 8.3 ff to get more details about PBX enrollment
     * and SAS relay.
     *
     * @param info
     *    Give some information to the user about the PBX requesting an
     *    enrollment.
     *
     */
    virtual void zrtpAskEnrollment(std::string info) =0;

    /**
     * ZRTP uses this method to inform about PBX enrollment result.
     *
     * Informs the use about the acceptance or denial of an PBX enrollment
     * request
     *
     * @param info
     *    Give some information to the user about the result of an
     *    enrollment.
     *
     */
    virtual void zrtpInformEnrollment(std::string info) =0;

};

#endif // ZRTPCALLBACK

