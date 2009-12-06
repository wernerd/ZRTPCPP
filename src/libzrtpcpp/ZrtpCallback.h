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

#ifndef _ZRTPCALLBACK_H_
#define _ZRTPCALLBACK_H_

#include <string>
#include <stdint.h>
#include <libzrtpcpp/ZrtpCodes.h>

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

/**
 * This abstract class defines the callback functions required by GNU ZRTP.
 *
 * This class is a pure abstract class, aka Interface in Java, that
 * defines the callback interface that the specific part of a GNU ZRTP
 * must implement. The generic part of GNU ZRTP uses these mehtods
 * to communicate with the specific part, for example to send data
 * via the RTP/SRTP stack, to set timers and cancel timer and so on.
 *
 * The generiy part of GNU ZRTP needs only a few callback methods to
 * be implemented by the specific part.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpCallback {

protected:
    friend class ZRtp;

    virtual ~ZrtpCallback() {};
    /**
     * Send a ZRTP packet via RTP.
     *
     * ZRTP calls this method to send a ZRTP packet via the RTP session.
     *
     * @param data
     *    Points to ZRTP packet to send.
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
     *    zero if cancel action failed, one if timer was canceled
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
     * @param subCode
     *     The subcode identifying the reason.
     * @see ZrtpCodes#MessageSeverity
     */
    virtual void sendInfo(GnuZrtpCodes::MessageSeverity severity, int32_t subCode) =0;

    /**
     * SRTP crypto data ready for the sender or receiver.
     *
     * The ZRTP implementation calls this method right after all SRTP
     * secrets are computed and ready to be used. The parameter points
     * to a structure that contains pointers to the SRTP secrets and a
     * <code>enum Role</code>. The called method (the implementation
     * of this abstract method) must either copy the pointers to the SRTP
     * data or the SRTP data itself to a save place. The SrtpSecret_t
     * structure is destroyed after the callback method returns to the
     * ZRTP implementation.
     *
     * The SRTP data themselfs are ontained in the ZRtp object and are
     * valid as long as the ZRtp object is active. TheZRtp's
     * destructor clears the secrets. Thus the called method needs to
     * save the pointers only, ZRtp takes care of the data.
     *
     * The implementing class may enable SRTP processing in this
     * method or delay it to srtpSecertsOn().
     *
     * @param secrets A pointer to a SrtpSecret_t structure that
     *     contains all necessary data.
     *
     * @param part for which part (Sender or Receiver) this data is
     *     valid.
     *
     * @return Returns false if something went wrong during
     *    initialization of SRTP context, for example memory shortage.
     */
    virtual bool srtpSecretsReady(SrtpSecret_t* secrets, EnableSecurity part) =0;

    /**
     * Switch off the security for the defined part.
     *
     * @param part Defines for which part (sender or receiver) to
     *    switch on security
     */
    virtual void srtpSecretsOff(EnableSecurity part) =0;

    /**
     * Switch on the security.
     *
     * ZRTP calls this method after it has computed the SAS and check
     * if it is verified or not. In addition ZRTP provides information
     * about the cipher algorithm and key length for the SRTP session.
     *
     * This method must enable SRTP processing if it was not enabled
     * during sertSecretsReady().
     *
     * @param c The name of the used cipher algorithm and mode, or
     *    NULL
     *
     * @param s The SAS string
     *
     * @param verified if <code>verified</code> is true then SAS was
     *    verified by both parties during a previous call.
     */
    virtual void srtpSecretsOn(std::string c, std::string s, bool verified) =0;

    /**
     * This method handles GoClear requests.
     *
     * According to the ZRTP specification the user must be informed about
     * a GoClear request because the ZRTP implementation switches off security
     * if it could authenticate the GoClear packet.
     *
     * <b>Note:</b> GoClear is not yet implemented in GNU ZRTP.
     *
     */
    virtual void handleGoClear() =0;

    /**
     * Handle ZRTP negotiation failed.
     *
     * ZRTP calls this method in case ZRTP negotiation failed. The
     * parameters show the severity as well as the reason.
     *
     * @param severity
     *     This defines the message's severity
     * @param subCode
     *     The subcode identifying the reason.
     * @see ZrtpCodes#MessageSeverity
     */
    virtual void zrtpNegotiationFailed(GnuZrtpCodes::MessageSeverity severity, int32_t subCode) =0;

    /**
     * ZRTP calls this method if the other side does not support ZRTP.
     *
     * If the other side does not answer the ZRTP <em>Hello</em> packets then
     * ZRTP calls this method,
     *
     */
    virtual void zrtpNotSuppOther() =0;

    /**
     * Enter synchronization mutex.
     *
     * GNU ZRTP requires one mutes to synchronize its
     * processing. Because mutex implementations depend on the
     * underlying infrastructure, for example operating system or
     * thread implementation, GNU ZRTP delegates mutex handling to the
     * spcific part of its implementation.
     */
    virtual void synchEnter() =0;

    /**
     * Leave synchronization mutex.
     */
    virtual void synchLeave() =0;

    /**
     * Inform about a PBX enrollment request.
     *
     * Please refer to chapter 8.3 ff to get more details about PBX
     * enrollment and SAS relay.
     *
     * <b>Note:</b> PBX enrollement is not yet fully supported by GNU
     * ZRTP.
     *
     * @param info Give some information to the user about the PBX
     *    requesting an enrollment.
     */
    virtual void zrtpAskEnrollment(std::string info) =0;

    /**
     * Inform about PBX enrollment result.
     *
     * Informs the use about the acceptance or denial of an PBX enrollment
     * request
     *
     * <b>Note:</b> PBX enrollement is not yet fully supported by GNU
     * ZRTP.
     *
     * @param info Give some information to the user about the result
     *    of an enrollment.
     */
    virtual void zrtpInformEnrollment(std::string info) =0;

    /**
     * Request a SAS signature.
     *
     * After ZRTP was able to compute the Short Authentication String
     * (SAS) it calls this method. The client may now use an
     * approriate method to sign the SAS. The client may use
     * ZrtpQueue#setSignatureData() to store the signature data an
     * enable signature transmission to the other peer. Refer to
     * chapter 8.2 of ZRTP specification.
     *
     * <b>Note:</b> SAS signing is not yet fully supported by GNU
     * ZRTP.
     *
     * @param sas
     *    The SAS string to sign.
     *
     */
    virtual void signSAS(std::string sas) =0;

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
     * <b>Note:</b> SAS signing is not yet fully supported by GNU
     * ZRTP.
     *
     * @param sas
     *    The SAS string that was signed by the other peer.
     * @return
     *    true if the signature was ok, false otherwise.
     *
     */
    virtual bool checkSASSignature(std::string sas) =0;
};

#endif // ZRTPCALLBACK

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
