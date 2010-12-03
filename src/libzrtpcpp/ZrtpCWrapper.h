/*
    <one line to give the program's name and a brief idea of what it does.>
    Copyright (C) <year>  <name of author>

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

#ifndef ZRTPCWRAPPER_H
#define ZRTPCWRAPPER_H

#include <stdint.h>

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
/*
 * Keep the following defines in sync with Role enumeration in ZrtpCallback.h
 */
#define Responder 1
#define Initiator 2

/**
 * This structure contains pointers to the SRTP secrets and the role info.
 *
 * About the role and what the meaning of the role is refer to the
 * of the enum Role. The pointers to the secrets are valid as long as
 * the ZRtp object is active. To use these data after the ZRtp object's
 * lifetime you may copy the data into a save place. The destructor
 * of ZRtp clears the data.
 */
typedef struct c_srtpSecrets
{
    const uint8_t* keyInitiator;
    int32_t initKeyLen;
    const uint8_t* saltInitiator;
    int32_t initSaltLen;
    const uint8_t* keyResponder;
    int32_t respKeyLen;
    const uint8_t* saltResponder;
    int32_t respSaltLen;
    int32_t srtpAuthTagLen;
    char* sas;
    int32_t  role;
} C_SrtpSecret_t;

/*
 * Keep the following defines in sync with enum EnableSecurity in ZrtpCallback.h
 */
#define ForReceiver 1
#define ForSender   2

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct ZRtp ZRtp;
    typedef struct ZrtpCallbackWrapper ZrtpCallbackWrapper;

    typedef struct zrtpContext
    {
        ZRtp* zrtpEngine;
        ZrtpCallbackWrapper* zrtpCallback;
    } ZrtpContext;

    /**
    * This structure defines the callback functions required by GNU ZRTP.
    *
    * The RTP stack specific part must implement the callback methods.
    * The generic part of GNU ZRTP uses these mehtods
    * to communicate with the specific part, for example to send data
    * via the RTP/SRTP stack, to set timers and cancel timer and so on.
    *
    * The generiy part of GNU ZRTP needs only a few callback methods to
    * be implemented by the specific part.
    *
    * @author Werner Dittmann <Werner.Dittmann@t-online.de>
    */

    typedef struct C_Callbacks
    {
        /*
        * The following methods define the GNU ZRTP callback interface.
        * For detailed documentation refer to file ZrtpCallback.h, each C
        * method has "zrtp_" prepended to the C++ name.
        */
        int32_t (*zrtp_sendDataZRTP) ( const uint8_t* data, int32_t length ) ;
        int32_t (*zrtp_activateTimer) ( int32_t time ) ;
        int32_t (*zrtp_cancelTimer)() ;
        void (*zrtp_sendInfo) ( int32_t severity, int32_t subCode ) ;
        int32_t (*zrtp_srtpSecretsReady) ( C_SrtpSecret_t* secrets, int32_t part ) ;
        void (*zrtp_srtpSecretsOff) ( int32_t part ) ;
        void (*zrtp_rtpSecretsOn) ( char* c, char* s, int32_t verified ) ;
        void (*zrtp_handleGoClear)() ;
        void (*zrtp_zrtpNegotiationFailed) ( int32_t severity, int32_t subCode ) ;
        void (*zrtp_zrtpNotSuppOther)() ;
        void (*zrtp_synchEnter)() ;
        void (*zrtp_synchLeave)() ;
        void (*zrtp_zrtpAskEnrollment) ( char* info ) ;
        void (*zrtp_zrtpInformEnrollment) ( char* info ) ;
        void (*zrtp_signSAS)(char* sas) ;
        int32_t (*zrtp_checkSASSignature) ( char* sas ) ;
    } C_Callbacks;

    /**
     * Application callback methods.
     *
     * The RTP stack specific part of GNU ZRTP uses these callback methods
     * to report ZRTP events to the application. Thus the application that
     * instantiates the RTP stack shall implement these methods and show these
     * inforemation to the user.
     *
     * <b>CAVEAT</b><br/>
     * All user callback methods run in the context of the RTP thread. Thus
     * it is of paramount importance to keep the execution time of the methods
     * as short as possible.
     *
     * @author Werner Dittmann <Werner.Dittmann@t-online.de>
     */

    typedef struct C_UserCallbacks
    {
        /*
        * The following methods define the GNU ZRTP user callback interface.
        * For detailed documentation refer to file ZrtpUserCallback.h, each C
        * method has "zrtp_" prepended to the C++ name.
        */
        void (*zrtp_secureOn)(char* cipher);
        void (*zrtp_secureOff)();
        void (*zrtp_showSAS)(char* sas, int32_t verified);
        void (*zrtp_confirmGoClear)();
        void (*zrtp_showMessage)(int32_t sev, int32_t subCode);
        void (*zrtp_zrtpNegotiationFailed)(int32_t severity, int32_t subCode);
        void (*zrtp_zrtpNotSuppOther)();
        void (*zrtp_zrtpAskEnrollment)(char* info);
        void (*zrtp_zrtpInformEnrollment)(char* info);
        void (*zrtp_signSAS)(char* sas);
        int32_t (*zrtp_checkSASSignature)(char* sas);
    } C_UserCallbacks;

    ZrtpContext* zrtp_CreateWrapper (C_Callbacks *cb, char* id,
                                      void* config, char* zidFilename );
    void zrtp_DestroyWrapper ( ZrtpContext* zrtpContext );
    
    /**
     * Kick off the ZRTP protocol engine.
     *
     * This method calls the ZrtpStateClass#evInitial() state of the state
     * engine. After this call we are able to process ZRTP packets
     * from our peer and to process them.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_startZrtpEngine(ZrtpContext* zrtpContext);

    /**
     * Stop ZRTP security.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_stopZrtp(ZrtpContext* zrtpContext);

    /**
     * Process RTP extension header.
     *
     * This method expects to get a pointer to the extension header of
     * a RTP packet. The method checks if this is really a ZRTP
     * packet. If this check fails the method returns 0 (false) in
     * case this is not a ZRTP packet. We return a 1 if we processed
     * the ZRTP extension header and the caller may process RTP data
     * after the extension header as usual.  The method return -1 the
     * call shall dismiss the packet and shall not forward it to
     * further RTP processing.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param extHeader
     *    A pointer to the first byte of the extension header. Refer to
     *    RFC3550.
     * @param peerSSRC
     *    The peer's SSRC.
     * @return
     *    Code indicating further packet handling, see description above.
     */
    void zrtp_processZrtpMessage(ZrtpContext* zrtpContext, uint8_t *extHeader, uint32_t peerSSRC);

    /**
     * Process a timeout event.
     *
     * We got a timeout from the timeout provider. Forward it to the
     * protocol state engine.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_processTimeout(ZrtpContext* zrtpContext);

    /**
     * Check for and handle GoClear ZRTP packet header.
     *
     * This method checks if this is a GoClear packet. If not, just return
     * false. Otherwise handle it according to the specification.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param extHeader
     *    A pointer to the first byte of the extension header. Refer to
     *    RFC3550.
     * @return
     *    False if not a GoClear, true otherwise.
     *
    int32_t zrtp_handleGoClear(ZrtpContext* zrtpContext, uint8_t *extHeader);
*/
    /**
     * Set the auxilliary secret.
     *
     * Use this method to set the auxilliary secret data. Refer to ZRTP
     * specification, chapter 4.3 ff
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param data
     *     Points to the secret data.
     * @param length
     *     Length of the auxilliary secrect in bytes
     */
    void zrtp_setAuxSecret(ZrtpContext* zrtpContext, uint8_t* data, int32_t length);

    /**
     * Set the PBX secret.
     *
     * Use this method to set the PBX secret data. Refer to ZRTP
     * specification, chapter 4.3 ff and 7.3
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param data
     *     Points to the other PBX data.
     * @param length
     *     The length in bytes of the data.
     */
    void zrtp_setPbxSecret(ZrtpContext* zrtpContext, uint8_t* data, int32_t length);

    /**
     * Check current state of the ZRTP state engine
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param state
     *    The state to check.
     * @return
     *    Returns true id ZRTP engine is in the given state, false otherwise.
     */
    int32_t zrtp_inState(ZrtpContext* zrtpContext, int32_t state);

    /**
     * Set SAS as verified.
     *
     * Call this method if the user confirmed (verfied) the SAS. ZRTP
     * remembers this together with the retained secrets data.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_SASVerified(ZrtpContext* zrtpContext);

    /**
     * Reset the SAS verfied flag for the current active user's retained secrets.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_resetSASVerified(ZrtpContext* zrtpContext);

    /**
     * Get the ZRTP Hello Hash data.
     *
     * Use this method to get the ZRTP Hello Hash data. The method
     * returns the data as a string containing the ZRTP protocol version and
     * hex-digits. Refer to ZRTP specification, chapter 8.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return
     *    a pointer to a C-string that contains the Hello hash value as
     *    hex-digits. The hello hash is available immediately after class
     *    instantiation. The call must use free() if it does not use the
     *    hello hash C-string anymore.
     */
    char* zrtp_getHelloHash(ZrtpContext* zrtpContext);

    /**
     * Get Multi-stream parameters.
     *
     * Use this method to get the Multi-stream parameters that were computed
     * during the ZRTP handshake. An application may use these parameters to
     * enable multi-stream processing for an associated SRTP session.
     *
     * The application must not modify the contents of returned char array, it
     * is opaque data. The application may hand over this string to a new ZRTP
     * instance to enable multi-stream processing for this new session.
     *
     * Refer to chapter 4.4.2 in the ZRTP specification for further details
     * and restriction how and when to use multi-stream mode.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param length
     *    Pointer to an integer that receives the length of the char array
     * @return
     *    a char array that contains the multi-stream parameters.
     *    If ZRTP was not started or ZRTP is not yet in secure state the method
     *    returns NULL and a length of 0.
     */
    char* zrtp_getMultiStrParams(ZrtpContext* zrtpContext, int32_t *length);

    /**
     * Set Multi-stream parameters.
     *
     * Use this method to set the parameters required to enable Multi-stream
     * processing of ZRTP. The multi-stream parameters must be set before the
     * application starts the ZRTP protocol engine.
     *
     * Refer to chapter 4.4.2 in the ZRTP specification for further details
     * of multi-stream mode.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param length
     *    The integer that contains the length of the char array
     * @param parameters
     *     A char array that contains the multi-stream parameters that this
     *     new ZRTP instanace shall use. See also
     *     <code>getMultiStrParams()</code>
     */
    void zrtp_setMultiStrParams(ZrtpContext* zrtpContext, char* parameters, int32_t length);

    /**
     * Check if this ZRTP session is a Multi-stream session.
     *
     * Use this method to check if this ZRTP instance uses multi-stream.
     * Refer to chapters 4.2 and 4.4.2 in the ZRTP.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return
     *     True if multi-stream is used, false otherwise.
     */
    int32_t zrtp_isMultiStream(ZrtpContext* zrtpContext);

    /**
     * Check if the other ZRTP client supports Multi-stream.
     *
     * Use this method to check if the other ZRTP client supports
     * Multi-stream mode.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return
     *     True if multi-stream is available, false otherwise.
     */
    int32_t zrtp_isMultiStreamAvailable(ZrtpContext* zrtpContext);

    /**
     * Accept a PBX enrollment request.
     *
     * If a PBX service asks to enroll the PBX trusted MitM key and the user
     * accepts this request, for example by pressing an OK button, the client
     * application shall call this method and set the parameter
     * <code>accepted</code> to true. If the user does not accept the request
     * set the parameter to false.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param accepted
     *     True if the enrollment request is accepted, false otherwise.
     */
    void zrtp_acceptEnrollment(ZrtpContext* zrtpContext, int32_t accepted);

    /**
     * Enable PBX enrollment
     *
     * The application calls this method to allow or disallow PBX enrollment.
     * If the applications allows PBX enrollment then the ZRTP implementation
     * honors the PBX enrollment flag in Confirm packets. Refer to chapter 7.3
     * for further details of PBX enrollment.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param yesNo
     *    If set to true then ZRTP honors the PBX enrollment flag in Commit
     *    packets and calls the appropriate user callback methods. If
     *    the parameter is set to false ZRTP ignores the PBX enrollment flags.
     */
    void zrtp_setPBXEnrollment(ZrtpContext* zrtpContext, int32_t yesNo);

    /**
     * Set signature data
     *
     * This functions stores signature data and transmitts it during ZRTP
     * processing to the other party as part of the Confirm packets. Refer to
     * chapters 5.7 and 7.2.
     *
     * The signature data must be set before ZRTP the application calls
     * <code>start()</code>.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param data
     *    The signature data including the signature type block. The method
     *    copies this data into the Confirm packet at signature type block.
     * @param length
     *    The length of the signature data in bytes. This length must be
     *    multiple of 4.
     * @return
     *    True if the method stored the data, false otherwise.
     */
    int32_t zrtp_setSignatureData(ZrtpContext* zrtpContext, uint8_t* data, int32_t length);

    /**
     * Get signature data
     *
     * This functions returns signature data that was receivied during ZRTP
     * processing. Refer to chapters 5.7 and 7.2.
     *
     * The signature data can be retrieved after ZRTP enters secure state.
     * <code>start()</code>.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param data
     *    Pointer to a data buffer. This buffer must be large enough to
     *    hold the signature data. Refer to <code>getSignatureLength()</code>
     *    to get the length of the received signature data.
     * @return
     *    Number of bytes copied into the data buffer
     */
    int32_t zrtp_getSignatureData(ZrtpContext* zrtpContext, uint8_t* data);

    /**
     * Get length of signature data
     *
     * This functions returns the length of signature data that was receivied
     * during ZRTP processing. Refer to chapters 5.7 and 7.2.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return
     *    Length in bytes of the received signature data. The method returns
     *    zero if no signature data avilable.
     */
    int32_t zrtp_getSignatureLength(ZrtpContext* zrtpContext);

    /**
     * Emulate a Conf2Ack packet.
     *
     * This method emulates a Conf2Ack packet. According to ZRTP specification
     * the first valid SRTP packet that the Initiator receives must switch
     * on secure mode. Refer to chapter 4 in the specificaton
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_conf2AckSecure(ZrtpContext* zrtpContext);

    /**
     * Get other party's ZID (ZRTP Identifier) data
     *
     * This functions returns the other party's ZID that was receivied
     * during ZRTP processing.
     *
     * The ZID data can be retrieved after ZRTP receive the first Hello
     * packet from the other party. The application may call this method
     * for example during SAS processing in showSAS(...) user callback
     * method.
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param data
     *    Pointer to a data buffer. This buffer must have a size of
     *    at least 12 bytes (96 bit) (ZRTP Identifier, see chap. 4.9)
     * @return
     *    Number of bytes copied into the data buffer - must be equivalent
     *    to 96 bit, usually 12 bytes.
     */
    int32_t zrtp_getZid(ZrtpContext* zrtpContext, uint8_t* data);

#ifdef __cplusplus
}
#endif

#endif
