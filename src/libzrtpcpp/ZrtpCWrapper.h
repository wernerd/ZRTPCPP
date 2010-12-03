/*
    This file defines the GNU ZRTP C-to-C++ wrapper.
    Copyright (C) 2010  Werner Dittmann

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

#define CRC_SIZE  4             /*!< Size of CRC code of a ZRTP packet */
#define ZRTP_MAGIC 0x5a525450   /*!< The magic code that identifies a ZRTP packet */
#define MAX_ZRTP_SIZE 3072

/*
 * IMPORTANT: keep the following enums in synch with ZrtpCodes. We copy them here
 * to avoid any C++ header includes and defines. The protocol states are located
 * ZrtpStateClass.h .
 */
/**
 * This enum defines the information message severity.
 *
 * The ZRTP implementation issues information messages to inform the user
 * about ongoing processing, unusual behavior, or alerts in case of severe
 * problems. Each main severity code a number of sub-codes exist that
 * specify the exact nature of the problem.
 *
 * An application gets message severity codes and the associated sub-codes
 * via the ZrtpUserCallback#showMessage method.
 *
 * The severity levels and their meaning are:
 *
 * <dl>
 * <dt>Info</dt> <dd>keeps the user informed about ongoing processing and
 *     security setup. The enumeration InfoCodes defines the subcodes.
 * </dd>
 * <dt>Warning</dt> <dd>is an information about some security issues, e.g. if
 *     an AES 256 encryption is request but only DH 3072 as public key scheme
 *     is supported. ZRTP will establish a secure session (SRTP). The
 *     enumeration WarningCodes defines the sub-codes.
 * </dd>
 * <dt>Severe</dt> <dd>is used if an error occured during ZRTP protocol usage.
 *     In case of <em>Severe</em> ZRTP will <b>not</b> establish a secure session.
 *     The enumeration SevereCodes defines the sub-codes.
 * </dd>
 * <dt>Zrtp</dt> <dd>shows a ZRTP security problem. Refer to the enumeration
 *     ZrtpErrorCodes for sub-codes. GNU ZRTP of course will <b>not</b>
 *     establish a secure session.
 * </dd>
 * </dl>
 *
 */
enum zrtp_MessageSeverity {
    zrtp_Info = 1,
    zrtp_Warning,
    zrtp_Severe,
    zrtp_ZrtpError
};

/**
 * Sub-codes for Info
 */
enum zrtp_InfoCodes {
    zrtp_InfoHelloReceived = 1,          /*!< Hello received, preparing a Commit */
    zrtp_InfoCommitDHGenerated,          /*!< Commit: Generated a public DH key */
    zrtp_InfoRespCommitReceived,         /*!< Responder: Commit received, preparing DHPart1 */
    zrtp_InfoDH1DHGenerated,             /*!< DH1Part: Generated a public DH key */
    zrtp_InfoInitDH1Received,            /*!< Initiator: DHPart1 received, preparing DHPart2 */
    zrtp_InfoRespDH2Received,            /*!< Responder: DHPart2 received, preparing Confirm1 */
    zrtp_InfoInitConf1Received,          /*!< Initiator: Confirm1 received, preparing Confirm2 */
    zrtp_InfoRespConf2Received,          /*!< Responder: Confirm2 received, preparing Conf2Ack */
    zrtp_InfoRSMatchFound,               /*!< At least one retained secrets matches - security OK */
    zrtp_InfoSecureStateOn,              /*!< Entered secure state */
    zrtp_InfoSecureStateOff              /*!< No more security for this session */
};

/**
 * Sub-codes for Warning
 */
enum zrtp_WarningCodes {
    zrtp_WarningDHAESmismatch = 1,       /*!< Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096 */
    zrtp_WarningGoClearReceived,         /*!< Received a GoClear message */
    zrtp_WarningDHShort,                 /*!< Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096 */
    zrtp_WarningNoRSMatch,               /*!< No retained shared secrets available - must verify SAS */
    zrtp_WarningCRCmismatch,             /*!< Internal ZRTP packet checksum mismatch - packet dropped */
    zrtp_WarningSRTPauthError,           /*!< Dropping packet because SRTP authentication failed! */
    zrtp_WarningSRTPreplayError,         /*!< Dropping packet because SRTP replay check failed! */
    zrtp_WarningNoExpectedRSMatch        /*!< Valid retained shared secrets availabe but no matches found - must verify SAS */
};

/**
 * Sub-codes for Severe
 */
enum zrtp_SevereCodes {
    zrtp_SevereHelloHMACFailed = 1,      /*!< Hash HMAC check of Hello failed! */
    zrtp_SevereCommitHMACFailed,         /*!< Hash HMAC check of Commit failed! */
    zrtp_SevereDH1HMACFailed,            /*!< Hash HMAC check of DHPart1 failed! */
    zrtp_SevereDH2HMACFailed,            /*!< Hash HMAC check of DHPart2 failed! */
    zrtp_SevereCannotSend,               /*!< Cannot send data - connection or peer down? */
    zrtp_SevereProtocolError,            /*!< Internal protocol error occured! */
    zrtp_SevereNoTimer,                  /*!< Cannot start a timer - internal resources exhausted? */
    zrtp_SevereTooMuchRetries            /*!< Too much retries during ZRTP negotiation - connection or peer down? */
};

/**
  * Error codes according to the ZRTP specification chapter 6.9
  *
  * GNU ZRTP uses these error codes in two ways: to fill the appropriate
  * field ing the ZRTP Error packet and as sub-code in
  * ZrtpUserCallback#showMessage(). GNU ZRTP uses thes error codes also
  * to report received Error packts, in this case the sub-codes are their
  * negative values.
  *
  * The enumeration member comments are copied from the ZRTP specification.
  */
enum zrtp_ZrtpErrorCodes {
    zrtp_MalformedPacket =   0x10,    /*!< Malformed packet (CRC OK, but wrong structure) */
    zrtp_CriticalSWError =   0x20,    /*!< Critical software error */
    zrtp_UnsuppZRTPVersion = 0x30,    /*!< Unsupported ZRTP version */
    zrtp_HelloCompMismatch = 0x40,    /*!< Hello components mismatch */
    zrtp_UnsuppHashType =    0x51,    /*!< Hash type not supported */
    zrtp_UnsuppCiphertype =  0x52,    /*!< Cipher type not supported */
    zrtp_UnsuppPKExchange =  0x53,    /*!< Public key exchange not supported */
    zrtp_UnsuppSRTPAuthTag = 0x54,    /*!< SRTP auth. tag not supported */
    zrtp_UnsuppSASScheme =   0x55,    /*!< SAS scheme not supported */
    zrtp_NoSharedSecret =    0x56,    /*!< No shared secret available, DH mode required */
    zrtp_DHErrorWrongPV =    0x61,    /*!< DH Error: bad pvi or pvr ( == 1, 0, or p-1) */
    zrtp_DHErrorWrongHVI =   0x62,    /*!< DH Error: hvi != hashed data */
    zrtp_SASuntrustedMiTM =  0x63,    /*!< Received relayed SAS from untrusted MiTM */
    zrtp_ConfirmHMACWrong =  0x70,    /*!< Auth. Error: Bad Confirm pkt HMAC */
    zrtp_NonceReused =       0x80,    /*!< Nonce reuse */
    zrtp_EqualZIDHello =     0x90,    /*!< Equal ZIDs in Hello */
    zrtp_GoCleatNotAllowed = 0x100,   /*!< GoClear packet received, but not allowed */
    zrtp_IgnorePacket =      0x7fffffff /*!< Internal state, not reported */
};

/* The ZRTP protocol states */
enum zrtpStates {
    Initial,
    Detect,
    AckDetected,
    AckSent,
    WaitCommit,
    CommitSent,
    WaitDHPart2,
    WaitConfirm1,
    WaitConfirm2,
    WaitConfAck,
    WaitClearAck,
    SecureState,
    WaitErrorAck,
    numberOfStates
};

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
        void* userData;
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

    typedef struct zrtp_Callbacks
    {
        /*
        * The following methods define the GNU ZRTP callback interface.
        * For detailed documentation refer to file ZrtpCallback.h, each C
        * method has "zrtp_" prepended to the C++ name.
        */
        int32_t (*zrtp_sendDataZRTP) (ZrtpContext* ctx, const uint8_t* data, int32_t length ) ;
        int32_t (*zrtp_activateTimer) (ZrtpContext* ctx, int32_t time ) ;
        int32_t (*zrtp_cancelTimer)(ZrtpContext* ctx) ;
        void (*zrtp_sendInfo) (ZrtpContext* ctx, int32_t severity, int32_t subCode ) ;
        int32_t (*zrtp_srtpSecretsReady) (ZrtpContext* ctx, C_SrtpSecret_t* secrets, int32_t part ) ;
        void (*zrtp_srtpSecretsOff) (ZrtpContext* ctx, int32_t part ) ;
        void (*zrtp_rtpSecretsOn) (ZrtpContext* ctx, char* c, char* s, int32_t verified ) ;
        void (*zrtp_handleGoClear)(ZrtpContext* ctx) ;
        void (*zrtp_zrtpNegotiationFailed) (ZrtpContext* ctx, int32_t severity, int32_t subCode ) ;
        void (*zrtp_zrtpNotSuppOther)(ZrtpContext* ctx) ;
        void (*zrtp_synchEnter)(ZrtpContext* ctx) ;
        void (*zrtp_synchLeave)(ZrtpContext* ctx) ;
        void (*zrtp_zrtpAskEnrollment) (ZrtpContext* ctx, char* info ) ;
        void (*zrtp_zrtpInformEnrollment) (ZrtpContext* ctx, char* info ) ;
        void (*zrtp_signSAS)(ZrtpContext* ctx, char* sas) ;
        int32_t (*zrtp_checkSASSignature) (ZrtpContext* ctx, char* sas ) ;
    } zrtp_Callbacks;

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

    typedef struct zrtp_UserCallbacks
    {
        /*
        * The following methods define the GNU ZRTP user callback interface.
        * For detailed documentation refer to file ZrtpUserCallback.h, each C
        * method has "zrtp_" prepended to the C++ name.
        */
        void (*zrtp_secureOn)(void* data, char* cipher);
        void (*zrtp_secureOff)(void* data);
        void (*zrtp_showSAS)(void* data, char* sas, int32_t verified);
        void (*zrtp_confirmGoClear)(void* data);
        void (*zrtp_showMessage)(void* data, int32_t sev, int32_t subCode);
        void (*zrtp_zrtpNegotiationFailed)(void* data, int32_t severity, int32_t subCode);
        void (*zrtp_zrtpNotSuppOther)(void* data);
        void (*zrtp_zrtpAskEnrollment)(void* data, char* info);
        void (*zrtp_zrtpInformEnrollment)(void* data, char* info);
        void (*zrtp_signSAS)(void* data, char* sas);
        int32_t (*zrtp_checkSASSignature)(void* data, char* sas);
        
        void* userData;
    } zrtp_UserCallbacks;

    /**
     * Create the GNU ZRTP C wrapper.
     *
     * This wrapper implements the C interface to the C++ based GNU ZRTP.
     *
     * @param cb
     *     The callback structure that holds the addresses of the callback
     *     methods.
     * @param id
     *     A C string that holds the ZRTP client id, only the first 16 chars
     *     are used.
     * @param config
     *     Pointer to ZRTP config data - TDB - defines which encryption 
     *     algorithms to, which SHA etc.
     * @param zidFilename
     *     The name of the ZID file. This file holds some parameters and
     *     other data like additional shared secrets.
     * @param userData
     *     A pointer to user data. The wrapper just stores this pointer in
     *     the ZrtpContext and the application may use it for its purposes.
     * @returns 
    *      Pointer to the ZrtpContext
     */
    ZrtpContext* zrtp_CreateWrapper (zrtp_Callbacks *cb, char* id,
                                     void* config, const char* zidFilename,
                                     void* userData );

    void zrtp_DestroyWrapper (ZrtpContext* zrtpContext );

    /**
     * Computes the ZRTP checksum over a received ZRTP packet buffer and 
     * compares the result with received checksum.
     *
     * @param buffer
     *    Pointer to ZRTP packet buffer
     * @param length
     *    Length of the packet buffer excluding received CRC data
     * @param crc
     *    The received CRC data.
     * @returns
     *    True if CRC matches, false otherwise.
     */
    int32_t zrtp_CheckCksum(uint8_t* buffer, uint16_t length, uint32_t crc);
    
    /**
     * Computes the ZRTP checksum over a newly created  ZRTP packet buffer. 
     *
     * @param buffer
     *    Pointer to the created ZRTP packet buffer
     * @param length
     *    Length of the packet buffer
     * @returns
     *    The computed CRC.
     */
    uint32_t zrtp_GenerateCksum(uint8_t* buffer, uint16_t length);
    
    /**
     * Prepares the ZRTP checksum for appending to ZRTP packet. 
     * @param crc
     *    The computed CRC data.
     * @returns
     *    Prepared CRC data in host order
     */
    uint32_t zrtp_EndCksum(uint32_t crc);

    /**
     * Kick off the ZRTP protocol engine.
     *
     * This method calls the ZrtpStateClass#evInitial() state of the state
     * engine. After this call we are able to process ZRTP packets
     * from our peer and to process them.
     *
     * <b>NOTE: application shall never call this method directly but use the
     * appropriate method provided by the RTP implementation. </b>
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_startZrtpEngine(ZrtpContext* zrtpContext);

    /**
     * Stop ZRTP security.
     *
     * <b>NOTE: application shall never call this method directly but use the
     * appropriate method provided by the RTP implementation. </b>
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     */
    void zrtp_stopZrtpEngine(ZrtpContext* zrtpContext);

    /**
     * Process RTP extension header.
     *
     * This method expects to get a pointer to the message part of
     * a ZRTP packet.
     *
     * <b>NOTE: application shall never call this method directly. Only
     * the module that implements the RTP binding shall use this method</b>
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @param extHeader
     *    A pointer to the first byte of the ZRTP message part.
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
     * <b>NOTE: application shall never call this method directly. Only
     * the module that implements the RTP binding shall use this method</b>
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
     * <b>NOTE: application usually don't call this method. Only
     * the module that implements the RTP binding shall use this method</b>
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
     * <b>NOTE: An application may call this method if it needs this information.
     * Usually it is not necessary.</b>
     *
     * @param zrtpContext
     *    Pointer to the opaque ZrtpContext structure.
     * @return
     *    a pointer to a C-string that contains the Hello hash value as
     *    hex-digits. The hello hash is available immediately after
     *    @c zrtp_CreateWrapper .
     *    The caller must @c free() if it does not use the
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
     * <b>NOTE: application shall never call this method directly. Only
     * the module that implements the RTP binding shall use this method</b>
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
     *    to 12 bytes.
     */
    int32_t zrtp_getZid(ZrtpContext* zrtpContext, uint8_t* data);

#ifdef __cplusplus
}
#endif

#endif
