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

#ifndef _ZRTPQUEUE_H_
#define _ZRTPQUEUE_H_

#include <ccrtp/cqueue.h>
#include <ccrtp/rtppkt.h>
#include <libzrtpcpp/ZrtpCallback.h>
#include <libzrtpcpp/ZRtp.h>


class ZrtpUserCallback;

#ifdef  CCXX_NAMESPACES
namespace ost {
#endif

/** 
 * GNU ZRTP extension to GNU ccRTP.
 *
 * ZRTP was developed by Phil Zimmermann and provides functions to
 * negotiate keys and other necessary data to set-up Secure RTP
 * (SRTP). Refer to Phil's ZRTP specification at his <a
 * href="http://zfoneproject.com/">Zfone project</a> site to get more
 * detailed imformation about the capabilities of ZRTP.
 * 
 * <b>Short overview of the ZRTP implementation</b>
 *
 * ZRTP is a specific protocol to negotiate encryption algorithms and
 * the required key material. ZRTP uses a RTP session to exchange its
 * protocol messages.
 *
 * The ZRTP implementation splits into two parts:
 * <ul>
 * <li>The ZRTP core implementation consisting of the ZRTP protocol
 *     engine, the ZRTP protocol message, and the ZRTP methods to
 *     compute the data to set-up SRTP. This part of the ZRTP
 *     implementation is independent of a RTP/SRTP implementation.
 * </li>
 * <li>The second part of the implementation is specific <em>glue</em>
 *     code the binds the independent part to the actual RTP/SRTP
 *     implementation and other operatind system specific services
 *     such as timers.
 * </li>
 * </ul>
 *
 * The independent part of the ZRTP implementation defines a callback
 * interface class (refer to ZrtpCallback) that the glue code must
 * implement. The independent part uses the fucntions of the callback
 * to communication with the actual RTP/SRTP implementation, to access
 * timers and semaphores.
 *
 * ZrtpQueue implements the ZrtpCallback interface and extends the GNU
 * ccRTP AVPQueue class to provide access to the underlying RTP/SRTP
 * send and receive queues. Applications use the ZRTP specific methods
 * of ZrtpQueue to control ZRTP, for example enable or disable ZRTP
 * processing or geting ZRTP status information.
 *
 * GNU ZRTP provides a ZrtpUserCallback class that an application may
 * extend and register with ZrtpQueue. ZRTP uses the callback methods
 * to inform the application of events during ZRTP processing. The
 * application may display this information or act otherwise. The
 * following figure depicts the relationships between ZrtpQueue,
 * AVPQueue, the generic ZRTP protocol implementation, and an
 * application.

 * <pre>
 *
 *                          +----------+
 *                          |          |
 *                          | AVPQueue |
 *                          |          |
 *                          +----------+
 *                               ^
 *                               |
 * +----------------+      +-----+------+
 * |                |      |            |      +-----------------+
 * |  Application   | uses |  ZrtpQueue | uses |                 |
 * |    provides    +------+    impl.   +------+  generic ZRTP   |
 * |ZrtpUserCallback|      |ZrtpCallback|      |    protocol     |
 * |                |      |            |      | implementation  |
 * +----------------+      +------------+      |                 |
 *                                             |                 |
 *                                             +-----------------+
 *</pre>
 *
 * Because ZrtpQueue extends AVPQueue all public methods defined by
 * AVPQueue are also available. ZrtpQueue overwrites some of the
 * public methods of AVPQueue to implement ZRTP specific code. 
 *
 * Similar to GNU ccRTP the ZRTP implementation provides typedef to
 * simplify usage of the ZrtpQueue in applications. The following
 * paragraphs show some small examples on how to use ZrtpQueue and
 * what are the differences to a normal GNU ccRTP RTPSession.
 *
 * ZrtpQueue implements code that is specific to the GNU ccRTP
 * implementation. ZrtpQueue also implements specific code to provide
 * semaphores and timeout handling. Both, the semaphores and the
 * timeout handling, use the GNU Common C++ library. Refer to the <a
 * href="http://www.gnutelephony.org/index.php/GNU_Common_C%2B%2B">GNU
 * Common C++</a> web site.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpQueue : public AVPQueue, public ZrtpCallback {

 public:

     /**
      * Initialize the ZrtpQueue.
      *
      * Before an application can use ZRTP it has to initialize the
      * ZRTP implementation. This method initializes the timeout
      * thread and a specific file that contains ZRTP specific
      * information such as the retained shared secrets.
      *
      * If one application requires several ZRTP sessions all session
      * use the same timeout thread and use the same ZID
      * file. Therefore an application does not need to do any
      * synchronisation regading ZID files or timeouts. This is
      * managed by the ZRTP implementation.
      *
      * The current implementation of ZrtpQueue does not support
      * different ZID files for one application instance. This
      * restriction may be removed in later versions. 
      *
      * The application may specify its own ZID file name. If no ZID
      * file name is specified it defaults to
      * <code>$HOME/.GNUccRTP.zid</code> if the
      * <code>HOME</code>environment variable is set. If it is not set
      * the current directory is used.
      *
      * If the method could set up the timeout thread and open the ZID
      * file then it enables ZRTP processing and returns.
      *
      * @param zidFilename
      *     The name of the ZID file, can be a relative or absolut 
      *     filename.
      * @return 
      *     1 on success, ZRTP processing enabled, -1 on failure,
      *     ZRTP processing disabled.
      *
      */
    int32_t initialize(const char *zidFilename);

    /*
     * Applications use the following methods to control ZRTP, for example
     * to enable ZRTP, set flags etc.
     */

    /**
     * Enable or diable ZRTP processing.
     *
     * Call this method to enable or disable ZRTP processing after
     * calling <code>initialize()</code>. This can be done before
     * using a RTP session or at any time during a RTP session.
     *
     * Existing SRTP sessions or currently active ZRTP processing will
     * not be stopped or disconnected.
     *
     * If the application enables ZRTP then:
     * <ul>
     * <li>ZrtpQueue starts to send ZRTP Hello packets after at least
     * one RTP packet was sent and received on the associated RTP
     * session. Thus if an application enables ZRTP and ZrtpQueue
     * detects traffic on the RTP session then ZrtpQueue automatically
     * starts the ZRTP protocol. This automatic start is convenient
     * for applications that negotiate RTP parameters and set up RTP
     * sessions but the actual RTP traffic starts some time later.
     * </li>
     * <li>ZrtpQueue analyses incoming packets if they are ZRTP
     * messages and ZRTP is started, either via automatic start (see
     * above) or explicitly via startZrtp() then ZrtpQueue
     * forwards these packets to the ZRTP protocol engine.
     * </ul>
     *
     * @param onOff
     *     If set to true enable ZRTP, false to disable ZRTP
     */
    void setEnableZrtp(bool onOff)   {
        enableZrtp = onOff;
    }

    /**
     * Return the state of ZRTP enable state.
     *
     * @return <code>true</code> if ZRTP processing is enabled,
     * <code>false</code> otherwise.
     */
    bool isEnableZrtp() {
        return enableZrtp;
    }
    /**
     * Set SAS as verified.
     *
     * The application may call this method if the user confirmed
     * (verfied) the Short Authentication String (SAS) with the peer.
     *
     * ZRTP calls ZrtpUserCallback#showSAS after it computed the SAS
     * and the application registered a user callback class. The
     * application should display the SAS and provide a mechanism at
     * the user interface that enables the user to confirm the SAS.
     *
     * ZRTP remembers the SAS confirmation status together with the
     * retained secrets data. If both parties confirmed the SAS then
     * ZRTP informs the application about this status on the next ZRTP
     * session.
     *
     * For more detailed information regarding SAS please refer to the
     * ZRTP specification, chapter 8.
     */
    void SASVerified() {
        if (zrtpEngine != NULL)
            zrtpEngine->SASVerified();
    }

    /**
     * Reset the SAS verfied flag for the current user's retained secrets.
     *
     */
    void resetSASVerified() {
        if (zrtpEngine != NULL)
            zrtpEngine->resetSASVerified();
    }

    /**
     * Confirm a go clear request.
     *
     * Call this method if the user confirmed a go clear (secure mode off).
     */
    void goClearOk()    {  }

    /**
     * Request to switch off secure mode.
     *
     * Call this method is the user itself wants to switch off secure
     * mode (go clear). After sending the "go clear" request to the peer
     * ZRTP immediatly switch off SRTP processing. Every RTP data is sent
     * in clear after the go clear request.
     */
    void requestGoClear()  { }

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
    void setSigsSecret(uint8* data)  {
        if (zrtpEngine != NULL)
            zrtpEngine->setSigsSecret(data);
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
    void setSrtpsSecret(uint8* data)  {
        if (zrtpEngine != NULL)
            zrtpEngine->setSrtpsSecret(data);
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
    void setOtherSecret(uint8* data, int32 length)  {
        if (zrtpEngine != NULL)
            zrtpEngine->setOtherSecret(data, length);
    }

    /**
     * Set the application's callback class.
     *
     * The destructor of ZrtpQueue also destorys the user callback
     * class if it was set.
     *
     * @param ucb
     *     Implementation of the application's ZrtpUserCallback class
     */
    void setUserCallback(ZrtpUserCallback* ucb) {
        zrtpUserCallback = ucb;
    }

    /**
     * Set the client ID for ZRTP Hello message.
     *
     * The GNU ccRTP client may set its id to identify itself in the
     * ZRTP Hello message. The maximum length is 16 characters. A
     * shorter id string is possible, it will be filled with blanks. A
     * longer id string will be truncated to 16 characters. The
     * standard client id is <code>GNU ccRTP ZRTP </code>.
     *
     * Setting the client's id must be done before calling
     * initialize() or starting the ZRTP protocol with startZrtp() .
     *
     * @param id
     *     The client's id string
     */
    void setClientId(std::string id) {
        clientIdString = id;
    }

    /**
     * Get the ZRTP Hello Hash data.
     *
     * Use this method to get the ZRTP Hello Hash data. The method 
     * returns the data as a string containing hex-digits. Refer to ZRTP
     * specification, chapter 9.1.
     *
     * @return
     *    a std:string containing the Hello hash value as hex-digits. The
     *    hello hash is available immediatly after starting the ZrtpQueue.
     *    If ZRTP was not started or ZRTP the method returns an empty string.
     */
    std::string getHelloHash()  {
        if (zrtpEngine != NULL)
            return zrtpEngine->getHelloHash();
        else
            return std::string();
    }

    /**
     * Get the ZRTP SAS data.
     *
     * Use this method to get the ZRTP SAS data formatted as string
     * and ready to use in the SDP as defined in the ZRTP
     * specification, chapter 9.4. The format of this SAS string is
     * different from the SAS string sent to the application via
     * ZrtpUserCallback#showSAS.
     *
     * @return a std:string containing the SAS and the SAS hash,
     *    formatted as specified in chapter 9.4. If ZRTP was not
     *    started or ZRTP is not yet in secure state the method
     *    returns an empty string.
     */
    std::string getSasData()  {
        if (zrtpEngine != NULL)
            return zrtpEngine->getSasData();
        else
            return std::string();
    }

    /**
     * Get Multi-stream parameters.
     *
     * Use this method to get the Multi-stream that were computed during
     * the ZRTP handshake. An application may use these parameters to
     * enable multi-stream processing for an associated SRTP session.
     *
     * Refer to chapter 5.4.2 in the ZRTP specification for further details
     * and restriction how and when to use multi-stream mode.
     *
     * @return
     *    a string that contains the multi-stream parameters. The application
     *    must not modify the contents of this string, it is opaque data. The
     *    application may hand over this string to a new ZrtpQueue instance
     *    to enable multi-stream processing for this ZrtpQueue. If ZRTP was 
     *    not started or ZRTP is not yet in secure state the method returns an
     *    empty string.
     */
    std::string getMultiStrParams()  {
        if (zrtpEngine != NULL)
            return zrtpEngine->getMultiStrParams();
        else
            return std::string();
    }

    /**
     * Set Multi-stream parameters.
     *
     * Use this method to set the parameters required to enable Multi-stream
     * processing of ZRTP. The multi-stream parameters must be set before the
     * application starts the ZRTP protocol engine.
     *
     * Refer to chapter 5.4.2 in the ZRTP specification for further details
     * of multi-stream mode.
     *
     * @param parameters
     *     A string that contains the multi-stream parameters that this
     *     new ZrtpQueue instanace shall use. See also 
     *     <code>getMultiStrParams()</code>
     */
    void setMultiStrParams(std::string parameters)  {
        if (zrtpEngine != NULL)
            zrtpEngine->setMultiStrParams(parameters);
    }

    /**
     * Check if this ZRTP use Multi-stream.
     *
     * Use this method to check if this ZRTP instance uses multi-stream. Even
     * if the application provided multi-stram parameters it may happen that
     * full DH mode was used. Refer to chapters 5.2 and 5.4.2 in the ZRTP #
     * when this may happen.
     *
     * @return
     *     True if multi-stream is used, false otherwise.
     */
    bool isMultiStream()  {
        if (zrtpEngine != NULL)
            return zrtpEngine->isMultiStream();
    }

    /**
     * Accept a PBX enrollment request.
     *
     * If a PBX service asks to enroll the MiTM key and the user accepts this
     * requtes, for example by pressing an OK button, the client application
     * shall call this method and set the parameter <code>accepted</code> to
     * true. If the user does not accept the request set the parameter to 
     * false.
     *
     * @param accepted
     *     True if the enrollment request is accepted, false otherwise.
     */
    void acceptEnrollment(bool accepted) {
        if (zrtpEngine != NULL)
            zrtpEngine->acceptEnrollment(accepted);
    }

    /**
     * Set signature data
     *
     * This functions stores signature data and transmitts it during ZRTP
     * processing to the other party as part of the Confirm packets. Refer to 
     * chapters 6.7 and 8.2.
     *
     * The signature data must be set before ZRTP the application calls
     * <code>start()</code>.
     *
     * @param data
     *    The signature data including the signature type block. The method
     *    copies this data into the Confirm packet at signature type block.
     * @param length
     *    The length of the signature data in bytes. This length must be
     *    multiple of 4.
     * @return
     *    True if the method stored the data, false otherwise.
     */
    bool setSignatureData(uint8* data, int32 length) {
        if (zrtpEngine != NULL) 
            return zrtpEngine->setSignatureData(data, length);
    }

    /**
     * Get signature data
     *
     * This functions returns signature data that was receivied during ZRTP
     * processing. Refer to chapters 6.7 and 8.2.
     *
     * The signature data can be retrieved after ZRTP enters secure state.
     * <code>start()</code>.
     *
     * @param data
     *    Pointer to a data buffer. This buffer must be large enough to
     *    hold the signature data. Refer to <code>getSignatureLength()</code>
     *    to get the length of the received signature data.
     * @return
     *    Number of bytes copied into the data buffer
     */
    int32 getSignatureData(uint8* data) {
        if (zrtpEngine != NULL) 
            return zrtpEngine->getSignatureData(data);
    }

    /**
     * Get length of signature data
     *
     * This functions returns the length of signature data that was receivied 
     * during ZRTP processing. Refer to chapters 6.7 and 8.2.
     *
     * @return
     *    Length in bytes of the received signature data. The method returns
     *    zero if no signature data avilable.
     */
    int32 getSignatureLength() {
        if (zrtpEngine != NULL) 
            return zrtpEngine->getSignatureLength();
    }

    /**
     * Enable PBX enrollment
     *
     * The application calls this method to allow or disallow PBX enrollment.
     * If the applications allows PBX enrollment then the ZRTP implementation
     * honors the PBX enrollment flag in Confirm packets. Refer to chapter 8.3
     * for further details of PBX enrollment.
     *
     * @param yesNo
     *    If set to true then ZRTP honors the PBX enrollment flag in Commit
     *    packets and calls the appropriate user callback methods. If
     *    the parameter is set to false ZRTP ignores the PBX enrollment flags.
     */
    void setPBXEnrollment(bool yesNo) {
        if (zrtpEngine != NULL) 
            zrtpEngine->setPBXEnrollment(yesNo);
    }
   /**
     * Put data into the RTP output queue.
     *
     * This is used to create a data packet in the send queue.
     * Sometimes a "NULL" or empty packet will be used instead, and
     * these are known as "silent" packets.  "Silent" packets are
     * used simply to "push" the scheduler along more accurately
     * by giving the appearence that a next packet is waiting to
     * be sent and to provide a valid timestamp for that packet.
     *
     * This method overrides the same method in OutgoingDataQueue class.
     * During ZRTP processing it may be necessary to control the
     * flow of outgoing RTP payload packets (GoClear processing).
     *
     * @param stamp Timestamp for expected send time of packet.
     * @param data Value or NULL if special "silent" packet.
     * @param len May be 0 to indicate a default by payload type.
     **/
    void
    putData(uint32 stamp, const unsigned char* data = NULL, size_t len = 0);

    /**
     * Immediatly send a data packet.
     *
     * This is used to create a data packet and send it immediately.
     * Sometimes a "NULL" or empty packet will be used instead, and
     * these are known as "silent" packets.  "Silent" packets are
     * used simply to "push" the scheduler along more accurately
     * by giving the appearence that a next packet is waiting to
     * be sent and to provide a valid timestamp for that packet.
     *
     * This method overrides the same method in OutgoingDataQueue class.
     * During ZRTP processing it may be necessary to control the
     * flow of outgoing RTP payload packets (GoClear processing).
     *
     * @param stamp Timestamp immediate send time of packet.
     * @param data Value or NULL if special "silent" packet.
     * @param len May be 0 to indicate a default by payload type.
     **/
    void
    sendImmediate(uint32 stamp, const unsigned char* data = NULL, size_t len = 0);

    /**
     * Starts the ZRTP protocol engine.
     *
     * Applications may call this method to immediatly start the ZRTP protocol
     * engine any time after initializing ZRTP and setting optinal parameters,
     * for example client id or multi-stream parameters.
     *
     * If the application does not call this method but sucessfully initialized
     * the ZRTP engine using <code>initialize()</code> then ZRTP also starts
     * after the application sent and received RTP packets. An application can
     * disable this automatic, delayed start of the ZRTP engine using 
     * <code>setEnableZrtp(false)</code> before sending or receiving RTP
     * packets.
     *
     */
    void startZrtp();

    /**
     * Stops the ZRTP protocol engine and stops SRTP.
     *
     * Applications call this method to stop the ZRTP protocol engine and
     * SRTP processing.
     *
     */
    void stopZrtp();

    /**
     * This function is used by the service thread to process
     * the next incoming packet and place it in the receive list.
     *
     * This class overloads the function of IncomingDataQueue
     * implementation.
     *
     * @return number of payload bytes received,  <0 if error.
     */
    virtual size_t takeInDataPacket();

    /**
     * A hook that gets called if the decoding of an incoming SRTP was erroneous
     *
     * @param pkt
     *     The SRTP packet with error.
     * @param errorCode
     *     The error code: -1 - SRTP authentication failure, -2 - replay
     *     check failed
     * @return
     *     True: put the packet in incoming queue for further processing
     *     by the applications; false: dismiss packet. The default
     *     implementation returns false.
     */
    virtual bool
    onSRTPPacketError(IncomingRTPPkt& pkt, int32 errorCode);

    /**
     * Handle timeout event forwarded by the TimeoutProvider.
     *
     * Just call the ZRTP engine for further processing.
     */
    void handleTimeout(const std::string &c) {
        if (zrtpEngine != NULL) {
            zrtpEngine->processTimeout();
        }
    };

    /*
     * The following methods implement the internal callback interface.
     * Refer to ZrtpCallback.h
     */
    int32_t sendDataZRTP(const unsigned char* data, int32_t length);

    int32_t activateTimer(int32_t time);

    int32_t cancelTimer();

    void sendInfo(MessageSeverity severity, const char* msg);

    /**
     * Switch on the security for the defined part.
     *
     * Create an CryproContext with the negotiated ZRTP data and
     * register it with the respective part (sender or receiver) thus
     * replacing the current active context (usually an empty
     * context). This effectively enables SRTP.
     *
     * @param secrets
     *    The secret keys and salt negotiated by ZRTP
     * @param part
     *    An enum that defines wich direction to switch on: sender or receiver
     * @return
     *    Returns false if something went wrong during initialization of SRTP
     *    context, for example memory shortage.
     */
    bool srtpSecretsReady(SrtpSecret_t* secrets, EnableSecurity part);

    /**
     * Switch off the security for the defined part.
     *
     * Create an empty CryproContext and register it with the
     * repective part (sender or receiver) thus replacing the current
     * active context. This effectively disables SRTP.
     *
     * @param part
     *    An enum that defines wich direction to switch off: sender or receiver
     */
    void srtpSecretsOff(EnableSecurity part);

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
    void srtpSecretsOn(std::string c, std::string s, bool verified);

    /**
     * This method shall handle GoClear requests.
     *
     * According to the ZRTP specification the user must be informed about
     * this message because the ZRTP implementation switches off security
     * if it could authenticate the GoClear packet.
     *
     */
    void handleGoClear();

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
    void zrtpNegotiationFailed(MessageSeverity severity, const char* msg);

    /**
     * ZRTP calls this methof if the other side does not support ZRTP.
     *
     * If the other side does not answer the ZRTP <em>Hello</em> packets then
     * ZRTP calls this method,
     *
     */
    void zrtpNotSuppOther();

    /**
     * ZRTP calls these methods to enter or leave its synchronization mutex.
     */
    void synchEnter();
    void synchLeave();

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
    void zrtpAskEnrollment(std::string info);

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
    void zrtpInformEnrollment(std::string info);

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
    void signSAS(std::string sas);

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
    bool checkSASSignature(std::string sas);

    /*
     * End of ZrtpCallback functions.
     */

    protected:
        ZrtpQueue(uint32 size = RTPDataQueue::defaultMembersHashSize,
                  RTPApplication& app = defaultApplication());

        /**
         * Local SSRC is given instead of computed by the queue.
         */
        ZrtpQueue(uint32 ssrc, uint32 size =
                    RTPDataQueue::defaultMembersHashSize,
                    RTPApplication& app = defaultApplication());

        virtual ~ZrtpQueue();

    private:
        void init();
        size_t rtpDataPacket(IncomingRTPPkt* packet, int32 rtn, 
                             InetHostAddress network_address, 
                             tpport_t transport_port);

        ZRtp *zrtpEngine;
        ZrtpUserCallback* zrtpUserCallback;

        std::string clientIdString;

        bool enableZrtp;

        int32 secureParts;

        CryptoContext* recvCryptoContext;
        CryptoContext* senderCryptoContext;
        int16 senderZrtpSeqNo;
        ost::Mutex synchLock;	// Mutex for ZRTP (used by ZrtpStateClass)

};

class IncomingZRTPPkt : public IncomingRTPPkt {

    public:
    /**
     * Build a ZRTP packet object from a data buffer.
     *
     * @param block pointer to the buffer the whole packet is stored in.
     * @param len length of the whole packet, expressed in octets.
     *
     **/

    IncomingZRTPPkt(const unsigned char* block, size_t len);

    ~IncomingZRTPPkt()
    { }

    inline uint32
    getZrtpMagic() const
    { return ntohl(getHeader()->timestamp); }
};

class OutgoingZRTPPkt : public OutgoingRTPPkt {

    public:
    /**
     * Construct a new ZRTP packet to be sent.
     *
     * A new copy in memory (holding all this components
     * along with the fixed header) is created.
     *
     * @param hdrext whole header extension.
     * @param hdrextlen size of whole header extension, in octets.
     **/
    OutgoingZRTPPkt(const unsigned char* const hdrext, uint32 hdrextlen);
    ~OutgoingZRTPPkt()
    { }
};

#ifdef  CCXX_NAMESPACES
}
#endif

#endif
