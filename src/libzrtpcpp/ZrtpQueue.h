/*
  Copyright (C) 2006, 2007 Werner Dittmann

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

#ifndef _ZRTPQUEUE_H_
#define _ZRTPQUEUE_H_

#include <ccrtp/cqueue.h>
#include <ccrtp/rtppkt.h>
#include <libzrtpcpp/ZrtpCallback.h>
#include <libzrtpcpp/ZRtp.h>

/**
 * The bridge between the ZRTP implementation and GNU ccRTP.
 *
 * The ZRPT implementation is fairly independent from the underlying
 * RTP/SRTP implementation. This class implements specific
 * functions and interfaces that ZRTP uses to call functions of the
 * hosting RTP/SRTP environment. In this case the host is GNU ccRTP.
 *
 * <p/>
 *
 * As required by the ZRTP implementation this class implements
 * the ZrtpCallback interface.
 *
 * <p/>
 *
 * The <code>initialize</code> method stores the timeout provider and
 * reuses it for every instance.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class ZrtpUserCallback;

#ifdef  CCXX_NAMESPACES
namespace ost {
#endif

class ZrtpQueue : public AVPQueue, public ZrtpCallback {

 public:

     /**
      * Initialize the ZrtpQueue.
      *
      * Before a programm can use ZRTP it has to initialize ZRTP
      * processing. This method initializes the timeout thread and
      * the ZID file that contais the retained secrets.
      *
      * If an application requires several ZRTP sessions all session use
      * the same timeout thread and use the same ZID file. Therefore an
      * application does not need to do any synchronisation regading
      * ZID files or timeouts. This is managed by the ZRTP implementation.
      *
      * The application may specify its own ZID file name. If no ZID file name
      * is specified it defaults to <code>$HOME/.GNUccRTP.zid</code> if the
      * <code>HOME</code>environment variable is set. If it is not set the
      * current directory is used.
      *
      * @param zidFilename
      *     The name of the ZID file, can be a relative or absolut filename.
      * @return 1 on success, -1 on failure. In the latter case the method also
      *     sets <code>setEnableZrtp(false)</code>.
      *
      */
    int32_t initialize(const char *zidFilename);

    /*
     * The following methods implement the external interface to control
     * ZRTP behaviour.
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
    void setEnableZrtp(bool onOff)   {
        enableZrtp = onOff;
    }

    /**
     * Set SAS as verified.
     *
     * Call this method if the user confirmed (verfied) the SAS. ZRTP
     * remembers this together with the retained secrets data.
     */
    void SASVerified() {
        if (zrtpEngine != NULL)
            zrtpEngine->SASVerified();
    }

    /**
     * Reset the SAS verfied flag for the current active user's retained secrets.
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
     * Set the callback class for UI intercation.
     *
     * The destructior of ZrtpQueue also destorys the user callback
     * class if it was set.
     *
     * @param ucb
     *     Implementation of the ZrtpUserCallback interface class
     */
    void setUserCallback(ZrtpUserCallback* ucb) {
        zrtpUserCallback = ucb;
    }

    /**
     * Set the client ID for ZRTP Hello message.
     *
     * The GNU ccRTP client may set its id to identify itself in the
     * ZRTP HELLO message. The maximum length is 15 characters. Shorter
     * id string are allowed, the will be filled with blanks. Longer id
     * will be truncated to 15 characters.
     *
     * @param id
     *     The client's id
     */
    void setClientId(std::string id) {
        clientIdString = id;
    }

    /**
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


    void start();
    void stop();

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
     * Refer to ZrtpCallback.h
     */
    int32_t sendDataZRTP(const unsigned char* data, int32_t length);

    int32_t activateTimer(int32_t time);

    int32_t cancelTimer();

    void sendInfo(MessageSeverity severity, char* msg);
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
     */
    void srtpSecretsReady(SrtpSecret_t* secrets, EnableSecurity part);

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
     *    The SAS string or NULL
     */
    void srtpSecretsOn(const char* c, const char* s);

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
    void zrtpNegotiationFailed(MessageSeverity severity, char* msg);

    /**
     * ZRTP calls this methof if the other side does not support ZRTP.
     *
     * If the other side does not answer the ZRTP <em>Hello</em> packets then
     * ZRTP calls this method,
     *
     */
    void zrtpNotSuppOther();

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
};
#endif

#endif
