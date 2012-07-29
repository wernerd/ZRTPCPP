#ifndef _CTZRTPSTREAM_H_
#define _CTZRTPSTREAM_H_

#include <map>

#include <libzrtpcpp/ZrtpCallback.h>

#include <CtZrtpSession.h>
#include <TimeoutProvider.h>

// Define sizer of internal buffers.
// NOTE: ZRTP buffer is large. An application shall never use ZRTP protocol
// options that fully use it, otherwise IP packet fragmentation may happen.
static const int maxZrtpSize = 3072;
static const int maxRtpSize =  1024;
static const int maxRtcpSize = 1300;

class CryptoContext;
class CryptoContextCtrl;
class ZRtp;
class CtZrtpCb;
class CtZrtpSendCb;
class CtZrtpSession;


typedef enum _tiviStatus {
    eLookingPeer = 1,
    eNoPeer,
    eGoingSecure,
    eSecure,
    eError,
    eSecureMitm
} tiviStatus;

class __EXPORT CtZrtpStream: public ZrtpCallback  {

public:

    bool isStarted() {return started;}

    bool isEnabled() {return enableZrtp;}

    CtZrtpSession::tiviStatus getCurrentState() {return tiviState;}

    CtZrtpSession::tiviStatus  getPreviousState() {return prevTiviState;}

protected:

    CtZrtpSession::streamName  index;      //!< either audio or video. Index in stream array
    CtZrtpSession::streamType  type;       //!< Master or slave stream. Necessary to handle multi-stream
    ZRtp              *zrtpEngine;         //!< The ZRTP core class of this stream
    CtZrtpSession::tiviStatus  tiviState;  //!< Status reported to Tivi client
    CtZrtpSession::tiviStatus  prevTiviState;  //!< previous status reported to Tivi client
    uint32_t          ownSSRC;             //!< Our own SSRC, in host order
    bool              enableZrtp;          //!< Enable the streams ZRTP engine
    bool              started;             //!< This stream's ZRTP engine is started
    bool              isStopped;           //!< Stream stopped by Tivi
    CryptoContext     *recvSrtp;           //!< The SRTP context for this stream
    CryptoContextCtrl *recvSrtcp;          //!< The SRTCP context for this stream
    CryptoContext     *sendSrtp;           //!< The SRTP context for this stream
    CryptoContextCtrl *sendSrtcp;          //!< The SRTCP context for this stream
    CtZrtpCb          *zrtpUserCallback;
    CtZrtpSendCb      *zrtpSendCallback;
    CtZrtpSession     *session;
    CMutexClass       synchLock;

    friend class CtZrtpSession;
    friend class TimeoutProvider<std::string, CtZrtpStream*>;

    CtZrtpStream();
    virtual ~CtZrtpStream();
    /**
     * Handle timeout event forwarded by the TimeoutProvider.
     *
     * Just call the ZRTP engine for further processing.
     */
    void handleTimeout(const std::string &c);

    /**
     * Set the application's callback class.
     *
     * @param ucb
     *     Implementation of the application's callback class
     */
    void setUserCallback(CtZrtpCb* ucb);

    /**
     * Set the application's send data callback class.
     *
     *
     * @param ucb
     *     Implementation of the application's send data callback class
     */
    void setSendCallback(CtZrtpSendCb* scb);

    /**
     * Stop this stream.
     *
     */
    void stopZrtp();

    /**
     * Process outgoing data.
     *
     * Depending on the state of the buffer the functions either returns the buffer
     * umodified or encrypted.
     * 
     * The function takes a uint8_t buffer that must contain RTP packet data. The
     * function also assumes that the RTP packet contains all protocol relevant fields
     * (SSRC, sequence number etc.) in network order.
     *
     * When encrypting the buffer must big enough to store additional data, usually
     * 10 bytes if the application set the full authentication length (80 bit).
     *
     * @param buffer contains data in RTP packet format
     * 
     * @param length length of the RTP packet data in buffer.
     *
     * @param newLength returns the new length of the RTP data. When encrypting
     *                  @c newLength covers the additional SRTP authentication data.
     */
    bool processOutgoingRtp(uint8_t *buffer, size_t length, size_t *newLength);

    /**
     * Process incoming data.
     *
     * Depending on the state of the buffer the functions either returns the RTP data
     * in the buffer either umodified or decrypted. An additional status is @c drop.
     * The functions returns this status if the application must not process this
     * RTP data. The function handled these packets as ZRTP packets.
     *
     * The function takes a uint8_t buffer that must contain RTP or ZRTP packet data.
     * The function also assumes that the RTP/ZRTP packet contains all protocol relevant
     * fields (SSRC, sequence number etc.) in network order or in the order defined
     * for the protocol.
     *
     * @param buffer contains data in RTP/ZRTP packet format
     *
     * @param length length of the RTP/ZRTP packet data in buffer.
     *
     * @param newLength returns the new length of the RTP data. When encrypting
     *                  @c newLength covers the additional SRTP authentication data.
     *
     * @return 1: success, 0: not an error but drop packet, -1: SRTP authentication failed,
     *            -2: SRTP replay check failed
     */
    int32_t processIncomingRtp(uint8_t *buffer, size_t length, size_t *newLength);

    /*
     * The following methods implement the GNU ZRTP callback interface.
     * For detailed documentation refer to file ZrtpCallback.h
     */
    int32_t sendDataZRTP(const unsigned char* data, int32_t length);

    int32_t activateTimer(int32_t time);

    int32_t cancelTimer();

    void sendInfo(GnuZrtpCodes::MessageSeverity severity, int32_t subCode);

    bool srtpSecretsReady(SrtpSecret_t* secrets, EnableSecurity part);

    void srtpSecretsOff(EnableSecurity part);

    void srtpSecretsOn(std::string c, std::string s, bool verified);

    void handleGoClear();

    void zrtpNegotiationFailed(GnuZrtpCodes::MessageSeverity severity, int32_t subCode);

    void zrtpNotSuppOther();

    void synchEnter();

    void synchLeave();

    void zrtpAskEnrollment(GnuZrtpCodes::InfoEnrollment info);

    void zrtpInformEnrollment(GnuZrtpCodes::InfoEnrollment  info);

    void signSAS(uint8_t* sasHash);

    bool checkSASSignature(uint8_t* sasHash);

    /*
     * End of ZrtpCallback functions.
     */
private:
    uint8_t zrtpBuffer[maxZrtpSize];
    uint8_t sendBuffer[maxRtpSize];
    uint8_t sendBufferCtrl[maxRtcpSize];
    uint16_t senderZrtpSeqNo;
    uint32_t peerSSRC;
    uint64_t protect;
    uint64_t unprotect;
    uint64_t unprotectFailed;
    uint32_t srtcpIndex;

    void initStrings();
};

#endif /* _CTZRTPSTREAM_H_ */