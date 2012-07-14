/*
*/

#ifndef _CTZRTPSESSION_H_
#define _CTZRTPSESSION_H_


#include <libzrtpcpp/ZrtpCallback.h>
#include <libzrtpcpp/ZrtpConfigure.h>
#include <Thread.h>

void t_add_zrtp_random(void *p, int iLen);
void *initZrtpG();

int relZrtpG(void *pZrtpGlobals);

class CtZrtpStream;
class CtZrtpCb;
class CtZrtpSendCb;


class __EXPORT CtZrtpSession {

public:
    typedef enum _streamName {
        AudioStream = 0,
        VideoStream = 1,
        AllStreams  = 2             //!< AllStreams is max number of streams
    } streamName;

    typedef enum _streamType {
        NoStream = 0,
        Master,
        Slave
    } streamType;

    typedef enum _tiviStatus {
        eLookingPeer = 1,
        eNoPeer,
        eGoingSecure,
        eSecure,
        eError,
        eSecureMitm,
        eWrongStream = -1
    } tiviStatus;


    CtZrtpSession();

    ~CtZrtpSession();

    /** @brief Initialize CtZrtpNew.
     *
     * Before an application can use ZRTP it has to initialize the
     * ZRTP implementation. This method initializes the timeout
     * thread and opens a file that contains ZRTP specific
     * information such as the applications ZID (ZRTP id) and its
     * retained shared secrets.
     *
     * If one application requires several ZRTP sessions all
     * sessions use the same timeout thread and use the same ZID
     * file. Therefore an application does not need to do any
     * synchronisation regading ZID files or timeouts. This is
     * managed by the ZRTP implementation.
     *
     * The application may specify its own ZID file name. If no
     * ZID file name is specified it defaults to
     * <code>$HOME/.GNUccRTP.zid</code> if the <code>HOME</code>
     * environment variable is set. If it is not set the current
     * directory is used.
     *
     * If the method could set up the timeout thread and open the ZID
     * file then it enables ZRTP processing and returns.
     *
     * @param zidFilename
     *     The name of the ZID file, can be a relative or absolut
     *     filename.
     *
     * @param config
     *     this parameter points to ZRTP configuration data. If it is
     *     NULL then ZrtpQueue uses a default setting. Default is NULL.
     *
     * @return
     *     1 on success, ZRTP processing enabled, -1 on failure,
     *     ZRTP processing disabled.
     *
     */
    int32_t init(const char *zidFilename = NULL, ZrtpConfigure* config = NULL);

    /**
     * Set the application's callback class.
     *
     * @param ucb
     *     Implementation of the application's callback class
     */
    void setUserCallback(CtZrtpCb* ucb, streamName streamNm);

    /**
     * Set the application's send data callback class.
     *
     *
     * @param ucb
     *     Implementation of the application's send data callback class
     */
    void setSendCallback(CtZrtpSendCb* scb, streamName streamNm);

    /**
     * Start a stream.
     *
     * If this start command specifies the @c Master stream the method starts it
     * immediately. The ZRTP engine immediatley send the first Hello packet.
     *
     * The functions my delay the start of a @c Slave stream until the @c Master
     * stream enters secure mode. The functions then gets the multi-stream data
     * from the master stream and copies it into the @c Slave streams and starts
     * them.
     *
     * If the @c Master stream is already in secure mode then the function copies
     * the multi-stream parameters to the @c slave and starts it immediately.
     *
     * @param uiSSRC the local SSRC for the stream
     *
     * @param streamNm which stream to start.
     */
    void start(unsigned int uiSSRC, streamName streamNm);

    /**
     * Stop a stream.
     *
     * Stop a stream and remove it from the session. To create a new stream
     * see @c newStream
     * 
     * @param streamNm which stream to stop.
     */
    void stop(streamName streamNm);

    /**
     * Create a new stream.
     *
     * This functions create a new stream. If a stream at @c streamNm exist the
     * function does @b not overwrite the existing stream.
     */
    bool newStream(streamName streamNm, streamType type);

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
     * 
     * @param streamNm specifies which stream to use
     */
    bool processOutoingRtp(uint8_t *buffer, size_t length, size_t *newLength, streamName streamNm);

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
     * @param streamNm specifies which stream to use
     * 
     * @return 1: success, 0: not an error but drop packet, -1: SRTP authentication failed,
     *            -2: SRTP replay check failed
     */
    int32_t processIncomingRtp(uint8_t *buffer, size_t length, size_t *newLength, streamName streamNm);

    /**
     * Check if a stream was started.
     *
     * @return @c true is started, @c false otherwise.
     */
    bool isStarted(streamName streamNm);

    /**
     * Check if a stream is enabled for ZRTP.
     *
     * For slave streams this flag is @c true if the application called @c start() for
     * this stream but the master stream is not yet in secure state.
     *
     * @return @c true is enabled, @c false otherwise.
     */
    bool isEnabled(streamName streamNm);

    tiviStatus getCurrentState(streamName streamNm);

    tiviStatus getPreviousState(streamName streamNm);

protected:
    friend class CtZrtpStream;

    /**
     * Session master stream entered secure state.
     *
     * The session's master stream entered secure state and computed all
     * necessary information to kick of slave streams. The session checks
     * if slave streams are available and if they are ready to start.
     *
     * @param stream is the stream that enters secure mode. This must be a
     *               @c Master stream
     */
    void masterStreamSecure(CtZrtpStream *stream);

    void synchEnter();

    void synchLeave();


private:
    CtZrtpStream *streams[AllStreams];
    std::string  clientIdString;
    std::string  multiStreamParameter;
    const uint8_t* ownZid;

    int32_t secureParts;

    bool mitmMode;
    bool signSas;
    bool enableParanoidMode;
    CMutexClass  synchLock;





    
#if 0
    int iStatus[2];
    int iEnding[2];
    int iPrevStatus[2];
    int iHasDstHash[2];
    void *pCtx;

    void setStatus(int iNew, char *p, int iIsVideo)
    {
        iPrevStatus[iIsVideo] = iStatus[iIsVideo];
        iStatus[iIsVideo] = iNew;
        if (zrtpcb)
            zrtpcb->onNewZrtpStatus(this, p, iIsVideo);
    }

    void onPeer(char *name, int iIsVerified){

        void safeStrCpy(char *dst, const char *name, int iMaxSize);      
        if (name)
            safeStrCpy(&bufPeer[0], name, sizeof(bufPeer)-1);
        if (zrtpcb)
            zrtpcb->onPeer(this, name, iIsVerified);
    }

    void onZrtpWarning(char *p, int iIsVideo){
        //TODO translate, onZrtpWarning(char *p, int iWarningCode, int iIsVideo);
        void safeStrCpy(char *dst, const char *name, int iMaxSize);      
        if (p)
            safeStrCpy(&bufWarning[0], p, sizeof(bufWarning)-1);
        if (zrtpcb)
            zrtpcb->onZrtpWarning(this, p, iIsVideo);
    }

public:
    D_EZRTPSTAT

    CtZrtpNew(void *pZrtpGlobalsN);
    ~CtZrtpNew();

    int init(int iCaller, char *zid_base16, int iInitVideoHash, int iInitAudioHash);

    void release();

    void start(unsigned int uiSSRC, int iIsVideo);

    inline int startIfNotStarted(unsigned int uiSSRC, int iIsVideo) {
        if (!iStarted[iIsVideo] && !iEnding[iIsVideo])
            start(uiSSRC, iIsVideo);
        return 0;
    }


    int isSecure(int iIsVideo);

    int encrypt(char *p, int &iLen, int iIsVideo);
    int decrypt(char *p, int &iLen, int iIsVideo);

    int setDstHash(char *p, int iLen, int iIsVideo);
 
    inline int isStarted(int iIsVideo) {
        return iStarted[iIsVideo] == 1;
    }

    inline int isEnabled() {return 1;}

    inline int canUseZrtp() {return iCanUseZRTP;}

    inline int getStatus(int iIsVideo) {return iStatus[iIsVideo];}

    int getInfo(char*key, char*p, intiMax);
   
   

    void onNeedEnroll(){
        iNeedEnroll=1;
        if (zrtpcb)
            zrtpcb->onNeedEnroll(this);
    }
    void enrollAccepted(const char*mitm_name);

    int clearCaches();
   
    void setVerify(int iVerified);
    //TODO int getSAS(int &iIsBase256, char *p, int iMaxLen);
   
    int setLastPeerName(char *name, int iIsMitm);

    const char *getZRTP_msg(int s);
#endif
};

#endif /* _CTZRTPSESSION_H_ */