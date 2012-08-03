
#ifndef _CTZRTPCALLBACK_H_
#define _CTZRTPCALLBACK_H_

#include <CtZrtpSession.h>

class __EXPORT CtZrtpCb {
public:
    virtual void onNewZrtpStatus(CtZrtpSession *session, char *p, CtZrtpSession::streamName streamNm) =0;
    virtual void onNeedEnroll(CtZrtpSession *session, CtZrtpSession::streamName streamNm, int32_t info) =0;
    virtual void onPeer(CtZrtpSession *session, char *name, int iIsVerified, CtZrtpSession::streamName streamNm) =0;
    virtual void onZrtpWarning(CtZrtpSession *session, char *p, CtZrtpSession::streamName streamNm) =0;
};


class __EXPORT CtZrtpSendCb {
public:
    virtual void sendRtp(CtZrtpSession const *session, uint8_t* packet, unsigned int length, CtZrtpSession::streamName streamNm) =0;
};

#endif