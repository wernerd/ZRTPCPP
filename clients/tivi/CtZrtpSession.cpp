/*
 * 
 */

#include <string>
#include <stdio.h>

#include <libzrtpcpp/ZIDFile.h>
#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpStateClass.h>
#include <srtp/CryptoContext.h>
#include <srtp/CryptoContextCtrl.h>

#include <CtZrtpStream.h>
#include <CtZrtpSession.h>

// using namespace GnuZrtpCodes;

CtZrtpSession::CtZrtpSession() {
    streams[AudioStream] = new CtZrtpStream();
    streams[VideoStream] = new CtZrtpStream();
}


int32_t CtZrtpSession::init(const char *zidFilename, ZrtpConfigure* config)
{
    int32_t ret = 1;

    synchEnter();

    ZrtpConfigure* configOwn = NULL;
    if (config == NULL) {
        config = configOwn = new ZrtpConfigure();
        config->setMandatoryOnly();
    }
    config->setParanoidMode(enableParanoidMode);

    ZIDFile* zf = ZIDFile::getInstance();
    if (!zf->isOpen()) {
        std::string fname;
        if (zidFilename == NULL) {
            char *home = getenv("HOME");
            std::string baseDir = (home != NULL) ? (std::string(home) + std::string("/."))
                                                    : std::string(".");
            fname = baseDir + std::string("GNUZRTP.zid");
            zidFilename = fname.c_str();
        }
        if (zf->open((char *)zidFilename) < 0) {
            ret = -1;
        }
    }
    if (ret > 0) {
        const uint8_t* ownZid = zf->getZid();
        CtZrtpStream *stream;

        stream = streams[AudioStream];
        stream->zrtpEngine = new ZRtp((uint8_t*)ownZid, stream, clientIdString, config, mitmMode, signSas);
        stream->type = Master;
        stream->index = AudioStream;
        stream->session = this;

        stream = streams[VideoStream];
        stream->zrtpEngine = new ZRtp((uint8_t*)ownZid, stream, clientIdString, config);
        stream->type = Slave;
        stream->index = VideoStream;
        stream->session = this;
    }
    if (configOwn != NULL) {
        delete configOwn;
    }
    synchLeave();
    return ret;
}

CtZrtpSession::~CtZrtpSession() {

    stop(AudioStream);
    stop(VideoStream);
}

void CtZrtpSession::setUserCallback(CtZrtpCb* ucb, streamName streamNm) {
    if (!(streamNm >= 0 && streamNm <= AllStreams && streams[streamNm] != NULL))
        return;

    if (streamNm == AllStreams) {
        for (int sn = 0; sn < AllStreams; sn++)
            streams[sn]->setUserCallback(ucb);
    }
    else
        streams[streamNm]->setUserCallback(ucb);
}

void CtZrtpSession::setSendCallback(CtZrtpSendCb* scb, streamName streamNm) {
    if (!(streamNm >= 0 && streamNm <= AllStreams && streams[streamNm] != NULL))
        return;

    if (streamNm == AllStreams) {
        for (int sn = 0; sn < AllStreams; sn++)
            streams[sn]->setSendCallback(scb);
    }
    else
        streams[streamNm]->setSendCallback(scb);

}

void CtZrtpSession::masterStreamSecure(CtZrtpStream *stream) {
    // Here we know that the AudioStream is the master and VideoStream the slave.
    // Otherwise weneed to loop and find the Master stream and the Slave streams.

    multiStreamParameter = stream->zrtpEngine->getMultiStrParams();
    CtZrtpStream *strm = streams[VideoStream];
    if (strm->enableZrtp) {
        strm->zrtpEngine->setMultiStrParams(multiStreamParameter);
        strm->zrtpEngine->startZrtpEngine();
        strm->started = true;
    }

}

void CtZrtpSession::start(unsigned int uiSSRC, CtZrtpSession::streamName streamNm) {
    if (!(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != NULL))
        return;

    CtZrtpStream *stream = streams[streamNm];

    stream->ownSSRC = uiSSRC;
    if (stream->type == Master) {
        stream->enableZrtp = true;
        stream->zrtpEngine->startZrtpEngine();
        stream->started = true;
        return;
    }
    // Process a Slave stream.
    stream->enableZrtp = true;
    if (!multiStreamParameter.empty()) {        // Multi-stream parameters available
        stream->zrtpEngine->setMultiStrParams(multiStreamParameter);
        stream->zrtpEngine->startZrtpEngine();
        stream->started = true;
    }
}

void CtZrtpSession::stop(streamName streamNm) {
    if (!(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != NULL))
        return;

    CtZrtpStream *stream = streams[streamNm];

    delete stream;                      // destroy the existing stuff
    stream = NULL;
}

#if 0
bool CtZrtpSession::newStream(streamName streamNm, streamType type) {
    if (!(streamNm >= 0 && streamNm < AllStreams))
        return false;

    CtZrtpStream *stream = streams[streamNm];
    if (stream != NULL) {               // Do not replace an existing stream
        return false;
    }
    if (stream->type == Master) {
        // Here we do a fixed check: could search for Master in array. But we know
        // Master is always AudioStream
        if (streamNm != AudioStream)
            return false;
        streams[AudioStream] = new CtZrtpStream();
        stream = streams[AudioStream];
        stream->zrtpEngine = new ZRtp((uint8_t*)ownZid, stream, clientIdString, config, mitmMode, signSas);
        stream->type = Master;
        stream->index = AudioStream;
        stream->session = this;
        return true;
    }
    streams[VideoStream] = new CtZrtpStream();
    stream = streams[VideoStream];
    stream->zrtpEngine = new ZRtp((uint8_t*)ownZid, stream, clientIdString, config);
    stream->type = Slave;
    stream->index = VideoStream;
    stream->session = this;
}
#endif

bool CtZrtpSession::processOutoingRtp(uint8_t *buffer, size_t length, size_t *newLength, streamName streamNm) {
    if (!(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != NULL))
        return false;

    CtZrtpStream *stream = streams[streamNm];
    return stream->processOutgoingRtp(buffer, length, newLength);
}

int32_t CtZrtpSession::processIncomingRtp(uint8_t *buffer, size_t length, size_t *newLength, streamName streamNm) {
    if (!(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != NULL))
        return 0;

    CtZrtpStream *stream = streams[streamNm];
    return stream->processIncomingRtp(buffer, length, newLength);
}

bool CtZrtpSession::isStarted(streamName streamNm) {
    if (!(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != NULL))
        return false;

    return streams[streamNm]->isStarted();
}

bool CtZrtpSession::isEnabled(streamName streamNm) {
    if (!(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != NULL))
        return false;

    return streams[streamNm]->isEnabled();
}

CtZrtpSession::tiviStatus CtZrtpSession::getCurrentState(streamName streamNm) {
    if (!(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != NULL))
        return eWrongStream;

    return streams[streamNm]->getCurrentState();
}

CtZrtpSession::tiviStatus CtZrtpSession::getPreviousState(streamName streamNm) {
    if (!(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != NULL))
        return eWrongStream;

    return streams[streamNm]->getPreviousState();
}

void CtZrtpSession::synchEnter() {
    synchLock.Lock();
}

void CtZrtpSession::synchLeave() {
    synchLock.Unlock();
}

