/*
 * Copyright (c) 2019 Silent Circle.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 * Tivi client glue code for ZRTP.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <string>
#include <cstdio>
#include <mutex>

#include <libzrtpcpp/ZIDCache.h>
#include <libzrtpcpp/ZRtp.h>

#include <CtZrtpStream.h>
#include <CtZrtpCallback.h>
#include <CtZrtpSession.h>

#include <zrtp/libzrtpcpp/ZIDCacheDb.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"

static std::mutex sessionLock;

const char *getZrtpBuildInfo()
{
    return zrtpBuildInfo;
}

std::shared_ptr<ZIDCache> CtZrtpSession::zrtpCache = nullptr;

CtZrtpSession::CtZrtpSession() : zrtpMaster(nullptr), mitmMode(false), signSas(false), enableParanoidMode(false), isReady(false),
    zrtpEnabled(true), sdesEnabled(true), discriminatorMode(false) {

    clientIdString = clientId;          // Client id is ZRTP global text data
}

// Specific initialization for SilentPhone: use _one_ ZRTP cache file for _all_ sessions, even
// for conference calls. This simplifies handling of cache data.
// If another app likes to have different cache files (or even open the same file several times ? )
// then just change the cache initialization at his point.
static std::shared_ptr<ZIDCache>
initCache(const char *zidFilename, std::shared_ptr<ZIDCache> cache) {
    std::string fname;
    if (!zidFilename) {
        char *home = getenv("HOME");
        std::string baseDir = (home) ? (std::string(home) + std::string("/."))
                                             : std::string(".");
        fname = baseDir + std::string("GNUZRTP.zid");
        zidFilename = fname.c_str();
    }

    // Check if a cache is available.
    // If yes and it has the same filename -> use it
    // otherwise close file and open new cache file
    if (cache) {
        if (cache->getFileName() == zidFilename) {
            return cache;
        }
        cache->close();
        if (cache->open((char *)zidFilename) < 0) {
            return std::shared_ptr<ZIDCache>();
        }
        return cache;
    }

    auto zf = std::make_shared<ZIDCacheDb>();
    if (zf->open((char *)zidFilename) < 0) {
        return std::shared_ptr<ZIDCache>();
    }
    return zf;
}

int CtZrtpSession::init(bool audio, bool video, int32_t callId, const char *zidFilename, std::shared_ptr<ZrtpConfigure>& config) {
    int32_t ret = 1;
    CtZrtpStream *stream;

    syncEnter();

    std::shared_ptr<ZrtpConfigure> configOwn;

    // Audio is the master stream, thus initialize ZID cache and ZRTP configure for it. Each Session has _one_
    // audio (master) which can have it's own configuration and own ZID cache.
    // The caller must make sure to initialize the audio stream before the video stream (or at the same time with
    // both boolean parameters set to true).
    if (audio) {

        // If we got no config -> initialize all necessary stuff here. This is for backward compat mainly.
        // Otherwise we expect to get a fully initialized config, including an initialized cache file instance
        if (!config) {
            auto zf = initCache(zidFilename, zrtpCache);
            if (!zf) {
                return -1;
            }
            if (!zrtpCache) {
                zrtpCache = zf;
            }

            configOwn = std::make_shared<ZrtpConfigure>();
            configOwn->setZidCache(zf);
            setupConfiguration(configOwn.get());
        }
        else {
            configOwn = config;
        }

        const uint8_t* ownZidFromCache = configOwn->getZidCache()->getZid();

        configOwn->setTrustedMitM(false);
#if defined AXO_SUPPORT
        configOwn->setSasSignature(true);
#endif
        configOwn->setParanoidMode(enableParanoidMode);

        // Create CTZrtpStream object only once, they are available for the whole lifetime of the session.
        if (streams[AudioStream] == nullptr)
            streams[AudioStream] = new CtZrtpStream();
        stream = streams[AudioStream];
        stream->zrtpEngine = new ZRtp((uint8_t*)ownZidFromCache, *stream, clientIdString, configOwn, mitmMode, signSas);
        stream->type = Master;
        stream->index = AudioStream;
        stream->session = this;
        stream->discriminatorMode = discriminatorMode;
    }
    if (video) {
        if (streams[VideoStream] == nullptr)
            streams[VideoStream] = new CtZrtpStream();

        // Get the ZRTP Configure from master and forward it to the slave stream. Slave stream should have the same
        // configuration and cache as the master stream. ZRTP configuration is managed via shared_ptr.
        auto videoConfig = streams[AudioStream]->zrtpEngine->getZrtpConfigure();
        const uint8_t* ownZidFromCache = videoConfig->getZidCache()->getZid();

        stream = streams[VideoStream];
        stream->zrtpEngine = new ZRtp((uint8_t*)ownZidFromCache, *stream, clientIdString, videoConfig);
        stream->type = Slave;
        stream->index = VideoStream;
        stream->session = this;
        stream->discriminatorMode = discriminatorMode;
    }
    callId_ = callId;

    isReady = true;

    syncLeave();
    return ret;
}

CtZrtpSession::~CtZrtpSession() {

    delete streams[AudioStream];
    delete streams[VideoStream];
}

void zrtp_log(const char *tag, const char *buf);
void CtZrtpSession::setupConfiguration(ZrtpConfigure *conf) {

// Set _WITHOUT_TIVI_ENV to a real name that is TRUE if the Tivi client is compiled/built.
#ifdef _WITHOUT_TIVI_ENV
#define GET_CFG_I(RET,_KEY)
#else
void *findGlobalCfgKey(char *key, int iKeyLen, int &iSize, char **opt, int *type);
#define GET_CFG_I(RET,_KEY) {int *p=(int*)findGlobalCfgKey((char*)_KEY,sizeof(_KEY)-1,iSZ,&opt,&type);if(p && iSZ==4)RET=*p;else RET=-1;}
#endif


// The next three vars are used in case of a real Tivi compile, see macro above.
    int iSZ;
    char *opt;
    int type;

    int b32sas = 0, iDisableDH2K = 0, iDisableAES256 = 0, iPreferDH2K = 0;
    int iDisableECDH256 = 0, iDisableECDH384 = 0, iEnableSHA384 = 1;
    int iDisableSkein = 0, iDisableTwofish = 0, iPreferNIST = 0;
    int iDisableSkeinHash = 0, iDisableBernsteinCurve25519 = 0, iDisableBernsteinCurve3617 = 0;
    int iEnableDisclosure = 0;

    GET_CFG_I(b32sas, "iDisable256SAS");
    GET_CFG_I(iDisableAES256, "iDisableAES256");
    GET_CFG_I(iDisableDH2K, "iDisableDH2K");
    GET_CFG_I(iPreferDH2K, "iPreferDH2K");

    GET_CFG_I(iDisableECDH256, "iDisableECDH256");
    GET_CFG_I(iDisableECDH384, "iDisableECDH384");
    GET_CFG_I(iEnableSHA384, "iEnableSHA384");
    GET_CFG_I(iDisableSkein, "iDisableSkein");
    GET_CFG_I(iDisableTwofish, "iDisableTwofish");
    GET_CFG_I(iPreferNIST, "iPreferNIST");

    GET_CFG_I(iDisableSkeinHash, "iDisableSkeinHash");
    GET_CFG_I(iDisableBernsteinCurve25519, "iDisableBernsteinCurve25519");
    GET_CFG_I(iDisableBernsteinCurve3617, "iDisableBernsteinCurve3617");
    GET_CFG_I(iEnableDisclosure, "iEnableDisclosure");

    conf->clear();

    /*
     * Setting the selection policy is a more generic policy than the iPreferNIST
     * configuration set by the user. The selection policy is a decision of the
     * client, not the user
     */
    conf->setSelectionPolicy(ZrtpConfigure::PreferNonNist);

    // Set the Disclosure flag if the client SW has DR active.
    if (iEnableDisclosure == 1)
        conf->setDisclosureFlag(true);

    /*
     * Handling of iPreferNIST: if this is false (== 0) then we add the non-NIST algorithms
     * to the configuration and place them in front of the NIST algorithms. Refer to RFC6189
     * section 4.1.2 regarding selection of the public key algorithm.
     * 
     * With the configuration flags we can enable/disable each ECC PK algorithm separately.
     * 
     */
    if (iPreferNIST == 0) {
        if (iDisableBernsteinCurve3617 == 0)
            conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("E414"));
        if (iDisableECDH384 == 0)
            conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("EC38"));
    }
    else {
        if (iDisableECDH384 == 0)
            conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("EC38"));
        if (iDisableBernsteinCurve3617 == 0)
            conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("E414"));
    }

    if (iPreferNIST == 0) {
        if (iDisableBernsteinCurve25519 == 0)
            conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("E255"));
        if (iDisableECDH256 == 0)
            conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("EC25"));
    }
    else {
        if (iDisableECDH256 == 0)
            conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("EC25"));
        if (iDisableBernsteinCurve25519 == 0)
            conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("E255"));
    }

    // DH2K handling: if DH2K not disabled and prefered put it infrom of DH3K,
    // If not preferred and not disabled put if after DH3K. Don't use DH2K if
    // it's not enabled at all (iDisableDH2K == 1)
    if (iPreferDH2K && iDisableDH2K == 0) {
        conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("DH2k"));
    }
    conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("DH3k"));
    if (iPreferDH2K == 0 && iDisableDH2K == 0)
        conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("DH2k"));

    conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("Mult"));


    // Handling of Hash algorithms: similar to PK, if PreferNIST is false
    // then put Skein in fromt oF SHA. Regardless if the Hash is enabled or
    // not: if configuration enables a large curve then also use the large
    // hashes.
    if (iPreferNIST == 0) {
        if (iDisableSkeinHash == 0 || iDisableBernsteinCurve3617 == 0)
            conf->addAlgo(HashAlgorithm, zrtpHashes.getByName("SKN3"));
        if (iEnableSHA384 == 1 || iDisableECDH384 == 0) 
            conf->addAlgo(HashAlgorithm, zrtpHashes.getByName("S384"));
    }
    else {
        if (iEnableSHA384 == 1 || iDisableECDH384 == 0) 
            conf->addAlgo(HashAlgorithm, zrtpHashes.getByName("S384"));
        if (iDisableSkeinHash == 0 || iDisableBernsteinCurve3617 == 0)
            conf->addAlgo(HashAlgorithm, zrtpHashes.getByName("SKN3"));
    }

    if (iPreferNIST == 0) {
        if (iDisableSkeinHash == 0)
            conf->addAlgo(HashAlgorithm, zrtpHashes.getByName("SKN2"));
        conf->addAlgo(HashAlgorithm, zrtpHashes.getByName("S256"));
    }
    else {
        conf->addAlgo(HashAlgorithm, zrtpHashes.getByName("S256"));
        if (iDisableSkeinHash == 0)
            conf->addAlgo(HashAlgorithm, zrtpHashes.getByName("SKN2"));
    }

    // Handling of Symmetric algorithms: always prefer twofish (regardless
    // of NIST setting) if it is not disabled. iDisableAES256 means: disable
    // large ciphers
    if (iDisableAES256 == 0) {
        if (iDisableTwofish == 0)
            conf->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("2FS3"));
        conf->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("AES3"));
    }

    if (iDisableTwofish == 0)
        conf->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("2FS1"));
    conf->addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName("AES1"));

    if (b32sas == 1) {
        conf->addAlgo(SasType, zrtpSasTypes.getByName("B32 "));
    }
    else if (b32sas == 2) {
        conf->addAlgo(SasType, zrtpSasTypes.getByName("B32E"));
        conf->addAlgo(SasType, zrtpSasTypes.getByName("B32 "));
    }
    else {
        conf->addAlgo(SasType, zrtpSasTypes.getByName("B256"));
        conf->addAlgo(SasType, zrtpSasTypes.getByName("B32 "));
    }

    if (iPreferNIST == 0) {
        if (iDisableSkein == 0) {
            conf->addAlgo(AuthLength, zrtpAuthLengths.getByName("SK32"));
            conf->addAlgo(AuthLength, zrtpAuthLengths.getByName("SK64"));
        }
        conf->addAlgo(AuthLength, zrtpAuthLengths.getByName("HS32"));
        conf->addAlgo(AuthLength, zrtpAuthLengths.getByName("HS80"));
    }
    else {
        conf->addAlgo(AuthLength, zrtpAuthLengths.getByName("HS32"));
        conf->addAlgo(AuthLength, zrtpAuthLengths.getByName("HS80"));
        if (iDisableSkein == 0) {
            conf->addAlgo(AuthLength, zrtpAuthLengths.getByName("SK32"));
            conf->addAlgo(AuthLength, zrtpAuthLengths.getByName("SK64"));
        }
    }
}

void CtZrtpSession::setUserCallback(CtZrtpCb* ucb, streamName streamNm) {
    if (!(streamNm >= 0 && streamNm <= AllStreams && streams[streamNm] != nullptr))
        return;

    if (streamNm == AllStreams) {
        for (auto& stream : streams) {
            stream->setUserCallback(ucb);
        }
    }
    else
        streams[streamNm]->setUserCallback(ucb);
}

void CtZrtpSession::setSendCallback(CtZrtpSendCb* scb, streamName streamNm) {
    if (!(streamNm >= 0 && streamNm <= AllStreams && streams[streamNm] != nullptr))
        return;

    if (streamNm == AllStreams) {
        for (auto& stream : streams) {
            stream->setSendCallback(scb);
        }
    }
    else
        streams[streamNm]->setSendCallback(scb);

}

void CtZrtpSession::masterStreamSecure(CtZrtpStream *masterStream) {
    // Here we know that the AudioStream is the master and VideoStream the slave.
    // Otherwise we need to loop and find the Master stream and the Slave streams.

    multiStreamParameter = masterStream->zrtpEngine->getMultiStrParams(&zrtpMaster);
    CtZrtpStream *strm = streams[VideoStream];
    if (strm->enableZrtp) {
        strm->zrtpEngine->setMultiStrParams(multiStreamParameter, zrtpMaster);
        strm->zrtpEngine->startZrtpEngine();
        strm->started = true;
        strm->tiviState = eLookingPeer;
        if (strm->zrtpUserCallback != nullptr)
            strm->zrtpUserCallback->onNewZrtpStatus(this, nullptr, strm->index);

    }
}

int CtZrtpSession::startIfNotStarted(unsigned int uiSSRC, int streamNm) {
    if (!(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return 0;

    if ((streamNm == VideoStream && !isSecure(AudioStream)) || streams[streamNm]->started)
        return 0;

    start(uiSSRC, streamNm == VideoStream ? CtZrtpSession::VideoStream : CtZrtpSession::AudioStream);
    return 0;
}

void CtZrtpSession::start(unsigned int uiSSRC, CtZrtpSession::streamName streamNm) {
    if (!zrtpEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return;

    CtZrtpStream *stream = streams[streamNm];

    stream->ownSSRC = uiSSRC;
    stream->enableZrtp = true;
    if (stream->type == Master) {
        stream->zrtpEngine->startZrtpEngine();
        stream->started = true;
        stream->tiviState = eLookingPeer;
        if (stream->zrtpUserCallback != nullptr)
            stream->zrtpUserCallback->onNewZrtpStatus(this, nullptr, stream->index);
        return;
    }
    // Process a Slave stream.
    if (!multiStreamParameter.empty()) {        // Multi-stream parameters available
        stream->zrtpEngine->setMultiStrParams(multiStreamParameter, zrtpMaster);
        stream->zrtpEngine->startZrtpEngine();
        stream->started = true;
        stream->tiviState = eLookingPeer;
        if (stream->zrtpUserCallback != nullptr)
            stream->zrtpUserCallback->onNewZrtpStatus(this, nullptr, stream->index);
    }
}

void CtZrtpSession::stop(streamName streamNm) {
    if (!(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return;

    streams[streamNm]->isStopped = true;
}

void CtZrtpSession::release() {
    release(AudioStream);
    release(VideoStream);
    zrtpMaster = nullptr;
}

void CtZrtpSession::release(streamName streamNm) {
    if (!(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return;

    CtZrtpStream *stream = streams[streamNm];
    stream->stopStream();                      // stop and reset stream
}

void CtZrtpSession::setLastPeerNameVerify(const char *name, int iIsMitm) {
    (void) iIsMitm;
    CtZrtpStream *stream = streams[AudioStream];

    if (!isReady || !stream || stream->isStopped)
        return;

    uint8_t peerZid[IDENTIFIER_LEN];
    std::string nm(name);
    stream->zrtpEngine->getPeerZid(peerZid);
    stream->zrtpEngine->getZidCache()->putPeerName(peerZid, nm);
    setVerify(1);
}

int CtZrtpSession::isSecure(streamName streamNm) {
    if (!(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return 0;

    CtZrtpStream *stream = streams[streamNm];
    return stream->isSecure();
}

bool CtZrtpSession::processOutoingRtp(uint8_t *buffer, size_t length, size_t *newLength, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return false;

    CtZrtpStream *stream = streams[streamNm];
    if (stream->isStopped)
        return false;

    return stream->processOutgoingRtp(buffer, length, newLength);
}

int32_t CtZrtpSession::processIncomingRtp(uint8_t *buffer, size_t length, size_t *newLength, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    CtZrtpStream *stream = streams[streamNm];
    if (stream->isStopped)
        return fail;

    return stream->processIncomingRtp(buffer, length, newLength);
}

bool CtZrtpSession::isStarted(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return false;

    return streams[streamNm]->isStarted();
}

bool CtZrtpSession::isEnabled(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return false;

    CtZrtpStream *stream = streams[streamNm];
    if (stream->isStopped)
        return false;

    return stream->isEnabled();
}

CtZrtpSession::tiviStatus CtZrtpSession::getCurrentState(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return eWrongStream;

    CtZrtpStream *stream = streams[streamNm];
    if (stream->isStopped)
        return eWrongStream;

    return stream->getCurrentState();
}

CtZrtpSession::tiviStatus CtZrtpSession::getPreviousState(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return eWrongStream;

    CtZrtpStream *stream = streams[streamNm];
    if (stream->isStopped)
        return eWrongStream;

    return stream->getPreviousState();
}

bool CtZrtpSession::isZrtpEnabled() {
    return zrtpEnabled;
}

bool CtZrtpSession::isSdesEnabled() {
    return sdesEnabled;
}

void CtZrtpSession::setZrtpEnabled(bool yesNo) {
    zrtpEnabled = yesNo;
}

void CtZrtpSession::setSdesEnabled(bool yesNo) {
    sdesEnabled = yesNo;
}

int CtZrtpSession::getSignalingHelloHash(char *helloHash, streamName streamNm, int32_t index) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return 0;

    CtZrtpStream *stream = streams[streamNm];
    if (stream->isStopped)
        return 0;

    return stream->getSignalingHelloHash(helloHash, index);
}

void CtZrtpSession::setSignalingHelloHash(const char *helloHash, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return;

    CtZrtpStream *stream = streams[streamNm];
    if (stream->isStopped)
        return;

    stream->setSignalingHelloHash(helloHash);
}

void CtZrtpSession::setVerify(int iVerified) {
    CtZrtpStream *stream = streams[AudioStream];

    if (!isReady || !stream || stream->isStopped)
        return;

    if (iVerified) {
        stream->zrtpEngine->SASVerified();
        stream->sasVerified = true;
    }
    else {
        stream->zrtpEngine->resetSASVerified();
        stream->sasVerified = false;
    }
}

int CtZrtpSession::getInfo(const char *key, uint8_t *buffer, size_t maxLen, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    CtZrtpStream *stream = streams[streamNm];
    return stream->getInfo(key, (char*)buffer, (int)maxLen);
}

int CtZrtpSession::getNumberOfCountersZrtp(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return -1;

    CtZrtpStream *stream = streams[streamNm];
    return stream->getNumberOfCountersZrtp();
}

int CtZrtpSession::getCountersZrtp(int32_t* counters, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return -1;

    CtZrtpStream *stream = streams[streamNm];
    return stream->getCountersZrtp(counters);
}


int CtZrtpSession::enrollAccepted(char *p) {
    if (!isReady || streams[AudioStream] == nullptr)
        return fail;

    CtZrtpStream *stream = streams[AudioStream];
    int ret = stream->enrollAccepted(p);
    setVerify(true);
    return ret;
}

int CtZrtpSession::enrollDenied() {
    if (!isReady || streams[AudioStream] == nullptr)
        return fail;

    CtZrtpStream *stream = streams[AudioStream];
    int ret = stream->enrollDenied();
    setVerify(true);                        // TODO : Janis -> is that correct in this case?
    return ret;
}

void CtZrtpSession::setClientId(std::string id) {
    clientIdString = std::move(id);
}

bool CtZrtpSession::createSdes(char *cryptoString, size_t *maxLen, streamName streamNm, const sdesSuites suite) {

    if (!isReady || !sdesEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    CtZrtpStream *stream = streams[streamNm];
    return stream->createSdes(cryptoString, maxLen, static_cast<ZrtpSdesStream::sdesSuites>(suite));
}

bool CtZrtpSession::parseSdes(char *recvCryptoStr, size_t recvLength, char *sendCryptoStr,
                              size_t *sendLength, bool sipInvite, streamName streamNm) {

    if (!isReady || !sdesEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    CtZrtpStream *stream = streams[streamNm];
    return stream->parseSdes(recvCryptoStr, recvLength, sendCryptoStr, sendLength, sipInvite);
}

bool CtZrtpSession::getSavedSdes(char *sendCryptoStr, size_t *sendLength, streamName streamNm) {
    if (!isReady || !sdesEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    CtZrtpStream *stream = streams[streamNm];
    return stream->getSavedSdes(sendCryptoStr, sendLength);
}

bool CtZrtpSession::isSdesActive(streamName streamNm) {
    if (!isReady || !sdesEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    CtZrtpStream *stream = streams[streamNm];
    return stream->isSdesActive();
}

int CtZrtpSession::getCryptoMixAttribute(char *algoNames, size_t length, streamName streamNm) {
    if (!isReady || !sdesEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return 0;

    CtZrtpStream *stream = streams[streamNm];
    return stream->getCryptoMixAttribute(algoNames, length);
}

bool CtZrtpSession::setCryptoMixAttribute(const char *algoNames, streamName streamNm) {
    if (!isReady || !sdesEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    CtZrtpStream *stream = streams[streamNm];
    return stream->setCryptoMixAttribute(algoNames);
}

void CtZrtpSession::resetSdesContext(streamName streamNm, bool force) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return;

    CtZrtpStream *stream = streams[streamNm];
    stream->resetSdesContext(force);
}


int32_t CtZrtpSession::getNumberSupportedVersions(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return 0;
    return CtZrtpStream::getNumberSupportedVersions();
}

const char* CtZrtpSession::getZrtpEncapAttribute(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return nullptr;

    CtZrtpStream *stream = streams[streamNm];
    if (stream->isStopped)
        return nullptr;

    return CtZrtpStream::getZrtpEncapAttribute();
}

void CtZrtpSession::setZrtpEncapAttribute(const char *attribute, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return;

    CtZrtpStream *stream = streams[streamNm];
    if (stream->isStopped)
        return;

    stream->setZrtpEncapAttribute(attribute);
}

void CtZrtpSession::setAuxSecret(const unsigned char *secret, int length) {
    if (!isReady || streams[AudioStream] == nullptr)
        return;

    CtZrtpStream *stream = streams[AudioStream];
    if (stream->isStopped)
        return;

    stream->setAuxSecret(secret, length);
}

void CtZrtpSession::setDiscriminatorMode ( bool on ) {
    discriminatorMode = on;
}

bool CtZrtpSession::isDiscriminatorMode() {
    return discriminatorMode;
}

int32_t CtZrtpSession::getSrtpTraceData(SrtpErrorData* data, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return 0;

    CtZrtpStream *stream = streams[streamNm];
    return stream->getSrtpTraceData(data);
}

void CtZrtpSession::cleanCache() {
// TODO    getZidCacheInstance()->cleanup();
}

void CtZrtpSession::syncEnter() {
    sessionLock.lock();
}

void CtZrtpSession::syncLeave() {
    sessionLock.unlock();
}

#pragma clang diagnostic pop