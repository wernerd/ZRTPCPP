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

#include "libzrtpcpp/ZIDCache.h"
#include "libzrtpcpp/ZRtp.h"

#include "CtZrtpStream.h"
#include "CtZrtpCallback.h"
#include "CtZrtpSession.h"
#include "buildInfo.h"

#ifdef ZID_DATABASE
#include "zrtp/libzrtpcpp/ZIDCacheDb.h"
#endif

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"

static std::mutex sessionLock;

char const *getZrtpBuildInfo()
{
    return zrtpBuildInfo;
}

std::shared_ptr<ZIDCache> CtZrtpSession::zrtpCache = nullptr;

CtZrtpSession::CtZrtpSession() : zrtpMaster(nullptr), mitmMode(false), signSas(false), enableParanoidMode(false), isReady(false),
    zrtpEnabled(true), sdesEnabled(true), discriminatorMode(false) {

    clientIdString = clientId;          // Client id is ZRTP global text data
}

#ifdef ZID_DATABASE
// Specific initialization for SilentPhone: use _one_ ZRTP cache file for _all_ sessions, even
// for conference calls. This simplifies handling of cache data.
// If another app likes to have different cache files or open the same file several times
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
            return {};
        }
        return cache;
    }
    auto zf = std::make_shared<ZIDCacheDb>();
    if (zf->open((char *)zidFilename) < 0) {
        return {};
    }
    return zf;
}
#else

#include "../cryptcommon/ZrtpRandom.h"
// Set up an 'empty cache'. Use this only if you really need no cached ZRTP session
// data. In this case the app shall force the user to check and confirm the SAS data
// on each call to make sure nobody tampered with the ZRTP key negotiation.
//
// If an empty cache already exists, return it and thus also reuse the existing
// random ZID.
//
// Otherwise, the code generates a new random ZID and sets it as ZID in the empty cache
// instance.
static std::shared_ptr<ZIDCache>
initNoCache(const char *zidFilename, std::shared_ptr<ZIDCache> cache) {
    // Check if a cache is available.
    // If yes -> use it
    if (cache) {
        return cache;
    }
    auto zf = std::make_shared<ZIDCacheEmpty>();
    uint8_t newZid[IDENTIFIER_LEN] = {0};
    ZrtpRandom::getRandomData(newZid, IDENTIFIER_LEN);
    zf->setZid(newZid);
    return zf;
}
#endif

int CtZrtpSession::init(bool audio, bool video, int32_t callId, const char *zidFilename, std::shared_ptr<ZrtpConfigure>& config) {
    int32_t ret = 1;
    std::shared_ptr<ZrtpCallback> stream;

    syncEnter();

    std::shared_ptr<ZrtpConfigure> configOwn;

    // Audio is the master stream, thus initialize ZID cache and ZRTP configure for it. Each Session has _one_
    // audio (master) which can have it's own configuration and own ZID cache.
    // The caller must make sure to initialize the audio stream before the video stream (or at the same time with
    // both boolean parameters set to true).
    if (audio) {

        // If we got no config -> initialize all necessary stuff here. This is for backward compatibility.
        // Otherwise, we expect to get a fully initialized config, including an initialized cache file instance
        if (!config) {
#ifdef ZID_DATABASE
            auto zf = initCache(zidFilename, zrtpCache);
#else
            auto zf = initNoCache(zidFilename, zrtpCache);
#endif
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

        configOwn->setTrustedMitM(false);
#if defined AXO_SUPPORT
        configOwn->setSasSignature(true);
#endif
        configOwn->setParanoidMode(enableParanoidMode);

        // Create CTZrtpStream object only once, they are available for the whole lifetime of the session.
        if (streams[AudioStream] == nullptr)
            streams[AudioStream] = std::make_shared<CtZrtpStream>();
        stream = streams[AudioStream];
        streams[AudioStream]->zrtpEngine = new ZRtp(clientIdString, stream,  configOwn);
        streams[AudioStream]->type = Master;
        streams[AudioStream]->index = AudioStream;
        streams[AudioStream]->session = this;
        streams[AudioStream]->discriminatorMode = discriminatorMode;
    }
    if (video) {
        if (streams[VideoStream] == nullptr)
            streams[VideoStream] = std::make_shared<CtZrtpStream>();

        // Get the ZRTP Configure from master and forward it to the slave stream. Slave stream should have the same
        // configuration and cache as the master stream. ZRTP configuration is managed via shared_ptr.
        auto videoConfig = streams[AudioStream]->zrtpEngine->getZrtpConfigure();

        stream = streams[VideoStream];
        streams[VideoStream]->zrtpEngine = new ZRtp(clientIdString, stream, videoConfig);
        streams[VideoStream]->type = Slave;
        streams[VideoStream]->index = VideoStream;
        streams[VideoStream]->session = this;
        streams[VideoStream]->discriminatorMode = discriminatorMode;
    }
    callId_ = callId;

    isReady = true;

    syncLeave();
    return ret;
}

void zrtp_log(const char *tag, const char *buf);

void CtZrtpSession::setupConfiguration(ZrtpConfigure *conf) {

// Set _WITHOUT_TIVI_ENV to a real name that is TRUE if the Tivi client is compiled/built.
#ifdef _WITHOUT_TIVI_ENV
#define GET_CFG_I(RET,_KEY)
#else
void *findGlobalCfgKey(char *key, int iKeyLen, int &iSize, char **opt, int *type);
#define GET_CFG_I(RET,_KEY) {\
                                int *p = (int*)findGlobalCfgKey((char*)(_KEY), sizeof(_KEY)-1, iSZ, &opt, &type);\
                                if (p && iSZ == 4)                                                               \
                                    (RET) = *p;                                                                  \
                                else                                                                             \
                                    (RET) = -1;                                                                  \
                            }
#endif


// The next three vars are used in case of a real Tivi compile, see macro above.
    int iSZ;
    char *opt;
    int type;

    int b32sas, iDisableDH2K, iDisableAES256, iPreferDH2K;
    int iDisableECDH256, iDisableECDH384, iEnableSHA384;
    int iDisableSkein, iDisableTwofish, iPreferNIST;
    int iDisableSkeinHash, iDisableBernsteinCurve25519, iDisableBernsteinCurve3617;
    int iEnableDisclosure;

    GET_CFG_I(b32sas, "iDisable256SAS")
    GET_CFG_I(iDisableAES256, "iDisableAES256")
    GET_CFG_I(iDisableDH2K, "iDisableDH2K")
    GET_CFG_I(iPreferDH2K, "iPreferDH2K")

    GET_CFG_I(iDisableECDH256, "iDisableECDH256")
    GET_CFG_I(iDisableECDH384, "iDisableECDH384")
    GET_CFG_I(iEnableSHA384, "iEnableSHA384")
    GET_CFG_I(iDisableSkein, "iDisableSkein")
    GET_CFG_I(iDisableTwofish, "iDisableTwofish")
    GET_CFG_I(iPreferNIST, "iPreferNIST")

    GET_CFG_I(iDisableSkeinHash, "iDisableSkeinHash")
    GET_CFG_I(iDisableBernsteinCurve25519, "iDisableBernsteinCurve25519")
    GET_CFG_I(iDisableBernsteinCurve3617, "iDisableBernsteinCurve3617")
    GET_CFG_I(iEnableDisclosure, "iEnableDisclosure")

    setZrtpLogLevel(4);
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
        conf->addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName("SDH1"));

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
    // then put Skein in front oF SHA. Regardless if the Hash is enabled or
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
    auto strm = streams[VideoStream];
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

    auto stream = streams[streamNm];

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
    streams[streamNm]->stopStream();                      // stop and reset stream
}

void CtZrtpSession::setLastPeerNameVerify(const char *name, int iIsMitm) {
    (void) iIsMitm;
    auto stream = streams[AudioStream];

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
    return streams[streamNm]->isSecure();
}

bool CtZrtpSession::processOutoingRtp(uint8_t *buffer, size_t length, size_t *newLength, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return false;

    if (streams[streamNm]->isStopped)
        return false;

    return streams[streamNm]->processOutgoingRtp(buffer, length, newLength);
}

int32_t CtZrtpSession::processIncomingRtp(uint8_t *buffer, size_t length, size_t *newLength, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    if (streams[streamNm]->isStopped)
        return fail;

    return streams[streamNm]->processIncomingRtp(buffer, length, newLength);
}

bool CtZrtpSession::isStarted(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return false;

    return streams[streamNm]->isStarted();
}

bool CtZrtpSession::isEnabled(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return false;

    if (streams[streamNm]->isStopped)
        return false;

    return streams[streamNm]->isEnabled();
}

CtZrtpSession::tiviStatus CtZrtpSession::getCurrentState(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return eWrongStream;

    if (streams[streamNm]->isStopped)
        return eWrongStream;

    return streams[streamNm]->getCurrentState();
}

CtZrtpSession::tiviStatus CtZrtpSession::getPreviousState(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return eWrongStream;

    if (streams[streamNm]->isStopped)
        return eWrongStream;

    return streams[streamNm]->getPreviousState();
}

bool CtZrtpSession::isZrtpEnabled() const {
    return zrtpEnabled;
}

bool CtZrtpSession::isSdesEnabled() const {
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

    if (streams[streamNm]->isStopped)
        return 0;

    return streams[streamNm]->getSignalingHelloHash(helloHash, index);
}

void CtZrtpSession::setSignalingHelloHash(const char *helloHash, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return;

    if (streams[streamNm]->isStopped)
        return;

    streams[streamNm]->setSignalingHelloHash(helloHash);
}

void CtZrtpSession::setVerify(int iVerified) {
    auto stream = streams[AudioStream];

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

    return streams[streamNm]->getInfo(key, (char*)buffer, (int)maxLen);
}

int CtZrtpSession::getNumberOfCountersZrtp(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return -1;

    return streams[streamNm]->getNumberOfCountersZrtp();
}

int CtZrtpSession::getCountersZrtp(int32_t* counters, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return -1;

    return streams[streamNm]->getCountersZrtp(counters);
}


int CtZrtpSession::enrollAccepted(char *p) {
    if (!isReady || streams[AudioStream] == nullptr)
        return fail;

    int ret = streams[AudioStream]->enrollAccepted(p);
    setVerify(true);
    return ret;
}

int CtZrtpSession::enrollDenied() {
    if (!isReady || streams[AudioStream] == nullptr)
        return fail;

    int ret = streams[AudioStream]->enrollDenied();
    setVerify(true);                        // TODO : Janis -> is that correct in this case?
    return ret;
}

void CtZrtpSession::setClientId(std::string id) {
    clientIdString = std::move(id);
}

bool CtZrtpSession::createSdes(char *cryptoString, size_t *maxLen, streamName streamNm, const sdesSuites suite) {

    if (!isReady || !sdesEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    return streams[streamNm]->createSdes(cryptoString, maxLen, static_cast<ZrtpSdesStream::sdesSuites>(suite));
}

bool CtZrtpSession::parseSdes(char *recvCryptoStr, size_t recvLength, char *sendCryptoStr,
                              size_t *sendLength, bool sipInvite, streamName streamNm) {

    if (!isReady || !sdesEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    return streams[streamNm]->parseSdes(recvCryptoStr, recvLength, sendCryptoStr, sendLength, sipInvite);
}

bool CtZrtpSession::getSavedSdes(char *sendCryptoStr, size_t *sendLength, streamName streamNm) {
    if (!isReady || !sdesEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    return streams[streamNm]->getSavedSdes(sendCryptoStr, sendLength);
}

bool CtZrtpSession::isSdesActive(streamName streamNm) {
    if (!isReady || !sdesEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    return streams[streamNm]->isSdesActive();
}

int CtZrtpSession::getCryptoMixAttribute(char *algoNames, size_t length, streamName streamNm) {
    if (!isReady || !sdesEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return 0;

    return streams[streamNm]->getCryptoMixAttribute(algoNames, length);
}

bool CtZrtpSession::setCryptoMixAttribute(const char *algoNames, streamName streamNm) {
    if (!isReady || !sdesEnabled || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return fail;

    return streams[streamNm]->setCryptoMixAttribute(algoNames);
}

void CtZrtpSession::resetSdesContext(streamName streamNm, bool force) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return;

    streams[streamNm]->resetSdesContext(force);
}


int32_t CtZrtpSession::getNumberSupportedVersions(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return 0;
    return CtZrtpStream::getNumberSupportedVersions();
}

const char* CtZrtpSession::getZrtpEncapAttribute(streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return nullptr;

    if (streams[streamNm]->isStopped)
        return nullptr;

    return CtZrtpStream::getZrtpEncapAttribute();
}

void CtZrtpSession::setZrtpEncapAttribute(const char *attribute, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return;

    if (streams[streamNm]->isStopped)
        return;

    streams[streamNm]->setZrtpEncapAttribute(attribute);
}

void CtZrtpSession::setAuxSecret(const unsigned char *secret, int length) {
    if (!isReady || streams[AudioStream] == nullptr)
        return;

    if (streams[AudioStream]->isStopped)
        return;

    streams[AudioStream]->setAuxSecret(secret, length);
}

void CtZrtpSession::setDiscriminatorMode ( bool on ) {
    discriminatorMode = on;
}

bool CtZrtpSession::isDiscriminatorMode() const {
    return discriminatorMode;
}

int32_t CtZrtpSession::getSrtpTraceData(SrtpErrorData* data, streamName streamNm) {
    if (!isReady || !(streamNm >= 0 && streamNm < AllStreams && streams[streamNm] != nullptr))
        return 0;

    return streams[streamNm]->getSrtpTraceData(data);
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