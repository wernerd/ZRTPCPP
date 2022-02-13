/*
 * Copyright 2006 - 2018, Werner Dittmann
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
 */

#include <libzrtpcpp/ZrtpCallback.h>
#include <libzrtpcpp/ZrtpConfigure.h>
#include <libzrtpcpp/ZIDCache.h>
#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpCallbackWrapper.h>
#include <libzrtpcpp/ZrtpCWrapper.h>
#include <libzrtpcpp/ZrtpCrc32.h>
#include <zrtp/libzrtpcpp/ZIDCacheEmpty.h>
#include <zrtp/libzrtpcpp/ZIDCacheFile.h>

#ifdef ZID_DATABASE
#include <zrtp/libzrtpcpp/ZIDCacheDb.h>
#endif

class __EXPORT ZrtpConfigureWrapper: public ZrtpConfigure {
public:
    std::shared_ptr<ZrtpCallback> saveCallback;
};

static std::shared_ptr<ZIDCache>
zrtp_initZidFile(const char* zidFilename, CacheTypes cacheType) {

    auto zf = std::shared_ptr<ZIDCache>();

    switch (cacheType) {
        case NoCache:
            return std::make_shared<ZIDCacheEmpty>();

        case Database:
#ifdef ZID_DATABASE
            zf = std::make_shared<ZIDCacheDb>();
            break;
#else
            return nullptr;
#endif
        case File:
            zf = std::make_shared<ZIDCacheFile>();
            break;
    }

    std::string fname;
    if (!zidFilename) {
        char *home = getenv("HOME");
        std::string baseDir = (home) ? (std::string(home) + std::string("/."))
                                     : std::string(".");
        fname = baseDir + std::string("GNUZRTP.zid");
        zidFilename = fname.c_str();
    }
    if (zf->open((char *)zidFilename) < 0) {
        return std::shared_ptr<ZIDCache>();
    }
    return zf;
}

ZrtpContext* zrtp_CreateWrapper()
{
    auto* zc = new ZrtpContext;
    // Set a raw pointer in wrapper context, never delete this pointer.
    // Functions zrtp_initializeZrtpEngine takes ownership of the raw pointer and manages it
    // with a shared_pointer. Thus only clear the raw pointer in zrtp_DestroyWrapper() below.
    // Kids, don't do this at home ;-)
    zc->configure = new ZrtpConfigureWrapper();
    zc->configure->setStandardConfig();
    zc->zrtpEngine = nullptr;
    zc->userData = nullptr;

    return zc;
}

int32_t zrtp_initializeZrtpEngine(ZrtpContext* zrtpContext,
                                  zrtp_Callbacks *cb, const char* id,
                                  const char* zidFilename,
                                  void* userData,
                                  int32_t mitmMode,
                                  CacheTypes cacheType,
                                  ZrtpContext* copyConfigFrom) {
    std::string clientIdString(id);

    std::shared_ptr<ZrtpConfigure> configOwn;
    std::shared_ptr<ZrtpConfigureWrapper> configOwnWrapper;

    std::shared_ptr<ZrtpCallback> callback = std::make_shared<ZrtpCallbackWrapper>(cb, zrtpContext);
    zrtpContext->userData = userData;

    // don't copy from another context: take over ZrtpConfigure raw pointer,  check and
    // possibly set up ZID cache
    if (!copyConfigFrom) {
        // Take ownership of ZrtpConfigure raw pointer
        configOwnWrapper = std::shared_ptr<ZrtpConfigureWrapper>(zrtpContext->configure);
        configOwnWrapper->setTrustedMitM(mitmMode != 0);

        if (!configOwnWrapper->getZidCache()) {        // ZID Cache not set (shared ZID cache pointer is empty)
            auto zf = zrtp_initZidFile(zidFilename, cacheType);
            if (!zf) {
                return false;
            }
            configOwnWrapper->setZidCache(zf);
        }
    }
    else {
        // **** NOTE:
        // **** Only use ZrtpConfigure of another, existing ZRTP stream which was created with * a ZrtpCWrapper* because
        // **** the ZrtpCWrapper use an extended ZrtpConfigure class to store. Thus ZRtp must also store this extended
        // **** class. The code below relies on this when it down-casts the shared pointer returned from ZRtp.
        // ****
        delete zrtpContext->configure;              // delete initialized configure - we copy it from another context
        configOwn = copyConfigFrom->zrtpEngine->getZrtpConfigure(); // get pointer to ZrtpConfigure from other stream
        configOwnWrapper = std::static_pointer_cast<ZrtpConfigureWrapper>(configOwn);   // *** pay attention -> downcast here ***
        zrtpContext->configure = configOwnWrapper.get();   // set raw pointer in ZrtpContext
    }

    const unsigned char *myZid = configOwnWrapper->getZidCache()->getZid();
    if (!myZid) {
        return false;
    }
    configOwn = configOwnWrapper;           // implicit up-cast to have correct reference to base class
    zrtpContext->zrtpEngine = new ZRtp(clientIdString, callback, configOwn);
    return true;
}

void zrtp_setZidForEmptyCache(ZrtpContext* zrtpContext, uint8_t const * zid) {

    if (zrtpContext && zrtpContext->configure) {
        auto type = zrtpContext->configure->getZidCache()->getCacheType();
        if (type != ZIDCache::NoCache) {
            return;
        }
        zrtpContext->configure->getZidCache()->setZid(zid);
    }
}

void zrtp_DestroyWrapper(ZrtpContext* zrtpContext) {

    if (zrtpContext == nullptr)
        return;

    delete zrtpContext->zrtpEngine;
    zrtpContext->zrtpEngine = nullptr;

    // Don't delete ZrtpConfigure, see comments above.
    zrtpContext->configure = nullptr;

    delete zrtpContext;
}


int32_t zrtp_CheckCksum(uint8_t* buffer, uint16_t temp, uint32_t crc) 
{
    return zrtpCheckCksum(buffer, temp, crc);
}

uint32_t zrtp_GenerateCksum(uint8_t* buffer, uint16_t temp)
{
    return zrtpGenerateCksum(buffer, temp);
}

uint32_t zrtp_EndCksum(uint32_t crc)
{
    return zrtpEndCksum(crc);
}

/*
 * Applications use the following methods to control ZRTP, for example
 * to enable ZRTP, set flags etc.
 */
void zrtp_startZrtpEngine(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->startZrtpEngine();
}

void zrtp_stopZrtpEngine(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->stopZrtp();
}

void zrtp_processZrtpMessage(ZrtpContext* zrtpContext, uint8_t *extHeader, uint32_t peerSSRC, size_t length) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->processZrtpMessage(extHeader, peerSSRC, length);
}

void zrtp_processTimeout(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->processTimeout();
}

//int32_t zrtp_handleGoClear(ZrtpContext* zrtpContext, uint8_t *extHeader)
//{
//    if (zrtpContext && zrtpContext->zrtpEngine)
//        return zrtpContext->zrtpEngine->handleGoClear(extHeader) ? 1 : 0;
//
//    return 0;
//}

void zrtp_setAuxSecret(ZrtpContext* zrtpContext, uint8_t* data, uint32_t length) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->setAuxSecret(data, length);
}

int32_t zrtp_inState(ZrtpContext* zrtpContext, int32_t state) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->inState(state) ? 1 : 0;

    return 0;
}

void zrtp_SASVerified(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->SASVerified();
}

void zrtp_resetSASVerified(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->resetSASVerified();
}

char* zrtp_getHelloHash(ZrtpContext* zrtpContext, int32_t index) {
    std::string ret;
    if (zrtpContext && zrtpContext->zrtpEngine)
        ret = zrtpContext->zrtpEngine->getHelloHash(index);
    else
        return nullptr;

    if (ret.empty())
        return nullptr;

    char* retval = (char*)malloc(ret.size()+1);
    strcpy(retval, ret.c_str());
    return retval;
}

char* zrtp_getPeerHelloHash(ZrtpContext* zrtpContext) {
    std::string ret;
    if (zrtpContext && zrtpContext->zrtpEngine)
        ret = zrtpContext->zrtpEngine->getPeerHelloHash();
    else
        return nullptr;

    if (ret.empty())
        return nullptr;

    char* retval = (char*)malloc(ret.size()+1);
    strcpy(retval, ret.c_str());
    return retval;
}

char* zrtp_getMultiStrParams(ZrtpContext* zrtpContext, int32_t *length) {
    std::string ret;

    *length = 0;
    if (zrtpContext && zrtpContext->zrtpEngine)
        ret = zrtpContext->zrtpEngine->getMultiStrParams(&zrtpContext->zrtpMaster);
    else
        return nullptr;

    if (ret.empty())
        return nullptr;

    *length = ret.size();
    char* retval = (char*) malloc(ret.size());
    ret.copy(retval, ret.size(), 0);
    return retval;
}

void zrtp_setMultiStrParams(ZrtpContext* zrtpContext, char* parameters, int32_t length, ZrtpContext* master) {
    if (!zrtpContext || !zrtpContext->zrtpEngine || !master)
        return;

    if (parameters == nullptr)
        return;

    std::string str;
    str.assign(parameters, length); // set chars (bytes) to the string

    zrtpContext->zrtpEngine->setMultiStrParams(str, master->zrtpMaster);
}

int32_t zrtp_isMultiStream(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->isMultiStream() ? 1 : 0;

    return 0;
}

int32_t zrtp_isMultiStreamAvailable(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->isMultiStreamAvailable() ? 1 : 0;

    return 0;
}

void zrtp_acceptEnrollment(ZrtpContext* zrtpContext, int32_t accepted) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->acceptEnrollment(accepted != 0);
}

int32_t zrtp_isEnrollmentMode(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->isEnrollmentMode() ? 1 : 0;

    return 0;
}

void zrtp_setEnrollmentMode(ZrtpContext* zrtpContext, int32_t enrollmentMode) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->setEnrollmentMode(enrollmentMode != 0);
}

int32_t isPeerEnrolled(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->isPeerEnrolled() ? 1 : 0;

    return 0;
}

int32_t zrtp_sendSASRelayPacket(ZrtpContext* zrtpContext, uint8_t* sh, char* render) {
    if (zrtpContext && zrtpContext->zrtpEngine) {
        std::string rn(render);
        return zrtpContext->zrtpEngine->sendSASRelayPacket(sh, rn) ? 1 : 0;
    }
    return 0;
}


const char* zrtp_getSasType(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine) {
        std::string rn = zrtpContext->zrtpEngine->getSasType();
        if (rn.empty())
            return nullptr;

        char* retval = (char*)malloc(rn.size()+1);
        strcpy(retval, rn.c_str());
        return retval;
    }
    return nullptr;
}


uint8_t const * zrtp_getSasHash(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->getSasHash();

    return nullptr;
}

int32_t zrtp_setSignatureData(ZrtpContext* zrtpContext, uint8_t* data, int32_t length) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->setSignatureData(data, length) ? 1 : 0;

    return 0;
}

uint8_t const * zrtp_getSignatureData(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->getSignatureData();

    return nullptr;
}

int32_t zrtp_getSignatureLength(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->getSignatureLength();

    return 0;
}

void zrtp_conf2AckSecure(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        zrtpContext->zrtpEngine->conf2AckSecure();
}

int32_t zrtp_getPeerZid(ZrtpContext* zrtpContext, uint8_t* data) {
    if (data == nullptr)
        return 0;

    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->getPeerZid(data);

    return 0;
}

int32_t zrtp_getNumberSupportedVersions() {
    return ZRtp::getNumberSupportedVersions();
}

int32_t zrtp_getCurrentProtocolVersion(ZrtpContext* zrtpContext) {
    if (zrtpContext && zrtpContext->zrtpEngine)
        return zrtpContext->zrtpEngine->getCurrentProtocolVersion();
    return -1;
}

static EnumBase* getEnumBase(zrtp_AlgoTypes type)
{
        switch(type) {
        case zrtp_HashAlgorithm:
            return &zrtpHashes;

        case zrtp_CipherAlgorithm:
            return &zrtpSymCiphers;

        case zrtp_PubKeyAlgorithm:
            return &zrtpPubKeys;

        case zrtp_SasType:
            return &zrtpSasTypes;

        case zrtp_AuthLength:
            return &zrtpAuthLengths;

        default:
            return nullptr;
    }
}

char** zrtp_getAlgorithmNames(ZrtpContext* zrtpContext, Zrtp_AlgoTypes type) 
{
    auto* base = getEnumBase(type);

    if (!base)
        return nullptr;

    auto names = base->getAllNames();
    int size = base->getSize();
    char** cNames = new char* [size+1];
    cNames[size] = nullptr;

    int i = 0;
    for (const auto& b : *names) {
        cNames[i] = new char [b.size()+1];
        strcpy(cNames[i], b.c_str());
        ++i;
    }
    return cNames;
}

void zrtp_freeAlgorithmNames(char** names)
{
    if (!names)
        return;
    
    for (char** cp = names; *cp; cp++)
        delete *cp;
    
    delete names;
}

void zrtp_setStandardConfig(ZrtpContext* zrtpContext)
{
    if (zrtpContext && zrtpContext->configure)
        zrtpContext->configure->setStandardConfig();
}

void zrtp_setMandatoryOnly(ZrtpContext* zrtpContext)
{
    if (zrtpContext && zrtpContext->configure)
        zrtpContext->configure->setMandatoryOnly();
}

void zrtp_confClear(ZrtpContext* zrtpContext)
{
    if (zrtpContext && zrtpContext->configure)
        zrtpContext->configure->clear();
}

int32_t zrtp_addAlgo(ZrtpContext* zrtpContext, zrtp_AlgoTypes algoType, const char* algo)
{
    auto* base = getEnumBase(algoType);
    if (base) {
        auto& a = base->getByName(algo);
        if (zrtpContext && zrtpContext->configure)
            return zrtpContext->configure->addAlgo((AlgoTypes)algoType, a);
    }
    return -1;
}

int32_t zrtp_addAlgoAt(ZrtpContext* zrtpContext, zrtp_AlgoTypes algoType, const char* algo, int32_t index)
{
    auto* base = getEnumBase(algoType);
    if (base) {
        auto& a = base->getByName(algo);
        if (zrtpContext && zrtpContext->configure)
            return zrtpContext->configure->addAlgoAt((AlgoTypes)algoType, a, index);
    }
    return -1;
}

int32_t zrtp_removeAlgo(ZrtpContext* zrtpContext, zrtp_AlgoTypes algoType, const char* algo)
{
    auto* base = getEnumBase(algoType);
    if (base) {
        auto& a = base->getByName(algo);
        if (zrtpContext && zrtpContext->configure)
            return zrtpContext->configure->removeAlgo((AlgoTypes)algoType, a);
    }
    return -1;
}

int32_t zrtp_getNumConfiguredAlgos(ZrtpContext* zrtpContext, zrtp_AlgoTypes algoType)
{
    if (zrtpContext && zrtpContext->configure)
        return zrtpContext->configure->getNumConfiguredAlgos((AlgoTypes)algoType);
    return -1;
}

const char* zrtp_getAlgoAt(ZrtpContext* zrtpContext, Zrtp_AlgoTypes algoType, int32_t index)
{
    if (zrtpContext && zrtpContext->configure) {
        auto& a = zrtpContext->configure->getAlgoAt((AlgoTypes)algoType, index);
       return a.getName();
    }
    return nullptr;
}

int32_t zrtp_containsAlgo(ZrtpContext* zrtpContext, Zrtp_AlgoTypes algoType, const char*  algo)
{
    auto* base = getEnumBase(algoType);
    if (base) {
        auto& a = base->getByName(algo);
        if (zrtpContext && zrtpContext->configure)
            return zrtpContext->configure->containsAlgo((AlgoTypes)algoType, a) ? 1 : 0;
    }
    return 0;
}

void zrtp_setTrustedMitM(ZrtpContext* zrtpContext, int32_t yesNo)
{
    if (zrtpContext && zrtpContext->configure)
        zrtpContext->configure->setTrustedMitM(yesNo != 0);
}

int32_t zrtp_isTrustedMitM(ZrtpContext* zrtpContext)
{
    if (zrtpContext && zrtpContext->configure)
        return zrtpContext->configure->isTrustedMitM() ? 1 : 0;
    return 0;        /* standard setting: trustedMitM is false, thus if zrtp not initialized it's always false */
}

void zrtp_setSasSignature(ZrtpContext* zrtpContext, int32_t yesNo)
{
    if (zrtpContext && zrtpContext->configure)
        zrtpContext->configure->setSasSignature(yesNo != 0);
}

int32_t zrtp_isSasSignature(ZrtpContext* zrtpContext)
{
    if (zrtpContext && zrtpContext->configure)
        return zrtpContext->configure->isSasSignature() ? 1 : 0;
    return 0;       /* standard setting: sasSignature is false, thus if zrtp not initialized it's always false */
}
