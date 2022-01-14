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

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <crypto/aesCFB.h>
#include <crypto/twoCFB.h>
#include <libzrtpcpp/ZrtpConfigure.h>
#include <libzrtpcpp/ZrtpTextData.h>

AlgorithmEnum::AlgorithmEnum(const AlgoTypes type, const char* name,
                             uint32_t klen, const char* ra, encrypt_t en,
                             decrypt_t de, NegotiatedAlgorithms alId):
    algoType(type) , algoName(name), keyLen(klen), readable(ra), encrypt(en),
    decrypt(de), algoId(alId) {
}

const char* AlgorithmEnum::getName() {
    return algoName.c_str(); 
}

const char* AlgorithmEnum::getReadable() {
    return readable.c_str();
}
    
uint32_t AlgorithmEnum::getKeylen() {
    return keyLen;
}

NegotiatedAlgorithms AlgorithmEnum::getAlgoId() {
    return algoId;
}

encrypt_t AlgorithmEnum::getEncrypt() {
    return encrypt;
}

decrypt_t AlgorithmEnum::getDecrypt() {
    return decrypt;
}

AlgoTypes AlgorithmEnum::getAlgoType() { 
    return algoType; 
}

bool AlgorithmEnum::isValid() {
    return (algoType != Invalid); 
}

static AlgorithmEnum invalidAlgo(Invalid, "", 0, "", nullptr, nullptr, None);


EnumBase::EnumBase(AlgoTypes a) : algoType(a) {}

EnumBase::~EnumBase() {
    for (auto b : algos) {
        delete b;
    }
}

void EnumBase::insert(const char* name) {
    if (!name)
        return;
    auto* e = new AlgorithmEnum(algoType, name, 0, "", nullptr, nullptr, None);
    algos.push_back(e);
}

void EnumBase::insert(const char* name, uint32_t klen, const char* ra,
                      encrypt_t enc, decrypt_t dec, NegotiatedAlgorithms alId) {
    if (!name)
        return;
    auto* e = new AlgorithmEnum(algoType, name, klen, ra, enc, dec, alId);
    algos.push_back(e);
}

size_t EnumBase::getSize() {
    return algos.size(); 
}

AlgoTypes EnumBase::getAlgoType() {
    return algoType;
}

AlgorithmEnum& EnumBase::getByName(const char* name) {
    for (auto b : algos) {
        if (strncmp(b->getName(), name, 4) == 0) {
            return *b;
        }
    }
    return invalidAlgo;
}

AlgorithmEnum& EnumBase::getByOrdinal(int ord) {
    int i = 0;
    for (auto b : algos) {
        if (i == ord) {
            return *b;
        }
        i++;
    }
    return invalidAlgo;
}

int EnumBase::getOrdinal(AlgorithmEnum& algo) {
    int i = 0;
    for (auto b : algos) {
        if (strncmp(b->getName(), algo.getName(), 4) == 0) {
            return i;
        }
        i++;
    }
    return -1;
}

std::unique_ptr<std::list<std::string>>
EnumBase::getAllNames() {
    auto strg = std::make_unique<std::list<std::string>>();

    for (auto b : algos) {
        std::string s(b->getName());
        strg->push_back(s);
    }
    return strg;
}


/**
 * Set up the enumeration list for available hash algorithms
 */
HashEnum::HashEnum() : EnumBase(HashAlgorithm) {
    insert(s256, 0, "SHA-256", nullptr, nullptr, None);
    insert(s384, 0, "SHA-384", nullptr, nullptr, None);
    insert(skn2, 0, "Skein-256", nullptr, nullptr, None);
    insert(skn3, 0, "Skein-384", nullptr, nullptr, None);
}

/**
 * Set up the enumeration list for available symmetric cipher algorithms
 */
SymCipherEnum::SymCipherEnum() : EnumBase(CipherAlgorithm) {
    insert(aes3, 32, "AES-256", aesCfbEncrypt, aesCfbDecrypt, Aes);
    insert(aes1, 16, "AES-128", aesCfbEncrypt, aesCfbDecrypt, Aes);
    insert(two3, 32, "Twofish-256", twoCfbEncrypt, twoCfbDecrypt, TwoFish);
    insert(two1, 16, "TwoFish-128", twoCfbEncrypt, twoCfbDecrypt, TwoFish);
}

/**
 * Set up the enumeration list for available public key algorithms
 */
PubKeyEnum::PubKeyEnum() : EnumBase(PubKeyAlgorithm) {
    insert(dh2k, 0, "DH-2048", nullptr, nullptr, None);
    insert(ec25, 0, "NIST ECDH-256", nullptr, nullptr, None);
    insert(dh3k, 0, "DH-3072", nullptr, nullptr, None);
    insert(ec38, 0, "NIST ECDH-384", nullptr, nullptr, None);
    insert(mult, 0, "Multi-stream",  nullptr, nullptr, None);
#ifdef SUPPORT_NON_NIST
    insert(e255, 0, "Curve 255", nullptr, nullptr, None);
    insert(e414, 0, "Curve 414", nullptr, nullptr, None);
#ifdef SIDH_SUPPORT
    insert(sdh5, 0, "SIDHp503", nullptr, nullptr, None);
    insert(sdh7, 0, "SIDHp751", nullptr, nullptr, None);
    insert(pq54, 0, "SIDHp503/Curve 414", nullptr, nullptr, None);
    insert(pq64, 0, "SIDHp610/Curve 414", nullptr, nullptr, None);
#endif
#endif
}

/**
 * Set up the enumeration list for available SAS algorithms
 */
SasTypeEnum::SasTypeEnum() : EnumBase(SasType) {
    insert(b32);
    insert(b256);
    insert(b32e);
    insert(b10d);
}

/**
 * Set up the enumeration list for available SRTP authentications
 */
AuthLengthEnum::AuthLengthEnum() : EnumBase(AuthLength) {
    insert(hs32, 32, "HMAC-SHA1 32 bit", nullptr, nullptr, Sha1);
    insert(hs80, 80, "HMAC-SHA1 80 bit", nullptr, nullptr, Sha1);
    insert(sk32, 32, "Skein-MAC 32 bit", nullptr, nullptr, Skein);
    insert(sk64, 64, "Skein-MAC 64 bit", nullptr, nullptr, Skein);
}

/*
 * Here the global accessible enumerations for all implemented algorithms.
 */
HashEnum zrtpHashes;
SymCipherEnum zrtpSymCiphers;
PubKeyEnum zrtpPubKeys;
SasTypeEnum zrtpSasTypes;
AuthLengthEnum zrtpAuthLengths;

/*
 * The public methods are mainly a facade to the private methods.
 */
ZrtpConfigure::ZrtpConfigure(): enableTrustedMitM(false), enableSasSignature(false), enableParanoidMode(false),
                                enableDisclosureFlag(false), selectionPolicy(Standard)
{
    setMandatoryOnly();
}

ZrtpConfigure::~ZrtpConfigure() = default;

void ZrtpConfigure::setStandardConfig() {
    clear();
    addStandardConfig();
}
void ZrtpConfigure::addStandardConfig() {
    addAlgo(HashAlgorithm, zrtpHashes.getByName(s384));
    addAlgo(HashAlgorithm, zrtpHashes.getByName(s256));

    addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName(two3));
    addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName(aes3));
    addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName(two1));
    addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName(aes1));

    addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName(ec25));
    addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName(dh3k));
    addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName(ec38));
    addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName(dh2k));
    addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName(mult));

    addAlgo(SasType, zrtpSasTypes.getByName(b32));

    addAlgo(AuthLength, zrtpAuthLengths.getByName(sk32));
    addAlgo(AuthLength, zrtpAuthLengths.getByName(sk64));
    addAlgo(AuthLength, zrtpAuthLengths.getByName(hs32));
    addAlgo(AuthLength, zrtpAuthLengths.getByName(hs80));
}

void ZrtpConfigure::setMandatoryOnly() {
    clear();
    addMandatoryOnly();
}

void ZrtpConfigure::addMandatoryOnly() {
    addAlgo(HashAlgorithm, zrtpHashes.getByName(s256));

    addAlgo(CipherAlgorithm, zrtpSymCiphers.getByName(aes1));

    addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName(dh3k));
    addAlgo(PubKeyAlgorithm, zrtpPubKeys.getByName(mult));

    addAlgo(SasType, zrtpSasTypes.getByName(b32));

    addAlgo(AuthLength, zrtpAuthLengths.getByName(hs32));
    addAlgo(AuthLength, zrtpAuthLengths.getByName(hs80));
}

void ZrtpConfigure::clear() {
    hashes.clear();
    symCiphers.clear();
    publicKeyAlgos.clear();
    sasTypes.clear();
    authLengths.clear();
}

int32_t ZrtpConfigure::addAlgo(AlgoTypes algoType, AlgorithmEnum& algo) {

    return addAlgo(getEnum(algoType), algo);
}

int32_t ZrtpConfigure::addAlgoAt(AlgoTypes algoType, AlgorithmEnum& algo, int32_t index) {

    return addAlgoAt(getEnum(algoType), algo, index);
}

AlgorithmEnum& ZrtpConfigure::getAlgoAt(AlgoTypes algoType, int32_t index) {

    return getAlgoAt(getEnum(algoType), index);
}

int32_t ZrtpConfigure::removeAlgo(AlgoTypes algoType, AlgorithmEnum& algo) {

    return removeAlgo(getEnum(algoType), algo);
}

uint32_t ZrtpConfigure::getNumConfiguredAlgos(AlgoTypes algoType) {

    return getNumConfiguredAlgos(getEnum(algoType));
}

bool ZrtpConfigure::containsAlgo(AlgoTypes algoType, AlgorithmEnum& algo) {

    return containsAlgo(getEnum(algoType), algo);
}

void ZrtpConfigure::printConfiguredAlgos(AlgoTypes algoType) {

    printConfiguredAlgos(getEnum(algoType));
}

/*
 * The next methods are the private methods that implement the real
 * details.
 */
AlgorithmEnum& ZrtpConfigure::getAlgoAt(std::vector<AlgorithmEnum* >& a, int32_t index) {

    if (index >= (int)a.size())
        return invalidAlgo;

    int i = 0;
    for (auto algo : a) {
        if (i == index) {
            return *algo;
        }
        i++;
    }
    return invalidAlgo;
}

int32_t ZrtpConfigure::addAlgo(std::vector<AlgorithmEnum* >& a, AlgorithmEnum& algo) {
    int size = (int)a.size();
    if (size >= maxNoOfAlgos)
        return -1;

    if (!algo.isValid())
        return -1;

    if (containsAlgo(a, algo))
        return (maxNoOfAlgos - size);

    a.push_back(&algo);
    return (maxNoOfAlgos - (int)a.size());
}

int32_t ZrtpConfigure::addAlgoAt(std::vector<AlgorithmEnum* >& a, AlgorithmEnum& algo, int32_t index) {
    if (index >= maxNoOfAlgos)
        return -1;

    int size = (int)a.size();

    if (!algo.isValid())
        return -1;

    if (index >= size) {
        a.push_back(&algo);
        return maxNoOfAlgos - (int)a.size();
    }
    auto b = a.begin();
    auto e = a.end();

    for (int i = 0; b != e; ++b) {
        if (i == index) {
            a.insert(b, &algo);
            break;
        }
        i++;
    }
    return (maxNoOfAlgos - (int)a.size());
}

int32_t ZrtpConfigure::removeAlgo(std::vector<AlgorithmEnum* >& a, AlgorithmEnum& algo) {

    if ((int)a.size() == 0 || !algo.isValid())
        return maxNoOfAlgos;

    auto b = a.begin();
    auto e = a.end();

    for (; b != e; ++b) {
        if (strcmp((*b)->getName(), algo.getName()) == 0) {
            a.erase(b);
            break;
        }
    }
    return (maxNoOfAlgos - (int)a.size());
}

uint32_t ZrtpConfigure::getNumConfiguredAlgos(std::vector<AlgorithmEnum* >& a) {
    return a.size() & 0x7U;
}

bool ZrtpConfigure::containsAlgo(std::vector<AlgorithmEnum* >& a, AlgorithmEnum& algo) {

    if ((int)a.size() == 0 || !algo.isValid())
        return false;

    for (auto b : a) {
        if (strcmp(b->getName(), algo.getName()) == 0) {
            return true;
        }
    }
    return false;
}

void ZrtpConfigure::printConfiguredAlgos(std::vector<AlgorithmEnum* >& a) {
    for (auto b : a) {
        printf("print configured: name: %s\n", b->getName());
    }
}

std::vector<AlgorithmEnum* >& ZrtpConfigure::getEnum(AlgoTypes algoType) {

    switch(algoType) {
        case HashAlgorithm:
            return hashes;

        case CipherAlgorithm:
            return symCiphers;

        case PubKeyAlgorithm:
            return publicKeyAlgos;

        case SasType:
            return sasTypes;

        case AuthLength:
            return authLengths;

        default:
            break;
    }
    return hashes;
}

void ZrtpConfigure::setTrustedMitM(bool yesNo) {
    enableTrustedMitM = yesNo;
}

bool ZrtpConfigure::isTrustedMitM() {
    return enableTrustedMitM;
}

void ZrtpConfigure::setSasSignature(bool yesNo) {
    enableSasSignature = yesNo;
}

bool ZrtpConfigure::isSasSignature() {
    return enableSasSignature;
}

void ZrtpConfigure::setParanoidMode(bool yesNo) {
    enableParanoidMode = yesNo;
}

bool ZrtpConfigure::isParanoidMode() {
    return enableParanoidMode;
}

void ZrtpConfigure::setDisclosureFlag(bool yesNo) {
    enableDisclosureFlag = yesNo;
}

bool ZrtpConfigure::isDisclosureFlag() {
    return enableDisclosureFlag;
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
