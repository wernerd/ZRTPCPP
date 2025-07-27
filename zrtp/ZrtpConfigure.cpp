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
#include <cstring>
#include <algorithm>
#include <crypto/aesCFB.h>
#include <crypto/twoCFB.h>
#include <libzrtpcpp/ZrtpConfigure.h>
#include <libzrtpcpp/ZrtpTextData.h>

AlgorithmEnum::AlgorithmEnum(const AlgoTypes type, const char *name,
                             int32_t const klen, const char *ra, encrypt_t const en,
                             decrypt_t const de, NegotiatedAlgorithms const alId) : algoType(type), algoName(name),
    keyLen(klen),
    readable(ra), encrypt(en),
    decrypt(de), algoId(alId) {
}

char const * AlgorithmEnum::getName() const {
    return algoName.c_str();
}

char const * AlgorithmEnum::getReadable() const {
    return readable.c_str();
}

int32_t AlgorithmEnum::getKeylen() const {
    return keyLen;
}

NegotiatedAlgorithms AlgorithmEnum::getAlgoId() const {
    return algoId;
}

encrypt_t AlgorithmEnum::getEncrypt() const {
    return encrypt;
}

decrypt_t AlgorithmEnum::getDecrypt() const {
    return decrypt;
}

AlgoTypes AlgorithmEnum::getAlgoType() const {
    return algoType;
}

bool AlgorithmEnum::isValid() const {
    return algoType != Invalid;
}

static AlgorithmEnum invalidAlgo(Invalid, "", 0, "", nullptr, nullptr, None);


EnumBase::EnumBase(AlgoTypes const algo) : algoType(algo) {
}

EnumBase::~EnumBase() {
    algos.erase(algos.cbegin(), algos.cend());
}

void EnumBase::insert(const char *name) {
    if (!name)
        return;
    auto eU = std::make_unique<AlgorithmEnum>(algoType, name, 0, "", nullptr, nullptr, None);
    algos.emplace_back(std::move(eU));
}

void EnumBase::insert(const char *name, int32_t const klen, const char *ra,
                      encrypt_t const en, decrypt_t const de, NegotiatedAlgorithms const alId) {
    if (!name)
        return;
    auto eU = std::make_unique<AlgorithmEnum>(algoType, name, klen, ra, en, de, alId);
    algos.emplace_back(std::move(eU));
}

size_t EnumBase::getSize() const {
    return algos.size();
}

AlgoTypes EnumBase::getAlgoType() const {
    return algoType;
}

AlgorithmEnum &EnumBase::getByName(const char *name) const {
    for (auto const &b: algos) {
        if (strncmp(b->getName(), name, 4) == 0) {
            return *b;
        }
    }
    return invalidAlgo;
}

AlgorithmEnum &EnumBase::getByOrdinal(int const ord) const {
    int i = 0;
    for (auto const &b: algos) {
        if (i == ord) {
            return *b;
        }
        i++;
    }
    return invalidAlgo;
}

int EnumBase::getOrdinal(AlgorithmEnum const &algo) const {
    int i = 0;
    for (auto const &b: algos) {
        if (strncmp(b->getName(), algo.getName(), 4) == 0) {
            return i;
        }
        i++;
    }
    return -1;
}

std::unique_ptr<std::list<std::string> >
EnumBase::getAllNames() const {
    auto strg = std::make_unique<std::list<std::string> >();

    for (auto const &b: algos) {
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
    insert(mult, 0, "Multi-stream", nullptr, nullptr, None);
#ifdef SUPPORT_NON_NIST
    insert(e255, 0, "Curve 255", nullptr, nullptr, None);
    insert(e414, 0, "Curve 414", nullptr, nullptr, None);
    insert(np06, 0, "SNTRUP 653/Curve 414", nullptr, nullptr, None);
    insert(np09, 0, "SNTRUP 953/Curve 414", nullptr, nullptr, None);
    insert(np12, 0, "SNTRUP 1277/Curve 414", nullptr, nullptr, None);
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
ZrtpConfigure::ZrtpConfigure() : enableTrustedMitM(false), enableSasSignature(false), enableParanoidMode(false),
                                 enableDisclosureFlag(false), selectionPolicy(Standard) {
    setMandatoryOnly();
}

ZrtpConfigure::~ZrtpConfigure() {
    zidCache.reset();
    clear();
}

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

int32_t ZrtpConfigure::addAlgo(AlgoTypes const algoType, AlgorithmEnum &algo) {
    return addAlgo(getEnum(algoType), algo);
}

int32_t ZrtpConfigure::addAlgoAt(AlgoTypes const algoType, AlgorithmEnum &algo, int32_t const index) {
    return addAlgoAt(getEnum(algoType), algo, index);
}

AlgorithmEnum &ZrtpConfigure::getAlgoAt(AlgoTypes const algoType, int32_t const index) {
    return getAlgoAt(getEnum(algoType), index);
}

int32_t ZrtpConfigure::removeAlgo(AlgoTypes const algoType, AlgorithmEnum const &algo) {
    return removeAlgo(getEnum(algoType), algo);
}

uint32_t ZrtpConfigure::getNumConfiguredAlgos(AlgoTypes const algoType) {
    return getNumConfiguredAlgos(getEnum(algoType));
}

bool ZrtpConfigure::containsAlgo(AlgoTypes const algoType, AlgorithmEnum &algo) {
    return containsAlgo(getEnum(algoType), algo);
}

[[maybe_unused]] void ZrtpConfigure::printConfiguredAlgos(AlgoTypes const algoType) {
    printConfiguredAlgos(getEnum(algoType));
}

/*
 * The next methods are the private methods that implement the real
 * details.
 */
AlgorithmEnum &ZrtpConfigure::getAlgoAt(std::vector<AlgorithmEnum *> const &a, int32_t const index) {
    if (index >= static_cast<int32_t>(a.size()))
        return invalidAlgo;

    int i = 0;
    for (auto const algo: a) {
        if (i == index) {
            return *algo;
        }
        i++;
    }
    return invalidAlgo;
}

int32_t ZrtpConfigure::addAlgo(std::vector<AlgorithmEnum *> &a, AlgorithmEnum &algo) {
    int const size = static_cast<int>(a.size());
    if (size >= maxNoOfAlgos)
        return -1;

    if (!algo.isValid())
        return -1;

    if (containsAlgo(a, algo))
        return maxNoOfAlgos - size;

    a.push_back(&algo);
    return maxNoOfAlgos - static_cast<int>(a.size());
}

int32_t ZrtpConfigure::addAlgoAt(std::vector<AlgorithmEnum *> &a, AlgorithmEnum &algo, int32_t const index) {
    if (index >= maxNoOfAlgos)
        return -1;

    int const size = static_cast<int>(a.size());

    if (!algo.isValid())
        return -1;

    if (index >= size) {
        a.push_back(&algo);
        return maxNoOfAlgos - static_cast<int>(a.size());
    }
    auto b = a.begin();
    auto const e = a.end();

    for (int i = 0; b != e; ++b) {
        if (i == index) {
            a.insert(b, &algo);
            break;
        }
        i++;
    }
    return maxNoOfAlgos - static_cast<int>(a.size());
}

int32_t ZrtpConfigure::removeAlgo(std::vector<AlgorithmEnum *> &a, AlgorithmEnum const &algo) {
    if (static_cast<int32_t>(a.size()) == 0 || !algo.isValid())
        return maxNoOfAlgos;

    auto b = a.begin();

    for (auto const e = a.end(); b != e; ++b) {
        if (strcmp((*b)->getName(), algo.getName()) == 0) {
            a.erase(b);
            break;
        }
    }
    return maxNoOfAlgos - static_cast<int>(a.size());
}

uint32_t ZrtpConfigure::getNumConfiguredAlgos(std::vector<AlgorithmEnum *> const &a) {
    return a.size() & 0x7U;
}

bool ZrtpConfigure::containsAlgo(std::vector<AlgorithmEnum *> const &a, AlgorithmEnum &algo) {
    if (a.empty() || !algo.isValid())
        return false;

    return std::any_of(a.cbegin(), a.cend(), [&algo](AlgorithmEnum const *b) {
        return strcmp(b->getName(), algo.getName()) == 0;
    });
}

void ZrtpConfigure::printConfiguredAlgos(std::vector<AlgorithmEnum *> const &a) {
    for (auto const b: a) {
        printf("print configured: name: %s\n", b->getName());
    }
}

std::vector<AlgorithmEnum *> &ZrtpConfigure::getEnum(AlgoTypes const algoType) {
    switch (algoType) {
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

void ZrtpConfigure::setTrustedMitM(bool const yesNo) {
    enableTrustedMitM = yesNo;
}

bool ZrtpConfigure::isTrustedMitM() const {
    return enableTrustedMitM;
}

void ZrtpConfigure::setSasSignature(bool const yesNo) {
    enableSasSignature = yesNo;
}

bool ZrtpConfigure::isSasSignature() const {
    return enableSasSignature;
}

void ZrtpConfigure::setParanoidMode(bool const yesNo) {
    enableParanoidMode = yesNo;
}

bool ZrtpConfigure::isParanoidMode() const {
    return enableParanoidMode;
}

void ZrtpConfigure::setDisclosureFlag(bool const yesNo) {
    enableDisclosureFlag = yesNo;
}

bool ZrtpConfigure::isDisclosureFlag() const {
    return enableDisclosureFlag;
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
