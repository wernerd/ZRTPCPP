#include <crypto/aesCFB.h>
#include <crypto/twoCFB.h>
#include <libzrtpcpp/ZrtpConfigure.h>
#include <libzrtpcpp/ZrtpTextData.h>

AlgorithmEnum::AlgorithmEnum(const AlgoTypes type, const char* name, 
                             int32_t klen, const char* ra, encrypt_t en, 
                             decrypt_t de, SrtpAlgorithms alId):
    algoType(type) , algoName(name), keyLen(klen), readable(ra), encrypt(en),
    decrypt(de), algoId(alId) {
}

AlgorithmEnum::~AlgorithmEnum()
{
}

const char* AlgorithmEnum::getName() {
    return algoName.c_str(); 
}

const char* AlgorithmEnum::getReadable() {
    return readable.c_str();
}
    
int AlgorithmEnum::getKeylen() {
    return keyLen;
}

SrtpAlgorithms AlgorithmEnum::getAlgoId() {
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

static AlgorithmEnum invalidAlgo(Invalid, "", 0, "", NULL, NULL, None);


EnumBase::EnumBase(AlgoTypes a) : algoType(a) {
}

EnumBase::~EnumBase() {}

void EnumBase::insert(const char* name) {
    if (!name)
        return;
    AlgorithmEnum* e = new AlgorithmEnum(algoType, name, 0, "", NULL, NULL, None);
    algos.push_back(e);
}

void EnumBase::insert(const char* name, int32_t klen, const char* ra,
                      encrypt_t enc, decrypt_t dec, SrtpAlgorithms alId) {
    if (!name)
        return;
    AlgorithmEnum* e = new AlgorithmEnum(algoType, name, klen, ra, enc, dec, alId);
    algos.push_back(e);
}

int EnumBase::getSize() {
    return algos.size(); 
}

AlgoTypes EnumBase::getAlgoType() {
    return algoType;
}

AlgorithmEnum& EnumBase::getByName(const char* name) {
    std::vector<AlgorithmEnum* >::iterator b = algos.begin();
    std::vector<AlgorithmEnum* >::iterator e = algos.end();

    for (; b != e; b++) {
        if (strncmp((*b)->getName(), name, 4) == 0) {
            return *(*b);
        }
    }
    return invalidAlgo;
}

AlgorithmEnum& EnumBase::getByOrdinal(int ord) {
    std::vector<AlgorithmEnum* >::iterator b = algos.begin();
    std::vector<AlgorithmEnum* >::iterator e = algos.end();

    for (int i = 0; b != e; ++b) {
        if (i == ord) {
            return *(*b);
        }
        i++;
    }
    return invalidAlgo;
}

int EnumBase::getOrdinal(AlgorithmEnum& algo) {
    std::vector<AlgorithmEnum* >::iterator b = algos.begin();
    std::vector<AlgorithmEnum* >::iterator e = algos.end();

    for (int i = 0; b != e; ++b) {
        if (strncmp((*b)->getName(), algo.getName(), 4) == 0) {
            return i;
        }
        i++;
    }
    return -1;
}

std::list<std::string>* EnumBase::getAllNames() {
    std::vector<AlgorithmEnum* >::iterator b = algos.begin();
    std::vector<AlgorithmEnum* >::iterator e = algos.end();

    std::list<std::string>* strg = new std::list<std::string>();

    for (; b != e; b++) {
        std::string s((*b)->getName());
        strg->push_back(s);
    }
    return strg;
}


/**
 * Set up the enumeration list for available hash algorithms
 */
HashEnum::HashEnum() : EnumBase(HashAlgorithm) {
    insert(s256, 0, "SHA-256", NULL, NULL, None);
    insert(s384, 0, "SHA-384", NULL, NULL, None);
}

HashEnum::~HashEnum() {}

/**
 * Set up the enumeration list for available symmetric cipher algorithms
 */
SymCipherEnum::SymCipherEnum() : EnumBase(CipherAlgorithm) {
    insert(aes3, 32, "AES-256", aesCfbEncrypt, aesCfbDecrypt, Aes);
    insert(aes1, 16, "AES-128", aesCfbEncrypt, aesCfbDecrypt, Aes);
    insert(two3, 32, "Twofish-256", twoCfbEncrypt, twoCfbDecrypt, TwoFish);
    insert(two1, 16, "TwoFish-128", twoCfbEncrypt, twoCfbDecrypt, TwoFish);
}

SymCipherEnum::~SymCipherEnum() {}

/**
 * Set up the enumeration list for available public key algorithms
 */
PubKeyEnum::PubKeyEnum() : EnumBase(PubKeyAlgorithm) {
    insert(dh2k, 0, "DH-2048", NULL, NULL, None);
    insert(ec25, 0, "ECDH-256", NULL, NULL, None);
    insert(dh3k, 0, "DH-3072", NULL, NULL, None);
    insert(ec38, 0, "ECDH-384", NULL, NULL, None);
    insert(mult, 0, "Multi-stream", NULL, NULL, None);
}

PubKeyEnum::~PubKeyEnum() {}

/**
 * Set up the enumeration list for available SAS algorithms
 */
SasTypeEnum::SasTypeEnum() : EnumBase(SasType) {
    insert(b32);
    insert(b256);
}

SasTypeEnum::~SasTypeEnum() {}

/**
 * Set up the enumeration list for available SRTP authentications
 */
AuthLengthEnum::AuthLengthEnum() : EnumBase(AuthLength) {
    insert(hs32, 32, "HMAC-SHA1 32 bit", NULL, NULL, Sha1);
    insert(hs80, 80, "HMAC-SHA1 80 bit", NULL, NULL, Sha1);
    insert(sk32, 32, "Skein-MAC 32 bit", NULL, NULL, Skein);
    insert(sk64, 64, "Skein-MAC 64 bit", NULL, NULL, Skein);
}

AuthLengthEnum::~AuthLengthEnum() {}

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
ZrtpConfigure::ZrtpConfigure() : enableTrustedMitM(false), enableSasSignature(false), enableParanoidMode(false) {}

ZrtpConfigure::~ZrtpConfigure() {}

void ZrtpConfigure::setStandardConfig() {
    clear();

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

int32_t ZrtpConfigure::getNumConfiguredAlgos(AlgoTypes algoType) {

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

    std::vector<AlgorithmEnum* >::iterator b = a.begin();
    std::vector<AlgorithmEnum* >::iterator e = a.end();

    for (int i = 0; b != e; ++b) {
        if (i == index) {
            return *(*b);
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

//    a[index] = &algo;

    if (index >= size) {
        a.push_back(&algo);
        return maxNoOfAlgos - (int)a.size();
    }
    std::vector<AlgorithmEnum* >::iterator b = a.begin();
    std::vector<AlgorithmEnum* >::iterator e = a.end();

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

    std::vector<AlgorithmEnum* >::iterator b = a.begin();
    std::vector<AlgorithmEnum* >::iterator e = a.end();

    for (; b != e; ++b) {
        if (strcmp((*b)->getName(), algo.getName()) == 0) {
            a.erase(b);
            break;
        }
    }
    return (maxNoOfAlgos - (int)a.size());
}

int32_t ZrtpConfigure::getNumConfiguredAlgos(std::vector<AlgorithmEnum* >& a) {
    return (int32_t)a.size();
}

bool ZrtpConfigure::containsAlgo(std::vector<AlgorithmEnum* >& a, AlgorithmEnum& algo) {

    if ((int)a.size() == 0 || !algo.isValid())
        return false;

    std::vector<AlgorithmEnum* >::iterator b = a.begin();
    std::vector<AlgorithmEnum* >::iterator e = a.end();

    for (; b != e; ++b) {
        if (strcmp((*b)->getName(), algo.getName()) == 0) {
            return true;
        }
    }
    return false;
}

void ZrtpConfigure::printConfiguredAlgos(std::vector<AlgorithmEnum* >& a) {

    std::vector<AlgorithmEnum* >::iterator b = a.begin();
    std::vector<AlgorithmEnum* >::iterator e = a.end();

    for (; b != e; ++b) {
        printf("print configured: name: %s\n", (*b)->getName());
    }
}

std::vector<AlgorithmEnum* >& ZrtpConfigure::getEnum(AlgoTypes algoType) {

    switch(algoType) {
        case HashAlgorithm:
            return hashes;
            break;

        case CipherAlgorithm:
            return symCiphers;
            break;

        case PubKeyAlgorithm:
            return publicKeyAlgos;
            break;

        case SasType:
            return sasTypes;
            break;

        case AuthLength:
            return authLengths;
            break;

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

#if 0
ZrtpConfigure config;

main() {
    printf("Start\n");
    printf("size: %d\n", zrtpHashes.getSize());
    AlgorithmEnum e = zrtpHashes.getByName("S256");
    printf("algo name: %s\n", e.getName());
    printf("algo type: %d\n", e.getAlgoType());

    std::list<std::string>* names = zrtpHashes.getAllNames();
    printf("size of name list: %d\n", names->size());
    printf("first name: %s\n", names->front().c_str());
    printf("last name: %s\n", names->back().c_str());

    printf("free slots: %d (expected 6)\n", config.addAlgo(HashAlgorithm, e));

    AlgorithmEnum e1(HashAlgorithm, "SHA384");
    printf("free slots: %d (expected 5)\n", config.addAlgoAt(HashAlgorithm, e1, 0));
    AlgorithmEnum e2 = config.getAlgoAt(HashAlgorithm, 0);
    printf("algo name: %s (expected SHA384)\n", e2.getName());
    printf("Num of configured algos: %d (expected 2)\n", config.getNumConfiguredAlgos(HashAlgorithm));
    config.printConfiguredAlgos(HashAlgorithm);
    printf("free slots: %d (expected 6)\n", config.removeAlgo(HashAlgorithm, e2));
    e2 = config.getAlgoAt(HashAlgorithm, 0);
    printf("algo name: %s (expected SHA256)\n", e2.getName());
    
    printf("clearing config\n");
    config.clear();
    printf("size: %d\n", zrtpHashes.getSize());
    e = zrtpHashes.getByName("S256");
    printf("algo name: %s\n", e.getName());
    printf("algo type: %d\n", e.getAlgoType());

}

#endif
/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
