#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <sstream>

#include <libzrtpcpp/ZrtpSdesStream.h>
#include <libzrtpcpp/ZrtpTextData.h>
#include <libzrtpcpp/ZrtpConfigure.h>
#include <libzrtpcpp/zrtpB64Decode.h>
#include <libzrtpcpp/zrtpB64Encode.h>
#include <srtp/SrtpHandler.h>
#include <srtp/CryptoContext.h>
#include <srtp/CryptoContextCtrl.h>
#include <cryptcommon/ZrtpRandom.h>
#include <crypto/hmac384.h>


#if defined(_WIN32) || defined(_WIN64)
# define snprintf _snprintf
#endif

/*
 * The ABNF grammar for the crypto attribute is defined below (from RFC 4568):
 *
 *  "a=crypto:" tag 1*WSP crypto-suite 1*WSP key-params *(1*WSP session-param)
 *
 *  tag              = 1*9DIGIT
 */

/*
 * Buffer size for names and other strings inside the crypto string. The parse
 * format below restricts parsing to 99 char to provide space for the @c nul byte.
 */
#define MAX_INNER_LEN 100

/*
 * This format scans a received SDES crypto attribute string according to the
 * grammer shown above but without a "a=crypto:" prefix.
 *
 * The format string parses:
 * - %d - the tag as decimal value
 * - %s - the crypto suite name, limited to 99 chars (see MAX_INNER_LEN)
 * - %s - the key parameters, limited to 99 chars
 * - %n - the number of parsed characters to far. The pointer to the session
 *   parameters is: cryptoString + numParsedChars.
 */
static const char parseCrypto[] = "%d %99s %99s %n";

static const int64_t maxTagValue = 999999999;

static const int minElementsCrypto = 3;

/*
 * The ABNF grammar for the key-param (from RFC 4568):
 *
 *  key-param        = key-method ":" key-info
 *
 * The SRTP specific definitions:
 *
 *  key-method          = srtp-key-method
 *  key-info            = srtp-key-info
 *
 *  srtp-key-method     = "inline"
 *  srtp-key-info       = key-salt ["|" lifetime] ["|" mki]
 *
 */

/*
 * This format parses the key parameter string which is never longer than
 * 99 chars (see parse string above):
 * - the fixed string "inline:"
 * - %[A-Za-z0-9+/=] - base 64 characters of master key||master salt
 * - the fixed separator character '|'
 * - %[0-9^] - the lifetime infomration as string that contains digits and ^
 * - the fixed separator character '|'
 * - %[0-9]:%d - parses and strore MKI value and MKI length, separated by ':'
 *
 * If the key parameter string does not contain the operional fields lifetime
 * and MKI information the respective parameters are not filled.
 */
static const char parseKeyParam[] = " inline:%[A-Za-z0-9+/=]|%[0-9^]|%[0-9]:%d";

static const int minElementsKeyParam = 1;

static const int32_t NONE = 0;
static const int32_t HMAC_SHA = 1;
static const int32_t SKEIN = 2;

typedef struct _cryptoMix {
    const char* name;
    int32_t hashLength;
    int32_t hashType;
} cryptoMix;

static cryptoMix knownMixAlgos[] = {
    {"HMAC-SHA-384", 384, HMAC_SHA},
    {NULL, 0, 0}
};

typedef struct _suite {
    ZrtpSdesStream::sdesSuites suite;
    const char *name;
    int32_t    keyLength;             // key length in bits
    int32_t    saltLength;            // salt lenght in bits
    int32_t    authKeyLength;         // authentication key length in bits
    const char *tagLength;            // tag type hs80 or hs32
    const char *cipher;               // aes1 or aes3
    uint32_t   b64length;             // length of b64 encoded key/saltstring
    uint64_t   defaultSrtpLifetime;   // key lifetimes in number of packets
    uint64_t   defaultSrtcpLifetime;
} suiteParam;

/* NOTE: the b64len of a 128 bit suite is 40, a 256bit suite uses 64 characters */
static suiteParam knownSuites[] = {
    {ZrtpSdesStream::AES_CM_128_HMAC_SHA1_32, "AES_CM_128_HMAC_SHA1_32", 128, 112, 160,
     hs32, "AES-128", 40, (uint64_t)1<<48, (uint64_t)1<<31
    },
    {ZrtpSdesStream::AES_CM_128_HMAC_SHA1_80, "AES_CM_128_HMAC_SHA1_80", 128, 112, 160,
     hs80, "AES-128", 40, (uint64_t)1<<48, (uint64_t)1<<31
    },
    {(ZrtpSdesStream::sdesSuites)0, NULL, 0, 0, 0, 0, 0, 0, 0, 0}
};

ZrtpSdesStream::ZrtpSdesStream(const sdesSuites s) :
    state(STREAM_INITALIZED), suite(s), recvSrtp(NULL), recvSrtcp(NULL), sendSrtp(NULL),
    sendSrtcp(NULL), srtcpIndex(0), cryptoMixHashLength(0), cryptoMixHashType(NONE)  {
}

ZrtpSdesStream::~ZrtpSdesStream() {
    close();
}

void ZrtpSdesStream::close() {
    delete sendSrtp;
    sendSrtp = NULL;

    delete recvSrtp;
    recvSrtp = NULL;

    delete sendSrtcp;
    sendSrtp = NULL;

    delete recvSrtcp;
    recvSrtp = NULL;
}

bool ZrtpSdesStream::createSdes(char *cryptoString, size_t *maxLen, bool sipInvite) {

    if (sipInvite) {
        if (state != STREAM_INITALIZED)
            return false;
        tag = 1;
    }
    else {
        if (state != IN_PROFILE_READY)
            return false;
    }

    bool s = createSdesProfile(cryptoString, maxLen);
    if (!s)
        return s;

    if (sipInvite) {
        state = OUT_PROFILE_READY;
    }
    else {
        createSrtpContexts(sipInvite);
        state = SDES_SRTP_ACTIVE;
    }
    return s;

}

bool ZrtpSdesStream::parseSdes(char *cryptoString, size_t length, bool sipInvite) {

    if (sipInvite) {
        if (state != OUT_PROFILE_READY)
            return false;
    }
    else {
        if (state != STREAM_INITALIZED)
            return false;
    }
    sdesSuites tmpSuite;
    int32_t tmpTag;

    bool s = parseCreateSdesProfile(cryptoString, length, &tmpSuite, &tmpTag);
    if (!s)
        return s;

    if (sipInvite) {
        // Check if answerer used same tag and suite as the offerer
        if (tmpTag != tag || suite != tmpSuite)
            return false;
        createSrtpContexts(sipInvite);
        state = SDES_SRTP_ACTIVE;
    }
    else {
        // Answerer stores tag and suite and uses it in createSdesProfile
        suite = tmpSuite;
        tag = tmpTag;
        state = IN_PROFILE_READY;
    }
    return s;
}

bool ZrtpSdesStream::outgoingRtp(uint8_t *packet, size_t length, size_t *newLength) {

    if (state != SDES_SRTP_ACTIVE || sendSrtp == NULL) {
        *newLength = length;
        return true;
    }
    bool rc = SrtpHandler::protect(sendSrtp, packet, length, newLength);
    if (rc)
        ;//protect++;
    return rc;
}

int ZrtpSdesStream::incomingRtp(uint8_t *packet, size_t length, size_t *newLength) {
    if (state != SDES_SRTP_ACTIVE || recvSrtp == NULL) {    // SRTP inactive, just return with newLength set
        *newLength = length;
        return 1;
    }
    int32_t rc = SrtpHandler::unprotect(recvSrtp, packet, length, newLength);
    if (rc == 1) {
//            unprotect++
    }
    else {
//            unprotectFailed++;
    }
    return rc;
}

bool ZrtpSdesStream::outgoingRtcp(uint8_t *packet, size_t length, size_t *newLength) {
#if 0
SrtpHandler::protectCtrl(CryptoContextCtrl* pcc, uint8_t* buffer, size_t length, size_t* newLength, uint32_t *srtcpIndex)
#endif
    return false;
}

int ZrtpSdesStream::incomingSrtcp(uint8_t *packet, size_t length, size_t *newLength) {
#if 0
int32_t SrtpHandler::unprotectCtrl(CryptoContextCtrl* pcc, uint8_t* buffer, size_t length, size_t* newLength)
#endif
    return 0;
}

const char* ZrtpSdesStream::getCipher() {
    return knownSuites[suite].cipher;
}

const char* ZrtpSdesStream::getAuthAlgo() {
    if (strcmp(knownSuites[suite].tagLength, hs80) == 0)
        return "HMAC-SHA1 80 bit";
    else
        return "HMAC-SHA1 32 bit";
}

int ZrtpSdesStream::getCryptoMixAttribute(char *algoNames, size_t length) {

    size_t len = strlen(knownMixAlgos[0].name);
    if (length < len+1)
        return 0;

    // In case we support more than one MIX profile select the correct one if the
    // application called setCryptoMixAttribute(...) and we selected one to use.
    const char* name = NULL;
    if (cryptoMixHashType != NONE) {
        for (cryptoMix* cp = knownMixAlgos; cp->name != NULL; cp++) {
            fprintf(stderr, "name0: %s\n", cp->name);
            if (cp->hashLength == cryptoMixHashLength && cp->hashType == cryptoMixHashType) {
                name = cp->name;
                break;
            }
        }
    }
    else
        name = knownMixAlgos[0].name;

    // TODO: enhance here to support multiple algorithms (concatenate string into the buffer until buffer full)
    if (name == NULL)
        return 0;

    strcpy(algoNames, name);
    return len;
}

bool ZrtpSdesStream::setCryptoMixAttribute(char *algoNames) {

    int len = strlen(algoNames);
    if (len <= 0)
        return false;

    std::string algoIn(algoNames);
    algoIn += ' ';

    // split input name string and lookup if we support one of the offered algorithms
    // We take the first match.
    std::string delimiters = " ";
    size_t current;
    size_t next = -1;
    cryptoMix* mix = NULL;

    do {
        current = next + 1;
        next = algoIn.find_first_of(delimiters, current);
        if (next == std::string::npos)
            break;

        const char* nm = algoIn.substr(current, next - current ).c_str();

        for (cryptoMix* cp = knownMixAlgos; cp->name != NULL; cp++) {
            if (strcmp(cp->name, nm) == 0) {
                mix = cp;
                break;
            }
        }
    }
    while (true);

    if (mix == NULL)
        return false;

    cryptoMixHashLength = mix->hashLength;
    cryptoMixHashType = mix->hashType;
    return true;
}

#ifdef WEAKRANDOM
/*
 * A standard random number generator that uses the portable random() system function.
 *
 * This should be enhanced to use a better random generator
 */
static int _random(unsigned char *output, size_t len)
{
    size_t i;

    for(i = 0; i < len; ++i )
        output[i] = random();

    return( 0 );
}
#else
#include <cryptcommon/ZrtpRandom.h>
static int _random(unsigned char *output, size_t len)
{
    return ZrtpRandom::getRandomData(output, len);
}
#endif

static int b64Encode(const uint8_t *binData, int32_t binLength, char *b64Data, int32_t b64Length)
{
    base64_encodestate _state;
    int codelength;

    base64_init_encodestate(&_state, 0);
    codelength = base64_encode_block(binData, binLength, b64Data, &_state);
    codelength += base64_encode_blockend(b64Data+codelength, &_state);

    return codelength;
}

static int b64Decode(const char *b64Data, int32_t b64length, uint8_t *binData, int32_t binLength)
{
    base64_decodestate _state;
    int codelength;

    base64_init_decodestate(&_state);
    codelength = base64_decode_block(b64Data, b64length, binData, &_state);
    return codelength;
}

void* createSha384HmacContext(uint8_t* key, int32_t keyLength);
void freeSha384HmacContext(void* ctx);
void hmacSha384Ctx(void* ctx, const uint8_t* data[], uint32_t dataLength[], uint8_t* mac, int32_t* macLength );

static int expand(uint8_t* prk, uint32_t prkLen, uint8_t* info, int32_t infoLen, int32_t L, uint32_t hashLen, uint8_t* outbuffer)
{
    int32_t n;
    uint8_t *T;
    void* hmacCtx;

    const uint8_t* data[4];      // 3 data pointers for HMAC data plus terminating NULL
    uint32_t dataLen[4];
    int32_t dataIdx = 0;

    uint8_t counter;
    int32_t macLength;

    if (prkLen < hashLen)
        return -1;

    n = (L + (hashLen-1)) / hashLen;

    // T points to buffer that holds concatenated T(1) || T(2) || ... T(N))
    T = reinterpret_cast<uint8_t*>(malloc(n * hashLen));

    // Prepare the HMAC
    if (hashLen == 384/8)
        hmacCtx = createSha384HmacContext(prk, prkLen);
    else
        return -1;

    // Prepare first HMAC. T(0) has zero length, thus we ignore it in first run.
    // After first run use its output (T(1)) as first data in next HMAC run.
    for (int i = 1; i <= n; i++) {
        if (infoLen > 0 && info != NULL) {
            data[dataIdx] = info;
            dataLen[dataIdx++] = infoLen;
        }
        counter = i & 0xff;
        data[dataIdx] = &counter;
        dataLen[dataIdx++] = 1;

        data[dataIdx] = NULL;
        dataLen[dataIdx++] = 0;

        if (hashLen == 384/8)
            hmacSha384Ctx(hmacCtx, data, dataLen, T + ((i-1) * hashLen), &macLength);

        // Use output of previous hash run as first input of next hash run
        dataIdx = 0;
        data[dataIdx] = T + ((i-1) * hashLen);
        dataLen[dataIdx++] = hashLen;
    }
    freeSha384HmacContext(hmacCtx);
    memcpy(outbuffer, T, L);
    free(T);
    return 0;
}

void ZrtpSdesStream::computeMixedKeys(bool sipInvite) {
    uint8_t salt[MAX_SALT_LEN*2];
    uint8_t ikm[MAX_KEY_LEN*2];

    // Concatenate the existing salt and key data. Depending on our role we have to change
    // the order of the data.
    if (sipInvite) {             // We are offerer, use local created data as mso and mko, so they go first
        memcpy(salt, &localKeySalt[localKeyLenBytes], localSaltLenBytes);
        memcpy(&salt[localSaltLenBytes], &remoteKeySalt[remoteKeyLenBytes], remoteSaltLenBytes);

        memcpy(ikm, localKeySalt, localKeyLenBytes);
        memcpy(&ikm[localKeyLenBytes], remoteKeySalt, remoteKeyLenBytes);
    }
    else {
        memcpy(salt, &remoteKeySalt[remoteKeyLenBytes], remoteSaltLenBytes);
        memcpy(&salt[remoteSaltLenBytes], &localKeySalt[localKeyLenBytes], localSaltLenBytes);

        memcpy(ikm, remoteKeySalt, remoteKeyLenBytes);
        memcpy(&ikm[remoteKeyLenBytes], localKeySalt, localKeyLenBytes);
    }
    uint32_t saltLen = localSaltLenBytes + remoteSaltLenBytes;
    uint32_t keyLen = localKeyLenBytes + remoteKeyLenBytes;
    uint32_t L = saltLen + keyLen;

    uint8_t prk[MAX_DIGEST_LENGTH];
    uint32_t prkLen;

    switch(cryptoMixHashType) {
        case HMAC_SHA:
            if (cryptoMixHashLength == 384)
                hmac_sha384(salt, saltLen, ikm, keyLen, prk, &prkLen);
            else
                return;
            break;

        case SKEIN:
            return;
    }

    uint8_t T[(MAX_SALT_LEN + MAX_KEY_LEN)*2];
    expand(prk, prkLen, NULL, 0, L, cryptoMixHashLength/8, T);

    // We have a new set of SRTP key data now, replace the old with the new.
    int32_t offset = 0;
    if (sipInvite) {    // We are offerer, replace local created data with mso and mko, remote with msa, mka
        memcpy(&localKeySalt[localKeyLenBytes], T, localSaltLenBytes);
        offset += localSaltLenBytes;
        memcpy(&remoteKeySalt[remoteKeyLenBytes], &T[offset], remoteSaltLenBytes);
        offset += remoteSaltLenBytes;

        memcpy(localKeySalt, &T[offset], localKeyLenBytes);
        offset += localKeyLenBytes;
        memcpy(remoteKeySalt, &T[offset], remoteKeyLenBytes);
    }
    else {            // We are answerer, replace remote data with mso and mko, local data with msa, mka
        memcpy(&remoteKeySalt[remoteKeyLenBytes], T, remoteSaltLenBytes);
        offset += remoteSaltLenBytes;
        memcpy(&localKeySalt[localKeyLenBytes], &T[offset], localSaltLenBytes);
        offset += localSaltLenBytes;

        memcpy(remoteKeySalt, &T[offset], remoteKeyLenBytes);
        offset += remoteKeyLenBytes;
        memcpy(localKeySalt, &T[offset], localKeyLenBytes);
    }
}

void ZrtpSdesStream::createSrtpContexts(bool sipInvite) {

    if (cryptoMixHashType != NONE) {
        computeMixedKeys(sipInvite);
    }

    sendSrtp = new CryptoContext(0,                     // SSRC (used for lookup)
                                 0,                     // Roll-Over-Counter (ROC)
                                 0L,                    // keyderivation << 48,
                                 localCipher,                // encryption algo
                                 localAuthn,                 // authtentication algo
                                 localKeySalt,               // Master Key
                                 localKeyLenBytes,           // Master Key length
                                 &localKeySalt[localKeyLenBytes], // Master Salt
                                 localSaltLenBytes,          // Master Salt length
                                 localKeyLenBytes,           // encryption keylen
                                 localAuthKeyLen,            // authentication key len (HMAC key lenght)
                                 localKeyLenBytes,          // session salt len
                                 localTagLength);            // authentication tag len
    sendSrtp->deriveSrtpKeys(0L);
    memset(localKeySalt, 0, sizeof(localKeySalt));

    recvSrtp = new CryptoContext(0,                     // SSRC (used for lookup)
                                 0,                     // Roll-Over-Counter (ROC)
                                 0L,                    // keyderivation << 48,
                                 remoteCipher,                // encryption algo
                                 remoteAuthn,                 // authtentication algo
                                 remoteKeySalt,               // Master Key
                                 remoteKeyLenBytes,           // Master Key length
                                 &remoteKeySalt[remoteKeyLenBytes], // Master Salt
                                 remoteSaltLenBytes,          // Master Salt length
                                 remoteKeyLenBytes,           // encryption keylen
                                 remoteAuthKeyLen,            // authentication key len (HMAC key lenght)
                                 remoteSaltLenBytes,          // session salt len
                                 remoteTagLength);            // authentication tag len
    recvSrtp->deriveSrtpKeys(0L);
    memset(remoteKeySalt, 0, sizeof(remoteKeySalt));
}

bool ZrtpSdesStream::createSdesProfile(char *cryptoString, size_t *maxLen) {

    char b64keySalt[(MAX_KEY_LEN + MAX_SALT_LEN) * 2] = {'\0'};
    uint32_t sidx;
    int32_t b64Len;

    /* Lookup crypto suite parameters */
    for (sidx = 0; knownSuites[sidx].name != NULL; sidx++) {
        if (knownSuites[sidx].suite == suite)
            break;
    }
    if (sidx >= sizeof(knownSuites)/sizeof(struct _suite)) {
        return false;
    }
    suiteParam *pSuite = &knownSuites[sidx];
    _random(localKeySalt, sizeof(localKeySalt));

    AlgorithmEnum& auth = zrtpAuthLengths.getByName(pSuite->tagLength);
    localAuthn = SrtpAuthenticationSha1Hmac;
    localAuthKeyLen = pSuite->authKeyLength / 8;
    localTagLength = auth.getKeylen() / 8;

    // If SDES will support other encryption algos - get it here based on
    // the algorithm name in suite
    localCipher = SrtpEncryptionAESCM;

    localKeyLenBytes = pSuite->keyLength / 8;
    localSaltLenBytes = pSuite->saltLength / 8;

    if (tag == -1)
        tag = 1;

    /* Get B64 code for master key and master salt */
    b64Len = b64Encode(localKeySalt, localKeyLenBytes + localSaltLenBytes, b64keySalt, sizeof(b64keySalt));
    b64keySalt[b64Len] = '\0';
    memset(cryptoString, 0, *maxLen);
    *maxLen = snprintf(cryptoString, *maxLen-1, "%d %s inline:%s", tag, pSuite->name, b64keySalt);

    return true;
}

bool ZrtpSdesStream::parseCreateSdesProfile(const char *cryptoStr, size_t length, sdesSuites *parsedSuite, int32_t *outTag) {
    int elements,  i;
    int charsScanned;
    int mkiLength = 0;
    uint32_t sidx;

    char cryptoString[MAX_CRYPT_STRING_LEN+1] = {'\0'};

    /* Parsed strings */
    char suiteName[MAX_INNER_LEN]  = {'\0'};
    char keyParams[MAX_INNER_LEN]  = {'\0'};
    char keySaltB64[MAX_INNER_LEN] = {'\0'};
    char lifetime[MAX_INNER_LEN]   = {'\0'};
    char mkiVal[MAX_INNER_LEN]     = {'\0'};

    if (length == 0)
        length = strlen(cryptoStr);

    if (length > MAX_CRYPT_STRING_LEN) {
        return false;
    }
    /* make own copy, null terminated */
    memcpy(cryptoString, cryptoStr, length);

    *outTag = -1;
    elements = sscanf(cryptoString, parseCrypto, outTag, suiteName, keyParams, &charsScanned);

    /* Do we have enough elements in the string */
    if (elements < minElementsCrypto) {
        return false;
    }

    /* Lookup crypto suite */
    for (sidx = 0; knownSuites[sidx].name != NULL; sidx++) {
        if (!strcmp(knownSuites[sidx].name, suiteName))
            break;
    }
    if (sidx >= sizeof(knownSuites)/sizeof(struct _suite)) {
        return false;
    }
    suiteParam *pSuite = &knownSuites[sidx];
    *parsedSuite = pSuite->suite;

    /* Now scan the key parameters */
    elements = sscanf(keyParams, parseKeyParam, keySaltB64, lifetime, mkiVal, &mkiLength);

    /* Currently only one we only accept key||salt B64 string, no other parameters */
    if (elements != minElementsKeyParam) {
        return false;
    }

    remoteKeyLenBytes = pSuite->keyLength / 8;
    remoteSaltLenBytes = pSuite->saltLength / 8;

    /* Check if key||salt B64 string hast the correct length */
    if (strlen(keySaltB64) != pSuite->b64length) {
        return false;
    }

    i = b64Decode(keySaltB64, pSuite->b64length, remoteKeySalt, remoteKeyLenBytes + remoteSaltLenBytes);

    /* Did the B64 decode deliver enough data for key||salt */
    if (i != (remoteKeyLenBytes + remoteSaltLenBytes)) {
        return false;
    }

    AlgorithmEnum& auth = zrtpAuthLengths.getByName(pSuite->tagLength);
    remoteAuthn = SrtpAuthenticationSha1Hmac;
    remoteAuthKeyLen = pSuite->authKeyLength / 8;
    remoteTagLength = auth.getKeylen() / 8;

    // If SDES will support other encryption algos - get it here based on
    // the algorithm name in suite
    remoteCipher = SrtpEncryptionAESCM;

    return true;
}