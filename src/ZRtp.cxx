/*
  Copyright (C) 2006-2007 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */
#include <sstream>

#include <libzrtpcpp/crypto/ZrtpDH.h>
#include <libzrtpcpp/crypto/hmac256.h>
#include <libzrtpcpp/crypto/sha256.h>
#include <libzrtpcpp/crypto/aesCFB.h>

#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpStateClass.h>
#include <libzrtpcpp/ZIDFile.h>
#include <libzrtpcpp/ZIDRecord.h>
#include <libzrtpcpp/Base32.h>

static void hexdump(const char* title, const unsigned char *s, int l) {
    int n=0;

    if (s == NULL) return;

    fprintf(stderr, "%s",title);
    for( ; n < l ; ++n)
    {
        if((n%16) == 0)
            fprintf(stderr, "\n%04x",n);
        fprintf(stderr, " %02x",s[n]);
    }
    fprintf(stderr, "\n");
}

/*
 * This method simplifies detection of libzrtpcpp inside Automake, configure
 * and friends
 */
#ifdef __cplusplus
extern "C" {
#endif
int ZrtpAvailable()
{
    return 1;
}
#ifdef __cplusplus
}
#endif

ZRtp::ZRtp(uint8_t *myZid, ZrtpCallback *cb, std::string id):
    callback(cb), dhContext(NULL) {

    DHss = NULL;
    multiStream = false;
    PBXEnrollment = false;
    /*
     * Generate H0 as a random number (256 bits, 32 bytes) and then
     * the hash chain, refer to chapter 10
     */
    randomZRTP(H0, SHA256_DIGEST_LENGTH);
    sha256(H0, SHA256_DIGEST_LENGTH, H1);        // hash H0 and generate H1
    sha256(H1, SHA256_DIGEST_LENGTH, H2);        // H2
    sha256(H2, SHA256_DIGEST_LENGTH, H3);        // H3

    zrtpHello.setH3(H3);             // set H3 in Hello, included in helloHash

    memcpy(zid, myZid, 12);
    zrtpHello.setZid(zid);
    setClientId(id);                // set id, compute HMAC and final helloHash

    msgShaContext = createSha256Context(); // prepare for Initiator case

    stateEngine = new ZrtpStateClass(this);
}

ZRtp::~ZRtp() {
    stopZrtp();

    if (DHss != NULL) {
	free(DHss);
        DHss = NULL;
    }
    if (stateEngine != NULL) {
	delete stateEngine;
        stateEngine = NULL;
    }
    if (dhContext != NULL) {
	delete dhContext;
        dhContext = NULL;
    }
    if (msgShaContext != NULL) {
        closeSha256Context(msgShaContext, NULL);
        msgShaContext = NULL;
    }
    memset(hmacKeyI, 0, SHA256_DIGEST_LENGTH);
    memset(hmacKeyR, 0, SHA256_DIGEST_LENGTH);

    memset(zrtpKeyI, 0, SHA256_DIGEST_LENGTH);
    memset(zrtpKeyR, 0, SHA256_DIGEST_LENGTH);
    /*
     * Clear the Initiator's srtp key and salt
     */
    memset(srtpKeyI, 0, SHA256_DIGEST_LENGTH);
    memset(srtpSaltI, 0,  SHA256_DIGEST_LENGTH);
    /*
     * Clear he Responder's srtp key and salt
     */
    memset(srtpKeyR, 0, SHA256_DIGEST_LENGTH);
    memset(srtpSaltR, 0, SHA256_DIGEST_LENGTH);

    memset(s0, 0, SHA256_DIGEST_LENGTH);
}

int32_t ZRtp::processZrtpMessage(uint8_t *message) {
    Event_t ev;

    ev.type = ZrtpPacket;
    ev.data.packet = message;

    int32_t ret;
    if (stateEngine != NULL) {
        ret = stateEngine->processEvent(&ev);
    }
    return ret;
}

int32_t ZRtp::processTimeout() {
    Event_t ev;

    ev.type = Timer;
    ev.data.packet = NULL;
    int32_t ret;
    if (stateEngine != NULL) {
        ret = stateEngine->processEvent(&ev);
    }
    return ret;

}

#ifdef oldgoclear
bool ZRtp::handleGoClear(uint8_t *message)
{
    char *msg, first, last;

    msg = (char *)message + 4;
    first = tolower(*msg);
    last = tolower(*(msg+6));

    if (first == 'g' && last == 'r') {
        Event_t ev;

        ev.type = ZrtpGoClear;
        ev.data.packet = message;
        if (stateEngine != NULL) {
            stateEngine->processEvent(&ev);
        }
        return true;
    }
    else {
        return false;
    }
}
#endif

void ZRtp::startZrtpEngine() {
    Event_t ev;

    ev.type = ZrtpInitial;
    stateEngine->processEvent(&ev);
}

void ZRtp::stopZrtp() {
    Event_t ev;

    if (stateEngine != NULL) {
        ev.type = ZrtpClose;
        stateEngine->processEvent(&ev);
    }
}

bool ZRtp::inState(int32_t state)
{
    if (stateEngine != NULL) {
        return stateEngine->inState(state);
    }
    else {
        return -1;
    }
}

/*
 * At this point we will assume the role of Initiator. This role may change
 * in case we have a commit-clash. Refer to chapter 5.2 in the spec how
 * to break this tie.
 */
ZrtpPacketCommit* ZRtp::prepareCommit(ZrtpPacketHello *hello, uint32_t* errMsg) {

    sendInfo(Info, "Hello received, preparing a Commit");

    if (memcmp(hello->getVersion(), zrtpVersion, 4) != 0) {
        *errMsg = UnsuppZRTPVersion;
        sendInfo(Error, "Received Hello packet with unsupported version number.");
        return NULL;
    }
    // Save our peer's (presumably the Responder) ZRTP id
    uint8_t* cid = hello->getClientId();
    memcpy(peerZid, hello->getZid(), 12);
    if (memcmp(peerZid, zid, 12) == 0) {       // peers have same ZID????
        *errMsg = EqualZIDHello;
        sendInfo(Error, "Received Hello packet with same ZID.");
        return NULL;
    }
    memcpy(peerH3, hello->getH3(), SHA256_DIGEST_LENGTH);

    /*
     * The Following section extracts the algorithm from the Hello
     * packet. Always the best possible (offered) algorithms are
     * used. If the received Hello does not contain algo specifiers
     * or offers only unsupported (optional) alogos then replace
     * these with mandatory algos and put them into the Commit packet.
     * Refer to the findBest*() functions.
     */
    cipher = findBestCipher(hello);
    hash = findBestHash(hello);
    pubKey = findBestPubkey(hello);
    sasType = findBestSASType(hello);
    authLength = findBestAuthLen(hello);

    if (cipher == Aes256 && pubKey != Dh4096) {
	sendInfo(Warning, "Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096");
    }
    // Generate the DH data and keys regarding the selected DH algorithm
    int32_t maxPubKeySize;
    if (pubKey == Dh3072) {
	dhContext = new ZrtpDH(3072);
	maxPubKeySize = 384;

    }
    else if (pubKey == Dh4096) {
	dhContext = new ZrtpDH(4096);
	maxPubKeySize = 512;
    }
    else {
        *errMsg = CriticalSWError;
	return NULL;
	// Error - shouldn't happen
    }
    dhContext->generateKey();
    pubKeyLen = dhContext->getPubKeySize();
    dhContext->getPubKeyBytes(pubKeyBytes);

    char buffer[128];
    snprintf((char *)buffer, 128, "Commit: Generated a public DH key of size: %d", dhContext->getPubKeySize());
    sendInfo(Info, buffer);

    // Prepare IV data that we will use during confirm packet encryption. 
    randomZRTP(randomIV, sizeof(randomIV));

    /*
     * Prepare our DHPart2 packet here. Required to compute HVI. If we stay
     * in Initiator role then we reuse this packet later in prepareDHPart2().
     * To create this DH packet we have to compute the retained secret ids
     * first. Thus get our peer's retained secret data first.
     */
    ZIDRecord zidRec(peerZid);
    ZIDFile *zidFile = ZIDFile::getInstance();
    zidFile->getRecord(&zidRec);

    //Compute the Initator's and Responder's retained secret ids.
    computeSharedSecretSet(zidRec);

    // Construct a DHPart2 message (Initiator's DH message). This packet
    //is required to compute the HVI (Hash Value Initiator), refer to 
    // chapter 5.4.1.1.

    // Fill the values in the DHPart2 packet
    zrtpDH2.setPubKeyType(pubKey);
    zrtpDH2.setMessageType((uint8_t*)DHPart2Msg);
    zrtpDH2.setRs1Id(rs1IDi);
    zrtpDH2.setRs2Id(rs2IDi);
    zrtpDH2.setSigsId(sigsIDi);
    zrtpDH2.setSrtpsId(srtpsIDi);
    zrtpDH2.setOtherSecretId(otherSecretIDi);
    zrtpDH2.setPv(pubKeyBytes);
    zrtpDH2.setH1(H1);

    int32_t len = zrtpDH2.getLength() * ZRTP_WORD_SIZE;

    // Compute HMAC over Hello, excluding the HMAC field (2*ZTP_WORD_SIZE)
    // and store in Hello
    uint8_t hmac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;
    hmac_sha256(H0, SHA256_DIGEST_LENGTH, (uint8_t*)zrtpDH2.getHeaderBase(), 
                len-(2*ZRTP_WORD_SIZE), hmac, &macLen);
    zrtpDH2.setHMAC(hmac);

    // Compute the HVI, refer to chapter 5.4.1.1 of the specification
    computeHvi(&zrtpDH2, hello);

    zrtpCommit.setZid(zid);
    zrtpCommit.setHashType((uint8_t*)supportedHashes[hash]);
    zrtpCommit.setCipherType((uint8_t*)supportedCipher[cipher]);
    zrtpCommit.setAuthLen((uint8_t*)supportedAuthLen[authLength]);
    zrtpCommit.setPubKeyType((uint8_t*)supportedPubKey[pubKey]);
    zrtpCommit.setSasType((uint8_t*)supportedSASType[sasType]);
    zrtpCommit.setHvi(hvi);
    zrtpCommit.setH2(H2);

    len = zrtpCommit.getLength() * ZRTP_WORD_SIZE;

    // Compute HMAC over Hello, excluding the HMAC field (2*ZTP_WORD_SIZE)
    // and store in Hello
    hmac_sha256(H1, SHA256_DIGEST_LENGTH, (uint8_t*)zrtpCommit.getHeaderBase(), 
                len-(2*ZRTP_WORD_SIZE), hmac, &macLen);
    zrtpCommit.setHMAC(hmac);

    // hash first messages to produce overall message hash
    // First the Responder's Hello message, second the Commit 
    // (always Initator's)
    sha256Ctx(msgShaContext, (unsigned char*)hello->getHeaderBase(), hello->getLength() * ZRTP_WORD_SIZE);
    sha256Ctx(msgShaContext, (unsigned char*)zrtpCommit.getHeaderBase(), len);

    // store Hello data temporarily until we can check HMAC after receiving Commit as
    // Responder or DHPart1 as Initiator 
    storeMsgTemp(hello);
    return &zrtpCommit;
}

/*
 * At this point we will take the role of the Responder. We may have been in 
 * the role of the Initiator before and already sent a commit packet that
 * clashed with a commit packet from our peer. If our HVI was lower than our
 * peer's HVI then we switched to Responder and handle our peer's commit packet
 * here. This method takes care to delete and refresh data left over from a
 * possible Initiator preparation. This belongs to prepared DH data, message 
 * hash SHA context
 */
ZrtpPacketDHPart* ZRtp::prepareDHPart1(ZrtpPacketCommit *commit, uint32_t* errMsg) {

    int i;

    sendInfo(Info, "Responder: Commit received, preparing DHPart1");

    // The following code check the hash chain according chapter 10 to detect
    // false ZRTP packets
    uint8_t tmpH3[SHA256_DIGEST_LENGTH];
    memcpy(peerH2, commit->getH2(), SHA256_DIGEST_LENGTH);
    sha256(peerH2, SHA256_DIGEST_LENGTH, tmpH3);

    if (memcmp(tmpH3, peerH3, SHA256_DIGEST_LENGTH) != 0) {
        *errMsg = IgnorePacket;
        return NULL;
    }

    // Check HMAC of previous Hello packet stored in temporary buffer. The
    // HMAC key of peer's Hello packet is peer's H2 that is contained in the 
    // Commit packet. Refer to chapter 9.1.
    if (!checkMsgHmac(peerH2)) {
        sendInfo(Alert, "Commit: Hello HMAC check failed!");
        return NULL;
    }

    // check if we support the commited Cipher type
    uint32_t cp = *(uint32_t*)commit->getCipherType();
    for (i = 0; i < NumSupportedSymCiphers; i++) {
        if (cp == *(uint32_t*)supportedCipher[i]) {
	    break;
	}
    }
    if (i >= NumSupportedSymCiphers) { // no match - something went wrong
        *errMsg = UnsuppCiphertype;
	sendInfo(Alert, "Cannot find a supported Cipher in Commit message");
	return NULL;
    }
    cipher = (SupportedSymCiphers)i;

    // check if we support the commited Authentication length
    cp = *(uint32_t*)commit->getAuthLen();
    for (i = 0; i < NumSupportedAuthLenghts; i++) {
        if (cp == *(uint32_t*)supportedAuthLen[i]) {
            break;
        }
    }
    if (i >= NumSupportedAuthLenghts) { // no match - something went wrong
        *errMsg = UnsuppSRTPAuthTag;
        sendInfo(Alert, "Cannot find a supported authentication length in Commit message");
        return NULL;
    }
    authLength = (SupportedAuthLengths)i;

    // check if we support the commited hash type
    cp = *(uint32_t*)commit->getHashType();
    for (i = 0; i < NumSupportedHashes; i++) {
        if (cp == *(uint32_t*)supportedHashes[i]) {
	    break;
	}
    }
    if (i >= NumSupportedHashes) { // no match - something went wrong
        *errMsg = UnsuppHashType;
	sendInfo(Alert, "Cannot find a supported Hash in Commit message");
	return NULL;
    }
    hash = (SupportedHashes)i;

    // check if we support the commited pub key type
    cp = *(uint32_t*)commit->getPubKeysType();
    for (i = 0; i < NumSupportedPubKeys; i++) {
        if (cp == *(uint32_t*)supportedPubKey[i]) {
	    break;
	}
    }
    if (i >= NumSupportedPubKeys) { // no match - something went wrong
        *errMsg = UnsuppPKExchange;
	sendInfo(Alert, "Cannot find a supported public key algorithm in Commit message");
	return NULL;
    }
    pubKey = (SupportedPubKeys)i;

    // check if we support the commited SAS type
    cp = *(uint32_t*)commit->getSasType();
    for (i = 0; i < NumSupportedSASTypes; i++) {
        if (cp == *(uint32_t*)supportedSASType[i]) {
	    break;
	}
    }
    if (i >= NumSupportedSASTypes) { // no match - something went wrong
        *errMsg = UnsuppSASScheme;
	sendInfo(Alert, "Cannot find a supported SAS algorithm in Commit message");
	return NULL;
    }
    sasType = (SupportedSASTypes)i;

    int32_t maxPubKeySize;
    switch (pubKey) {
        case Dh3072:
            maxPubKeySize = 384;
            break;
        case Dh4096:
            maxPubKeySize = 512;
            break;
        default:
            *errMsg = CriticalSWError;
            return NULL;
    }

    if (cipher == Aes256 && pubKey != Dh4096) {
        sendInfo(Warning, "Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096");
        // generate a warning
    }

    // Check if we can reuse DH context created during prepareCommit()
    // If no dhContext availabe of the parameters don't match - generate 
    // a new one
    if (dhContext == NULL || 
        !((pubKey == Dh3072 && dhContext->getDHlength() == 3072) ||
          (pubKey == Dh4096 && dhContext->getDHlength() == 4096))) {
        delete dhContext;
        // setup a new DH context and generate a fresh DH key pair
        if (pubKey == Dh3072) {
            dhContext = new ZrtpDH(3072);

        }
        else if (pubKey == Dh4096) {
            dhContext = new ZrtpDH(4096);
        }
    }
    dhContext->generateKey();
    pubKeyLen = dhContext->getPubKeySize();

    char buffer[128];
    snprintf(buffer, 128, "DH1Part: Generated a public DH key of size: %d", pubKeyLen);
    sendInfo(Info, buffer);

    if (pubKeyLen > maxPubKeySize) {
        *errMsg = CriticalSWError;
        snprintf(buffer, 128, "Generated DH public key too big: %d, max: %d", pubKeyLen, maxPubKeySize);
        sendInfo(Error, buffer);
        return NULL;
    }
    dhContext->getPubKeyBytes(pubKeyBytes);

    // Setup a DHPart1 packet.
    zrtpDH1.setPubKeyType(pubKey);
    zrtpDH1.setMessageType((uint8_t*)DHPart1Msg);
    zrtpDH1.setRs1Id(rs1IDr);
    zrtpDH1.setRs2Id(rs2IDr);
    zrtpDH1.setSigsId(sigsIDr);
    zrtpDH1.setSrtpsId(srtpsIDr);
    zrtpDH1.setOtherSecretId(otherSecretIDr);
    zrtpDH1.setPv(pubKeyBytes);
    zrtpDH1.setH1(H1);

    int32_t len = zrtpDH1.getLength() * ZRTP_WORD_SIZE;

    // Compute HMAC over DHPart1, excluding the HMAC field (2*ZTP_WORD_SIZE)
    // and store in DHPart1
    uint8_t hmac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;
    hmac_sha256(H0, SHA256_DIGEST_LENGTH, (uint8_t*)zrtpDH1.getHeaderBase(), 
                len-(2*ZRTP_WORD_SIZE), hmac, &macLen);
    zrtpDH1.setHMAC(hmac);

    // We are definitly responder. Save the peer's hvi for later compare.
    myRole = Responder;
    memcpy(peerHvi, commit->getHvi(), SHA256_DIGEST_LENGTH);

    // We are responder. Release a possibly pre-computed SHA256 context
    // because this was prepared for Initiator. Then create a new one.
    if (msgShaContext != NULL) {
        closeSha256Context(msgShaContext, NULL);
    }
    msgShaContext = createSha256Context();

    // Hash messages to produce overall message hash:
    // First the Responder's (my) Hello message, second the Commit 
    // (always Initator's), then the DH1 message (which is always a 
    // Responder's message)
    sha256Ctx(msgShaContext, (unsigned char*)zrtpHello.getHeaderBase(),
              zrtpHello.getLength() * ZRTP_WORD_SIZE);
    sha256Ctx(msgShaContext, (unsigned char*)commit->getHeaderBase(),
              commit->getLength() * ZRTP_WORD_SIZE);
    sha256Ctx(msgShaContext, (unsigned char*)zrtpDH1.getHeaderBase(),
              zrtpDH1.getLength() * ZRTP_WORD_SIZE);

    // store Commit data temporarily until we can check HMAC after receiving DHPart2
    storeMsgTemp(commit);

    return &zrtpDH1;
}

/*
 * At this point we will take the role of the Initiator.
 */
ZrtpPacketDHPart* ZRtp::prepareDHPart2(ZrtpPacketDHPart *dhPart1, uint32_t* errMsg) {

    uint8_t* pvr;
    uint8_t sas[SHA256_DIGEST_LENGTH+1];

    sendInfo(Info, "Initiator: DHPart1 received, preparing DHPart2");

    // Because we are initiator the protocol engine didn't receive Commit
    // thus could not store a peer's H2. A two step SHA256 is required to 
    // re-compute H3. Then compare with peer's H3 from peer's Hello packet.
    uint8_t tmpHash[SHA256_DIGEST_LENGTH];
    sha256(dhPart1->getH1(), SHA256_DIGEST_LENGTH, peerH2); // Compute peer's H2
    sha256(peerH2, SHA256_DIGEST_LENGTH, tmpHash);          // Compute peer's H3 (tmpHash)

    if (memcmp(tmpHash, peerH3, SHA256_DIGEST_LENGTH) != 0) {
        *errMsg = IgnorePacket;
        return NULL;
    }

    // Check HMAC of previous Hello packet stored in temporary buffer. The
    // HMAC key of the Hello packet is peer's H2 that was computed above.
    // Refer to chapter 9.1 and chapter 10.
    if (!checkMsgHmac(peerH2)) {
        sendInfo(Alert, "DHPart1: Hello HMAC check failed!");
        return NULL;
    }

    // get memory to store DH result TODO: make it fixed memory
    DHss = (uint8_t*)malloc(dhContext->getSecretSize());
    if (DHss == NULL) {
	sendInfo(Error, "Out of memory");	// serious error
	return NULL;
    }

    // get and check Responder's public value, see chap. 5.4.3 in the spec
    pvr = dhPart1->getPv();
    if (pubKey == Dh3072) {
        if (!dhContext->checkPubKey(pvr, 384)) {
            *errMsg = DHErrorWrongPV;
            sendInfo(Alert, "Wrong/weak public key value (pvr) received from other party");
            return NULL;
        }
	dhContext->computeKey(pvr, 384, DHss);
    }
    else {
        if (!dhContext->checkPubKey(pvr, 512)) {
            *errMsg = DHErrorWrongPV;
            sendInfo(Alert, "Wrong/weak public key value (pvr) received from other party");
            return NULL;
        }
        dhContext->computeKey(pvr, 512, DHss);
    }

    myRole = Initiator;

    // We are Inititaor: the Responder's Hello and the Initiator's (our) Commit
    // are already hashed in the context. Now hash the Responder's DH1 and then
    // the Initiator's (our) DH2 in that order.
    sha256Ctx(msgShaContext, (unsigned char*)dhPart1->getHeaderBase(), dhPart1->getLength() * ZRTP_WORD_SIZE);
    sha256Ctx(msgShaContext, (unsigned char*)zrtpDH2.getHeaderBase(), zrtpDH2.getLength() * ZRTP_WORD_SIZE);

    // Compute the message Hash
    closeSha256Context(msgShaContext, messageHash);
    msgShaContext = NULL;

    // To compute the S0 for the Initiator we need the retained secrets of our
    // peer. Get them from the storage.
    ZIDRecord zidRec(peerZid);
    ZIDFile *zid = ZIDFile::getInstance();
    zid->getRecord(&zidRec);

    // Now compute the S0, all dependend keys and the new RS1
    generateS0Initiator(dhPart1, zidRec);
    delete dhContext;
    dhContext = NULL;

    // store DHPart1 data temporarily until we can check HMAC after receiving Confirm1
    storeMsgTemp(dhPart1);
    return &zrtpDH2;
}

/*
 * At this point we are Responder.
 */
ZrtpPacketConfirm* ZRtp::prepareConfirm1(ZrtpPacketDHPart* dhPart2, uint32_t* errMsg) {

    uint8_t* pvi;
    uint8_t sas[SHA256_DIGEST_LENGTH+1];

    sendInfo(Info, "Responder: DHPart2 received, preparing Confirm1");

    // Because we are responder we received a Commit and stored its H2. 
    // Now re-compute H2 from received H1 and compare with stored peer's H2.
    uint8_t tmpHash[SHA256_DIGEST_LENGTH];
    sha256(dhPart2->getH1(), SHA256_DIGEST_LENGTH, tmpHash);
    if (memcmp(tmpHash, peerH2, SHA256_DIGEST_LENGTH) != 0) {
        *errMsg = IgnorePacket;
        return NULL;
    }

    // Check HMAC of Commit packet stored in temporary buffer. The
    // HMAC key of the Commit packet is peer's H1 that is contained in.
    // DHPart2. Refer to chapter 9.1 and chapter 10.
    if (!checkMsgHmac(dhPart2->getH1())) {
        sendInfo(Alert, "DHPart2: Commit HMAC check failed!");
        return NULL;
    }
    // TODO: fixed memory
    DHss = (uint8_t*)malloc(dhContext->getSecretSize());
    if (DHss == NULL) {
	// serious error
	return NULL;
    }

    // Get and check the Initiator's public value, see chap. 5.4.2 of the spec
    pvi = dhPart2->getPv();
    if (pubKey == Dh3072) {
        if (!dhContext->checkPubKey(pvi, 384)) {
            *errMsg = DHErrorWrongPV;
            sendInfo(Alert, "Wrong/weak public key value (pvi) received from other party");
            return NULL;
        }
        dhContext->computeKey(pvi, 384, DHss);
    }
    else {
        if (!dhContext->checkPubKey(pvi, 512)) {
            *errMsg = DHErrorWrongPV;
            sendInfo(Alert, "Wrong/weak public key value (pvi) received from other party");
            return NULL;
        }
        dhContext->computeKey(pvi, 512, DHss);
    }

    // Now we have the peer's pvi. Because we are responder re-compute my hvi
    // using my Hello packet and the Initiator's DHPart2 and compare with
    // hvi sent in commit packet. If it doesn't macht then a MitM attack
    // may have occured.
    computeHvi(dhPart2, &zrtpHello);
    if (memcmp(hvi, peerHvi, SHA256_DIGEST_LENGTH) != 0) {
        *errMsg = DHErrorWrongHVI;
        sendInfo(Alert, "Mismatch of HVI values. Possible MitM problem?");
        return NULL;
    }
    // Hash the Initiator's DH2 into the message Hash (other messages already
    // prepared, see method prepareDHPart1().
    sha256Ctx(msgShaContext, (unsigned char*)dhPart2->getHeaderBase(),
              dhPart2->getLength() * ZRTP_WORD_SIZE);

    closeSha256Context(msgShaContext, messageHash);
    msgShaContext = NULL;

    // To compute the S0 for the Initiator we need the retained secrets of our
    // peer. Get them from the storage.
    ZIDRecord zidRec(peerZid);
    ZIDFile *zid = ZIDFile::getInstance();
    zid->getRecord(&zidRec);

    /*
     * The expected shared secret Ids were already computed when we built the
     * DHPart1 packet. Generate s0, all depended keys, and the new RS1 value
     * for the ZID record.
     */
    generateS0Responder(dhPart2, zidRec);

    delete dhContext;
    dhContext = NULL;

    // Fill in Confirm1 packet.
    zrtpConfirm1.setMessageType((uint8_t*)Confirm1Msg);
    zrtpConfirm1.setSignatureLength(static_cast<uint8_t>(0));

    // Check if user verfied the SAS in a previous call and thus verfied
    // the retained secret.
    if (zidRec.isSasVerified()) {
        zrtpConfirm1.setSASFlag();
    }
    zrtpConfirm1.setExpTime(0xFFFFFFFF);
    zrtpConfirm1.setIv(randomIV);
    zrtpConfirm1.setHashH0(H0);

    uint8_t confMac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;

    // Encrypt and HMAC with Responder's key - we are Respondere here
    int16_t hmlen = (zrtpConfirm1.getLength() - 9) * ZRTP_WORD_SIZE;
    int keylen = (cipher == Aes128) ? 16 : 32;

    aesCfbEncrypt(zrtpKeyR, keylen, randomIV,
                  (unsigned char*)zrtpConfirm1.getHashH0(), hmlen);
    hmac_sha256(hmacKeyR, SHA256_DIGEST_LENGTH,
                (unsigned char*)zrtpConfirm1.getHashH0(),
                hmlen, confMac, &macLen);

    zrtpConfirm1.setHmac(confMac);

   // store DHPart2 data temporarily until we can check HMAC after receiving Confirm2
    storeMsgTemp(dhPart2);
    return &zrtpConfirm1;
}

ZrtpPacketConfirm* ZRtp::prepareConfirm2(ZrtpPacketConfirm *confirm1, uint32_t* errMsg) {

    sendInfo(Info, "Initiator: Confirm1 received, preparing Confirm2");

    uint8_t confMac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;

    // Use the Responder's keys here because we are Initiator here and
    // receive packets from Responder
    int16_t hmlen = (confirm1->getLength() - 9) * ZRTP_WORD_SIZE;
    int keylen = (cipher == Aes128) ? 16 : 32;

    hmac_sha256(hmacKeyR, SHA256_DIGEST_LENGTH,
                (unsigned char*)confirm1->getHashH0(),
                hmlen, confMac, &macLen);

    if (memcmp(confMac, confirm1->getHmac(), 2*ZRTP_WORD_SIZE) != 0) {
        *errMsg = ConfirmHMACWrong;
        sendInfo(Error, "HMAC verification of Confirm1 message failed");
        return NULL;
    }
    aesCfbDecrypt(zrtpKeyR, keylen, 
                  (unsigned char*)confirm1->getIv(),
                  (unsigned char*)confirm1->getHashH0(), hmlen);

    // Check HMAC of DHPart1 packet stored in temporary buffer. The
    // HMAC key of the DHPart1 packet is peer's H0 that is contained in.
    // Confirm1. Refer to chapter 9.1 and chapter 10.
    if (!checkMsgHmac(confirm1->getHashH0())) {
        sendInfo(Alert, "Confirm1: DHPart1 HMAC check failed!");
        return NULL;
    }

    /*
     * The Confirm1 is ok, handle the Retained secret stuff and inform
     * GUI about state.
     */
    bool sasFlag = confirm1->isSASFlag();

    // Initialize a ZID record to get peer's retained secrets
    ZIDRecord zidRec(peerZid);

    ZIDFile *zid = ZIDFile::getInstance();
    zid->getRecord(&zidRec);

    // Our peer did not confirm the SAS in last session, thus reset
    // our SAS flag too.
    if (!sasFlag) {
      zidRec.resetSasVerified();
    }

    // get verified flag from current RS1 before set a new RS1. This
    // may not be set even if peer's flag is set in confirm1 message.
    sasFlag = zidRec.isSasVerified() ? true : false;

    // Inform GUI about security state and SAS state
    bool sasVerified = zidRec.isSasVerified();
    std::string cs((cipher == Aes128) ? "AES-CM-128" : "AES-CM-256");
    callback->srtpSecretsOn(cs, SAS, sasVerified);

    // now we are ready to save the new RS1 which inherits the verified
    // flag from old RS1
    zidRec.setNewRs1((const uint8_t*)newRs1);
    zid->saveRecord(&zidRec);

    // now generate my Confirm2 message
    zrtpConfirm2.setMessageType((uint8_t*)Confirm2Msg);
    zrtpConfirm2.setSignatureLength(static_cast<uint8_t>(0));
    zrtpConfirm2.setHashH0(H0); 

    if (sasFlag) {
        zrtpConfirm2.setSASFlag();
    }
    zrtpConfirm2.setExpTime(0xFFFFFFFF);
    zrtpConfirm2.setIv(randomIV);

    // Encrypt and HMAC with Initiator's key - we are Initiator here
    hmlen = (zrtpConfirm2.getLength() - 9) * ZRTP_WORD_SIZE;
    aesCfbEncrypt(zrtpKeyI, keylen, randomIV,
                  (unsigned char*)zrtpConfirm2.getHashH0(), hmlen); 
    hmac_sha256(hmacKeyI, SHA256_DIGEST_LENGTH,
                (unsigned char*)zrtpConfirm2.getHashH0(),
                hmlen, confMac, &macLen);

    zrtpConfirm2.setHmac(confMac);
    return &zrtpConfirm2;
}

ZrtpPacketConf2Ack* ZRtp::prepareConf2Ack(ZrtpPacketConfirm *confirm2, uint32_t* errMsg) {

    sendInfo(Info, "Responder: Confirm2 received, preparing Conf2Ack");

    uint8_t confMac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;

    // Use the Initiator's keys here because we are Responder here and
    // reveice packets from Initiator
    int16_t hmlen = (confirm2->getLength() - 9) * ZRTP_WORD_SIZE;
    int keylen = (cipher == Aes128) ? 16 : 32;

    hmac_sha256(hmacKeyI, SHA256_DIGEST_LENGTH,
                (unsigned char*)confirm2->getHashH0(),
                hmlen, confMac, &macLen);

    if (memcmp(confMac, confirm2->getHmac(), 2*ZRTP_WORD_SIZE) != 0) {
        *errMsg = ConfirmHMACWrong;
        sendInfo(Error, "HMAC verification of Confirm2 message failed");
        return NULL;
    }
    aesCfbDecrypt(zrtpKeyI, keylen, 
                  (unsigned char*)confirm2->getIv(),
                  (unsigned char*)confirm2->getHashH0(), hmlen);

    // Check HMAC of DHPart2 packet stored in temporary buffer. The
    // HMAC key of the DHPart2 packet is peer's H0 that is contained in
    // Confirm2. Refer to chapter 9.1 and chapter 10.
    if (!checkMsgHmac(confirm2->getHashH0())) {
        sendInfo(Alert, "Confirm2: DHPart2 HMAC check failed!");
        return NULL;
    }

    /*
     * The Confirm2 is ok, handle the Retained secret stuff and inform
     * GUI about state.
     */
    bool sasFlag = confirm2->isSASFlag();

    // Initialize a ZID record to get peer's retained secrets
    ZIDRecord zidRec(peerZid);

    ZIDFile *zid = ZIDFile::getInstance();
    zid->getRecord(&zidRec);

    // Our peer did not confirm the SAS in last session, thus reset
    // our SAS flag too.
    if (!sasFlag) {
      zidRec.resetSasVerified();
    }

    // Inform GUI about security state and SAS state
    bool sasVerified = zidRec.isSasVerified();
    std::string cs((cipher == Aes128) ? "AES-CM-128" : "AES-CM-256");
    callback->srtpSecretsOn(cs, SAS, sasVerified);

    // save new RS1, this inherits the verified flag from old RS1
    zidRec.setNewRs1((const uint8_t*)newRs1);
    zid->saveRecord(&zidRec);

    return &zrtpConf2Ack;
}

ZrtpPacketErrorAck* ZRtp::prepareErrorAck(ZrtpPacketError* epkt)
{
    char buffer[128];
    snprintf((char *)buffer, 128, "Error: Received an Error message, code: %x", epkt->getErrorCode());

    sendInfo(Error, buffer);
    return &zrtpErrorAck;
}

ZrtpPacketError* ZRtp::prepareError(uint32_t errMsg)
{
    ZrtpPacketError* err = &zrtpError;
    err->setErrorCode(errMsg);
    return err;
}

// TODO Implement GoClear handling
ZrtpPacketClearAck* ZRtp::prepareClearAck(ZrtpPacketGoClear* gpkt)
{
    sendInfo(Warning, "Received a GoClear message");
    return &zrtpClearAck;
}

ZrtpPacketGoClear* ZRtp::prepareGoClear(uint32_t errMsg)
{
    uint8_t msg[16];
    ZrtpPacketGoClear* gclr = &zrtpGoClear;
    gclr->clrClearHmac();
    return gclr;
}

/*
 * The next functions look up and return a prefered algorithm. These
 * functions work as follows:
 * - If the Hello packet does not contain an algorithm (number of algorithms is
 *   zero) then return our prefered algorithm. This prefered algorithm must be
 *   one of the mandatory algorithms specified in chapter 6.1.x.
 * - If the functions find a match return the found algorithm.
 * - If the functions do not find a match return a prefered, mandatory
 *   algorithm.
 * This guarantees that we always return a supported alogrithm.
 *
 * The mandatory algorithms are: (internal enums are our prefered algoritms)
 * Hash:                S256 (SHA 256)             (internal enum Sha256)
 * Symmetric Cipher:    AES1 (AES 128)             (internal enum Aes128)
 * SRTP Authentication: HS32 and HS80 (32/80 bits) (internal enum AuthLen32)
 * Key Agreement:       DH3k (3072 Diffie-Helman)  (internal enum Dh3072)
 *
 */
SupportedHashes ZRtp::findBestHash(ZrtpPacketHello *hello) {

    int i;
    int ii;
    int num = hello->getNumHashes();

    if (num == 0) {
        return Sha256;
    }
    for (i = 0; i < NumSupportedHashes; i++) {
	for (ii = 0; ii < num; ii++) {
	    if (*(uint32_t*)hello->getHashType(ii) == *(uint32_t*)supportedHashes[i]) {
                return (SupportedHashes)i;
	    }
	}
    }
    return Sha256;
}

SupportedSymCiphers ZRtp::findBestCipher(ZrtpPacketHello *hello) {

    int i;
    int ii;
    int num = hello->getNumCiphers();

    if (num == 0) {
        return Aes128;
    }
    for (i = 0; i < NumSupportedSymCiphers; i++) {
	for (ii = 0; ii < num; ii++) {
	    if (*(uint32_t*)hello->getCipherType(ii) == *(uint32_t*)supportedCipher[i]) {
                return (SupportedSymCiphers)i;
	    }
	}
    }
    return Aes128;
}

SupportedPubKeys ZRtp::findBestPubkey(ZrtpPacketHello *hello) {

    int i;
    int ii;
    int num = hello->getNumPubKeys();

    if (num == 0) {
        return Dh3072;
    }
    for (i = 0; i < NumSupportedPubKeys; i++) {
	for (ii = 0; ii < num; ii++) {
	    if (*(uint32_t*)hello->getPubKeyType(ii) ==  *(uint32_t*)supportedPubKey[i]) {
                return (SupportedPubKeys)i;
	    }
	}
    }
    return Dh3072;
}

SupportedSASTypes ZRtp::findBestSASType(ZrtpPacketHello *hello) {

    int  i;
    int ii;
    int num = hello->getNumSas();

    if (num == 0) {
        return Libase32;
    }
    for (i = 0; i < NumSupportedSASTypes ; i++) {
	for (ii = 0; ii < num; ii++) {
	    if (*(uint32_t*)hello->getSasType(ii) == *(uint32_t*)supportedSASType[i]) {
                return (SupportedSASTypes)i;
	    }
	}
    }
    return Libase32;
}

SupportedAuthLengths ZRtp::findBestAuthLen(ZrtpPacketHello *hello) {

    int  i;
    int ii;
    int num = hello->getNumAuth();

    if (num == 0) {
        return AuthLen32;
    }
    for (i = 0; i < NumSupportedAuthLenghts ; i++) {
        for (ii = 0; ii < num; ii++) {
            if (*(uint32_t*)hello->getAuthLen(ii) == *(uint32_t*)supportedAuthLen[i]) {
                return (SupportedAuthLengths)i;
            }
        }
    }
    return AuthLen32;
}

bool ZRtp::verifyH2(ZrtpPacketCommit *commit) {
    uint8_t tmpH3[SHA256_DIGEST_LENGTH];

    sha256(commit->getH2(), SHA256_DIGEST_LENGTH, tmpH3);
    if (memcmp(tmpH3, peerH3, SHA256_DIGEST_LENGTH) != 0) {
        return false;
    }
    return true;
}

void ZRtp::computeHvi(ZrtpPacketDHPart* dh, ZrtpPacketHello *hello) {

    unsigned char* data[3];
    unsigned int length[3];
    /*
     * populate the vector to compute the HVI hash according to the
     * ZRTP specification.
     */
    data[0] = (uint8_t*)dh->getHeaderBase();
    length[0] = dh->getLength() * ZRTP_WORD_SIZE;

    data[1] = (uint8_t*)hello->getHeaderBase();
    length[1] = hello->getLength() * ZRTP_WORD_SIZE;

    data[2] = NULL;            // terminate data chunks
    sha256(data, length, hvi);
    return;
}

void ZRtp:: computeSharedSecretSet(ZIDRecord &zidRec) {

   /*
    * Compute the Initiator's and Reponder's retained shared secret Ids.
    */
    uint8_t randBuf[RS_LENGTH];
    uint32_t macLen;

    if (!zidRec.isRs1Valid()) {
	randomZRTP(randBuf, RS_LENGTH);
	hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)initiator,
		    strlen(initiator), rs1IDi, &macLen);
	hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)responder,
		    strlen(responder), rs1IDr, &macLen);
    }
    else {
	hmac_sha256((unsigned char*)zidRec.getRs1(), RS_LENGTH,
		     (unsigned char*)initiator, strlen(initiator),
		     rs1IDi, &macLen);
	hmac_sha256((unsigned char*)zidRec.getRs1(), RS_LENGTH,
		     (unsigned char*)responder, strlen(responder),
		     rs1IDr, &macLen);
    }

    if (!zidRec.isRs2Valid()) {
	randomZRTP(randBuf, RS_LENGTH);
	hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)initiator,
		    strlen(initiator), rs2IDi, &macLen);
	hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)responder,
		    strlen(responder), rs2IDr, &macLen);
    }
    else {
	hmac_sha256((unsigned char*)zidRec.getRs2(), RS_LENGTH,
		     (unsigned char*)initiator, strlen(initiator),
		     rs2IDi, &macLen);
	hmac_sha256((unsigned char*)zidRec.getRs2(), RS_LENGTH,
		     (unsigned char*)responder, strlen(responder),
		     rs2IDr, &macLen);
    }

    /*
    * For the time being we don't support these types of shared secrect. Could be
    * easily done: somebody sets some data into our ZRtp object, check it here
    * and use it. Otherwise use the random data.
    */
    randomZRTP(randBuf, RS_LENGTH);
    hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)initiator,
		strlen(initiator), sigsIDi, &macLen);
    hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)responder,
		strlen(responder), sigsIDr, &macLen);

    randomZRTP(randBuf, RS_LENGTH);
    hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)initiator,
		strlen(initiator), srtpsIDi, &macLen);
    hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)responder,
		strlen(responder), srtpsIDr, &macLen);

    randomZRTP(randBuf, RS_LENGTH);
    hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)initiator,
		strlen(initiator), otherSecretIDi, &macLen);
    hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)responder,
		strlen(responder), otherSecretIDr, &macLen);
}

/*
 * The DH packet for this function is DHPart1 and contains the Responder's
 * retained secret ids. Compare them with the expected secret ids (refer
 * to chapter 5.3.2 in the specification).
 */
void ZRtp::generateS0Initiator(ZrtpPacketDHPart *dhPart, ZIDRecord& zidRec) {
    const uint8_t* setD[5];
    int32_t rsFound = 0;

    setD[0] = setD[1] = setD[2] = setD[3] = setD[4] = NULL;

    /*
     * Select the real secrets into setD
     */
    int matchingSecrets = 0;
    if (memcmp(rs1IDr, dhPart->getRs1Id(), 8) == 0) {
	DEBUGOUT((fprintf(stdout, "%c: Match for Rs1 found\n", zid[0])));
        setD[matchingSecrets++] = zidRec.getRs1();
        rsFound = 0x1;
    }
    if (memcmp(rs2IDr, dhPart->getRs2Id(), 8) == 0) {
	DEBUGOUT((fprintf(stdout, "%c: Match for Rs2 found\n", zid[0])));
        setD[matchingSecrets++] = zidRec.getRs2();
        rsFound |= 0x2;
    }
    if (memcmp(sigsIDr, dhPart->getSigsId(), 8) == 0) {
	DEBUGOUT((fprintf(stdout, "%c: Match for SigS found\n", zid[0])));
        setD[matchingSecrets++] = zidRec.getRs2();
    }
    if (memcmp(srtpsIDr, dhPart->getSrtpsId(), 8) == 0) {
	DEBUGOUT((fprintf(stdout, "%c: Match for Srtps found\n", zid[0])));
        setD[matchingSecrets++] = zidRec.getRs2();
    }
    if (memcmp(otherSecretIDr, dhPart->getOtherSecretId(), 8) == 0) {
	DEBUGOUT((fprintf(stdout, "%c: Match for Other_secret found\n", zid[0])));
        setD[matchingSecrets++] = zidRec.getRs2();
    }

    // Check if some retained secrets found
    if (rsFound == 0) {
        sendInfo(Warning, "No retained secret matches - verify SAS");
    }
    if ((rsFound & 0x1) && (rsFound & 0x2)) {
        sendInfo(Info, "Both retained secrets match - security OK");
    }
    if ((rsFound & 0x1) && !(rsFound & 0x2)) {
        sendInfo(Warning, "Only the first retained secret matches - verify SAS");
    }
    if (!(rsFound & 0x1) && (rsFound & 0x2)) {
        sendInfo(Warning, "Only the second retained secret matches - verify SAS");
    }

    /*
     * Ready to generate s0 here.
     * The formular to compute S0 (Refer to ZRTP specification 5.4.4):
     *
      s0 = hash( counter | DHResult | "ZRTP-HMAC-KDF" | ZIDi | ZIDr | \
      total_hash | len(s1) | s1 | len(s2) | s2 | len(s3) | s3 | len(s4) | \
      s4 | len(s5) | s5 )
     *
     * Note: in this function we are Initiator, thus ZIDi is our zid 
     * (zid), ZIDr is the peer's zid (peerZid).
     */

    /*
     * These arrays hold the pointers and lengths of the data that must be
     * hashed to create S0.  According to the formula the max number of 
     * elements to hash is 16, add one for the terminating "NULL"
     */
    unsigned char* data[17];
    unsigned int   length[17];
    uint32_t pos = 0;                  // index into the array

    // we need a number of length data items, so define them here 
    uint32_t counter, sLen[5];

    //Very first element is a fixed counter, big endian 
    counter = 1;
    counter = htonl(counter);
    data[pos] = (unsigned char*)&counter;
    length[pos++] = sizeof(uint32_t);

    // Next is the DH result itself
    data[pos] = DHss;
    length[pos++] = dhContext->getSecretSize();

    // Next the fixed string "ZRTP-HMAC-KDF"
    data[pos] = (unsigned char*)KDFString;
    length[pos++] = strlen(KDFString);

    // Next is Initiator's id (ZIDi), in this case as Initiator 
    // it is zid 
    data[pos] = zid;
    length[pos++] = 3*ZRTP_WORD_SIZE;

    // Next is Responder's id (ZIDr), in this case our peer's id 
    data[pos] = peerZid;
    length[pos++] = 3*ZRTP_WORD_SIZE;

    // Next ist total hash (messageHash) itself 
    data[pos] = messageHash;
    length[pos++] = SHA256_DIGEST_LENGTH;

    /*
     * For each matching shared secret hash the length of 
     * the shared secret as 32 bit big-endian number followd by the 
     * shared secret itself. The length of a shared seceret is 
     * currently fixed to SHA256_DIGEST_LENGTH. If a shared 
     * secret is not used _only_ its length is hased as zero 
     * length. 
     */
    int secretHashLen = SHA256_DIGEST_LENGTH;
    secretHashLen = htonl(secretHashLen);        // prepare 32 bit big-endian number 

    for (int32_t i = 0; i < 5; i++) {
        if (setD[i] != NULL) {           // a matching secret, set length, then secret
            sLen[i] = secretHashLen;
            data[pos] = (unsigned char*)&sLen[i];
            length[pos++] = sizeof(uint32_t);
            data[pos] = (unsigned char*)setD[i];
            length[pos++] = SHA256_DIGEST_LENGTH;
        }
        else {                           // no machting secret, set length 0, skip secret
            sLen[i] = 0;
            data[pos] = (unsigned char*)&sLen[i];
            length[pos++] = sizeof(uint32_t);
        }
    }

    data[pos] = NULL;
    sha256(data, length, s0);
//  hexdump("S0 I", s0, SHA256_DIGEST_LENGTH);

    memset(DHss, 0, dhContext->getSecretSize());
    free(DHss);
    DHss = NULL;

    computeSRTPKeys();
}
/*
 * The DH packet for this function is DHPart2 and contains the Initiator's
 * retained secret ids. Compare them with the expected secret ids (refer
 * to chapter 5.3.1 in the specification).
 */
void ZRtp::generateS0Responder(ZrtpPacketDHPart *dhPart, ZIDRecord& zidRec) {
    const uint8_t* setD[5];
    int32_t rsFound = 0;

    setD[0] = setD[1] = setD[2] = setD[3] = setD[4] = NULL;

    /*
     * Select the real secrets into setD
     */
    int matchingSecrets = 0;
    if (memcmp(rs1IDi, dhPart->getRs1Id(), 8) == 0) {
	DEBUGOUT((fprintf(stdout, "%c: Match for Rs1 found\n", zid[0])));
        setD[matchingSecrets++] = zidRec.getRs1();
        rsFound = 0x1;
    }
    if (memcmp(rs2IDi, dhPart->getRs2Id(), 8) == 0) {
	DEBUGOUT((fprintf(stdout, "%c: Match for Rs2 found\n", zid[0])));
        setD[matchingSecrets++] = zidRec.getRs2();
        rsFound |= 0x2;
    }
    if (memcmp(sigsIDi, dhPart->getSigsId(), 8) == 0) {
	DEBUGOUT((fprintf(stdout, "%c: Match for SigS found\n", zid[0])));
        setD[matchingSecrets++] = zidRec.getRs2();
    }
    if (memcmp(srtpsIDi, dhPart->getSrtpsId(), 8) == 0) {
	DEBUGOUT((fprintf(stdout, "%c: Match for Srtps found\n", zid[0])));
        setD[matchingSecrets++] = zidRec.getRs2();
    }
    if (memcmp(otherSecretIDi, dhPart->getOtherSecretId(), 8) == 0) {
	DEBUGOUT((fprintf(stdout, "%c: Match for Other_secret found\n", zid[0])));
        setD[matchingSecrets++] = zidRec.getRs2();
    }

    // Check if some retained secrets found
    if (rsFound == 0) {
        sendInfo(Warning, "No retained secret matches - verify SAS");
    }
    if ((rsFound & 0x1) && (rsFound & 0x2)) {
        sendInfo(Info, "Both retained secrets match - security OK");
    }
    if ((rsFound & 0x1) && !(rsFound & 0x2)) {
        sendInfo(Warning, "Only the first retained secret matches - verify SAS");
    }
    if (!(rsFound & 0x1) && (rsFound & 0x2)) {
        sendInfo(Warning, "Only the second retained secret matches - verify SAS");
    }

    /*
     * ready to generate s0 here.
     * The formular to compute S0 (Refer to ZRTP specification 5.4.4):
     *
      s0 = hash( counter | DHResult | "ZRTP-HMAC-KDF" | ZIDi | ZIDr | \
      total_hash | len(s1) | s1 | len(s2) | s2 | len(s3) | s3 | len(s4) | \
      s4 | len(s5) | s5 )
     *
     * Note: in this function we are Responder, thus ZIDi is the peer's zid 
     * (peerZid), ZIDr is our zid.
     */

    /*
     * These arrays hold the pointers and lengths of the data that must be
     * hashed to create S0.  According to the formula the max number of 
     * elements to hash is 16, add one for the terminating "NULL"
     */
    unsigned char* data[17];
    unsigned int   length[17];
    uint32_t pos = 0;                  // index into the array


    // we need a number of length data items, so define them here 
    uint32_t counter, sLen[5];

    //Very first element is a fixed counter, big endian 
    counter = 1;
    counter = htonl(counter);
    data[pos] = (unsigned char*)&counter;
    length[pos++] = sizeof(uint32_t);

    // Next is the DH result itself
    data[pos] = DHss;
    length[pos++] = dhContext->getSecretSize();

    // Next the fixed string "ZRTP-HMAC-KDF"
    data[pos] = (unsigned char*)KDFString;
    length[pos++] = strlen(KDFString);

    // Next is Initiator's id (ZIDi), in this case as Responder 
    // it is peerZid 
    data[pos] = peerZid;
    length[pos++] = 3*ZRTP_WORD_SIZE;

    // Next is Responder's id (ZIDr), in this case our own zid 
    data[pos] = zid;
    length[pos++] = 3*ZRTP_WORD_SIZE;

    // Next ist total hash (messageHash) itself 
    data[pos] = messageHash;
    length[pos++] = SHA256_DIGEST_LENGTH;

    /*
     * For each matching shared secret hash the length of 
     * the shared secret as 32 bit big-endian number followd by the 
     * shared secret itself. The length of a shared seceret is 
     * currently fixed to SHA256_DIGEST_LENGTH. If a shared 
     * secret is not used _only_ its length is hased as zero 
     * length. 
     */
    int secretHashLen = SHA256_DIGEST_LENGTH;
    secretHashLen = htonl(secretHashLen);        // prepare 32 bit big-endian number 

    for (int32_t i = 0; i < 5; i++) {
        if (setD[i] != NULL) {           // a matching secret, set length, then secret
            sLen[i] = secretHashLen;
            data[pos] = (unsigned char*)&sLen[i];
            length[pos++] = sizeof(uint32_t);
            data[pos] = (unsigned char*)setD[i];
            length[pos++] = SHA256_DIGEST_LENGTH;
        }
        else {                           // no machting secret, set length 0, skip secret
            sLen[i] = 0;
            data[pos] = (unsigned char*)&sLen[i];
            length[pos++] = sizeof(uint32_t);
        }
    }

    data[pos] = NULL;
    sha256(data, length, s0);
//  hexdump("S0 R", s0, SHA256_DIGEST_LENGTH);

    memset(DHss, 0, dhContext->getSecretSize());
    free(DHss);
    DHss = NULL;

    computeSRTPKeys();
}

void ZRtp::computeSRTPKeys() {

    uint32_t macLen;

    // Inititiator key and salt
    hmac_sha256(s0, SHA256_DIGEST_LENGTH, (unsigned char*)iniMasterKey, strlen(iniMasterKey),
                srtpKeyI, &macLen);
    hmac_sha256(s0, SHA256_DIGEST_LENGTH, (unsigned char*)iniMasterSalt, strlen(iniMasterSalt),
                srtpSaltI, &macLen);

    // Responder key and salt
    hmac_sha256(s0, SHA256_DIGEST_LENGTH, (unsigned char*)respMasterKey, strlen(respMasterKey),
                srtpKeyR, &macLen);
    hmac_sha256(s0, SHA256_DIGEST_LENGTH, (unsigned char*)respMasterSalt, strlen(respMasterSalt),
                srtpSaltR, &macLen);

    // The HMAC keys for GoClear
    hmac_sha256(s0, SHA256_DIGEST_LENGTH, (unsigned char*)iniHmacKey, strlen(iniHmacKey),
                hmacKeyI, &macLen);
    hmac_sha256(s0, SHA256_DIGEST_LENGTH, (unsigned char*)respHmacKey, strlen(respHmacKey),
                hmacKeyR, &macLen);

    // The keys for Confirm messages
    hmac_sha256(s0, SHA256_DIGEST_LENGTH, (unsigned char*)iniZrtpKey, strlen(iniZrtpKey),
                zrtpKeyI, &macLen);
    hmac_sha256(s0, SHA256_DIGEST_LENGTH, (unsigned char*)respZrtpKey, strlen(respZrtpKey),
                zrtpKeyR, &macLen);

    // Compute the new Retained Secret
    hmac_sha256(s0, SHA256_DIGEST_LENGTH, (unsigned char*)retainedSec, strlen(retainedSec),
                newRs1, &macLen);

    // Compute the ZRTP Session Key
    hmac_sha256(s0, SHA256_DIGEST_LENGTH, (unsigned char*)zrtpSessionKey, strlen(zrtpSessionKey),
                zrtpSession, &macLen);

    // perform SAS generation according to chapter 5.5 and 8.
    // we don't need a speciai sasValue filed. sasValue are the first 
    // (leftmost) 32 bits (4 bytes) of sasHash
    uint8_t sasBytes[4];
    hmac_sha256(zrtpSession, SHA256_DIGEST_LENGTH, (unsigned char*)sasString, strlen(sasString),
                sasHash, &macLen);

    // according to chapter 8 only the leftmost 20 bits of sasValue (aka
    //  sasHash) are used to create the character SAS string of type SAS 
    // base 32 (5 bits per character)
    sasBytes[0] = sasHash[0];
    sasBytes[1] = sasHash[1];
    sasBytes[2] = sasHash[2] & 0xf0;
    sasBytes[3] = 0;
    SAS = Base32(sasBytes, 20).getEncoded();
}

bool ZRtp::srtpSecretsReady(EnableSecurity part) {

    SrtpSecret_t sec;

    sec.keyInitiator = srtpKeyI;
    sec.initKeyLen = (cipher == Aes128) ? 128 :256;
    sec.saltInitiator = srtpSaltI;
    sec.initSaltLen = 112;
    sec.keyResponder = srtpKeyR;
    sec.respKeyLen = (cipher == Aes128) ? 128 :256;
    sec.saltResponder = srtpSaltR;
    sec.respSaltLen = 112;
    sec.srtpAuthTagLen = (authLength == AuthLen32) ? 32 : 80;
    sec.sas = SAS;
    sec.role = myRole;

    return callback->srtpSecretsReady(&sec, part);
}

void ZRtp::srtpSecretsOff(EnableSecurity part) {
    callback->srtpSecretsOff(part);
}

void ZRtp::SASVerified()
{
    // Initialize a ZID record to get peer's retained secrets
    ZIDRecord zidRec(peerZid);
    ZIDFile *zid = ZIDFile::getInstance();

    zid->getRecord(&zidRec);
    zidRec.setSasVerified();
    zid->saveRecord(&zidRec);
}

void ZRtp::resetSASVerified()
{
    // Initialize a ZID record to get peer's retained secrets
    ZIDRecord zidRec(peerZid);
    ZIDFile *zid = ZIDFile::getInstance();

    zid->getRecord(&zidRec);
    zidRec.resetSasVerified();
    zid->saveRecord(&zidRec);
}

int32_t ZRtp::sendPacketZRTP(ZrtpPacketBase *packet) {
    return ((packet == NULL) ? 0 :
            callback->sendDataZRTP(packet->getHeaderBase(), (packet->getLength() * 4) + 4));
}

void ZRtp::setSigsSecret(uint8_t* data)
{
}

void ZRtp::setSrtpsSecret(uint8_t* data)
{
}

void ZRtp::setOtherSecret(uint8_t* data, int32_t length)
{
}

void ZRtp::setClientId(std::string id) {
    const char* tmp = "            ";

    if (id.size() < 3*ZRTP_WORD_SIZE) {
        zrtpHello.setClientId((unsigned char*)tmp);
    }
    zrtpHello.setClientId((unsigned char*)id.c_str());
    int32_t len = zrtpHello.getLength() * ZRTP_WORD_SIZE;

    // Hello packet is ready now, compute its HMAC
    // (excluding the HMAC field (2*ZTP_WORD_SIZE)) and store in Hello
    uint8_t hmac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;
    hmac_sha256(H2, SHA256_DIGEST_LENGTH, (uint8_t*)zrtpHello.getHeaderBase(), 
                len-(2*ZRTP_WORD_SIZE), hmac, &macLen);
    zrtpHello.setHMAC(hmac);

    // calculate hash over the final Hello packet, refer to chap 9.1 how to
    // use this hash in SIP/SDP
    sha256((uint8_t*)zrtpHello.getHeaderBase(), len, helloHash);
}

void ZRtp::storeMsgTemp(ZrtpPacketBase* pkt) {
    int32_t length = pkt->getLength() * ZRTP_WORD_SIZE;
    memset(tempMsgBuffer, 0, sizeof(tempMsgBuffer));
    memcpy(tempMsgBuffer, (uint8_t*)pkt->getHeaderBase(), length);
    lengthOfMsgData = length;
}

bool ZRtp::checkMsgHmac(uint8_t* key) {
    uint8_t hmac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;
    int32_t len = lengthOfMsgData-(2*ZRTP_WORD_SIZE);  // compute HMAC, but exlude the stored HMAC :-)

    hmac_sha256(key, SHA256_DIGEST_LENGTH, tempMsgBuffer, len, hmac, &macLen);
    return (memcmp(hmac, tempMsgBuffer+len, (2*ZRTP_WORD_SIZE)) == 0 ? true : false);
}


std::string ZRtp::getHelloHash() {
    std::ostringstream stm;

    uint8_t* hp = helloHash;

    stm << hex;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        stm << static_cast<uint32_t>(*hp++);
    }
    return stm.str();
}

std::string ZRtp::getSasData() {
    std::ostringstream stm;

    uint8_t* hp = sasHash;

    if (!inState(SecureState)) {
        return std::string();
    }

    // create  the zrtp-sas-attribute according to chapter 9.4:
    // first the SAS string, a blank, then leftmost 64 bit of sasHash in hex
    stm << SAS << ' ' << hex;
    for (int i = 0; i < 8; i++) {
        stm << static_cast<uint32_t>(*hp++);
    }
    return stm.str();
}

std::string ZRtp::getMultiStrParams() {

    // the string will hold binary data - it's opaque to the application
    std::string str;
    char tmp[SHA256_DIGEST_LENGTH + 1 + 1]; // digest length + cipher + authLength

    if (inState(SecureState) && !multiStream) {
        // construct array that holds zrtpSession, cipher type and auth-length
        memcpy(tmp, zrtpSession, SHA256_DIGEST_LENGTH);
        tmp[SHA256_DIGEST_LENGTH] = cipher;          //cipher is enumeration (int)
        tmp[SHA256_DIGEST_LENGTH + 1] = authLength;  //authLength is enumeration (int)
        str.assign(tmp, 0, SHA256_DIGEST_LENGTH + 1 + 1);   // set chars (bytes) to the string
    }
    return str;
}

void ZRtp::setMultiStrParams(std::string parameters) {

    char tmp[SHA256_DIGEST_LENGTH + 1 + 1]; // digest length + cipher + authLength

    // use string.copy(buffer, num, start=0) to retrieve chars (bytes) from the string
    parameters.copy(tmp, SHA256_DIGEST_LENGTH + 1 + 1, 0);

    memcpy(zrtpSession, tmp, SHA256_DIGEST_LENGTH);
    cipher = static_cast<SupportedSymCiphers>(tmp[SHA256_DIGEST_LENGTH]);
    authLength = static_cast<SupportedAuthLengths>(tmp[SHA256_DIGEST_LENGTH + 1]);

    // after setting zrtpSession, cipher and auth-length set multi-stream to true
    // TODO - enable this only after multi-stream is really implemented and tested
//    multiStream = true;
//    stateEngine->setMultiStream(true);
}

bool ZRtp::isMultiStream() {
    return multiStream;
}

void ZRtp::acceptEnrollment(bool accepted) {
    return;
}

bool ZRtp::setSignatureData(uint8_t* data, int32_t length) {
    return false;
}

int32_t ZRtp::getSignatureData(uint8_t* data) {
    return 0;
}

int32_t ZRtp::getSignatureLength() {
    return 0;
}

int32_t ZRtp::compareCommit(ZrtpPacketCommit *commit) {
    // TODO: enhance to compare according to rules defined in chapter 5.2
    return (memcmp(hvi, commit->getHvi(), SHA256_DIGEST_LENGTH)); 
}

void ZRtp:: setPBXEnrollment(bool yesNo) {
    PBXEnrollment = yesNo;
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
