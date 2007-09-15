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

ZRtp::ZRtp(uint8_t *myZid, ZrtpCallback *cb):
    callback(cb), dhContext(NULL) {

    DHss = NULL;
    zpDH2 = NULL;

    memcpy(zid, myZid, 12);
    zrtpHello.setZid(zid);

    msgShaContext = createSha256Context(); // prepare for Initiator case

    stateEngine = new ZrtpStateClass(this);
}

ZRtp::~ZRtp() {
    stopZrtp();

    if (DHss != NULL) {
	free(DHss);
        DHss = NULL;
    }
    if (zpDH2 != NULL) {
	delete zpDH2;
	zpDH2 = NULL;
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

    /*
     * If we need to stop the state engine before we reached SecureState
     * reset to initial state only. This state ignores any event except
     * ZrtpInitial and effectively stops the engine.
     */
    if (stateEngine != NULL) {
        if (!stateEngine->inState(SecureState)) {
            stateEngine->nextState(Initial);
            return;
        }
        ev.type = ZrtpClose;
        stateEngine->processEvent(&ev);
    }
}

int32_t ZRtp::checkState(int32_t state)
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

    /*
     * The Following section extracts the algorithm from the Hello
     * packet. Always the best possible (offered) algorithms are
     * used.
     */
    cipher = findBestCipher(hello);
    if (cipher >= NumSupportedSymCiphers) {
        *errMsg = UnsuppCiphertype;
	sendInfo(Error, "Hello message does not contain a supported Cipher");
	return NULL;
    }
    hash = findBestHash(hello);
    if (hash >= NumSupportedHashes) {
        *errMsg = UnsuppHashType;
	sendInfo(Error, "Hello message does not contain a supported Hash");
	return NULL;
    }
    pubKey = findBestPubkey(hello);
    if (pubKey >= NumSupportedPubKeys) {
        *errMsg = UnsuppPKExchange;
	sendInfo(Error, "Hello message does not contain a supported public key algorithm");
	return NULL;
    }
    sasType = findBestSASType(hello);
    if (sasType >= NumSupportedSASTypes) {
        *errMsg = UnsuppSASScheme;
	sendInfo(Error, "Hello message does not contain a supported SAS algorithm");
	return NULL;
    }
    authLength = findBestAuthLen(hello);
    if (authLength >= NumSupportedAuthLenghts) {
        *errMsg = UnsuppSRTPAuthTag;
        sendInfo(Error, "Hello message does not contain a supported authentication length");
        return NULL;
    }

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
    // This is done in advance to that we can destroy the DH data at the 
    // earliest posible time.
    dhContext->random(randomIV, sizeof(randomIV));

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
    // is required to compute the HVI (Hash Value Initiator).
    zpDH2 = new ZrtpPacketDHPart(pubKey);

    // Fill the values in the DHPart2 packet
    zpDH2->setMessageType((uint8_t*)DHPart2Msg);
    zpDH2->setRs1Id(rs1IDi);
    zpDH2->setRs2Id(rs2IDi);
    zpDH2->setSigsId(sigsIDi);
    zpDH2->setSrtpsId(srtpsIDi);
    zpDH2->setOtherSecretId(otherSecretIDi);
    zpDH2->setPv(pubKeyBytes);

    // Compute the HVI, refer to chapter 5.4.1 of the specification
    computeHvi(zpDH2, hello);

    ZrtpPacketCommit *commit = new ZrtpPacketCommit();
    commit->setZid(zid);
    commit->setHashType((uint8_t*)supportedHashes[hash]);
    commit->setCipherType((uint8_t*)supportedCipher[cipher]);
    commit->setAuthLen((uint8_t*)supportedAuthLen[authLength]);
    commit->setPubKeyType((uint8_t*)supportedPubKey[pubKey]);
    commit->setSasType((uint8_t*)supportedSASType[sasType]);
    commit->setHvi(hvi);

    // hash first messages to produce overall message hash
    // First the Responder's Hello message, second the Commit 
    // (always Initator's)
    sha256Ctx(msgShaContext, (unsigned char*)hello->getHeaderBase(), hello->getLength() * ZRTP_WORD_SIZE);
    sha256Ctx(msgShaContext, (unsigned char*)commit->getHeaderBase(), commit->getLength() * ZRTP_WORD_SIZE);
    return commit;
}

/*
 * At this point we will take the role of the Responder. We may have been in 
 * the role of the Initiator before and already sent a commit packet that
 * clashed with a commit packet from our peer. If our HVI was lower than out
 * peer's HVI the we switched to Responder and handle our peer's commit packet
 * here. This method takes care to delete and refresh data left over from a
 * possible Initiator preparation. This belongs to a prepared DHPart2 packet,
 * DH data, message hash SHA context
 */
ZrtpPacketDHPart* ZRtp::prepareDHPart1(ZrtpPacketCommit *commit, uint32_t* errMsg) {

    int i;

    sendInfo(Info, "Responder: Commit received, preparing DHPart1");

    // check if we support the commited Cipher type
    uint8_t *cp = commit->getCipherType();
    for (i = 0; i < NumSupportedSymCiphers; i++) {
	if (!memcmp(cp, supportedCipher[i], ZRTP_WORD_SIZE)) {
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
    cp = commit->getAuthLen();
    for (i = 0; i < NumSupportedAuthLenghts; i++) {
        if (!memcmp(cp, supportedAuthLen[i], ZRTP_WORD_SIZE)) {
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
    cp = commit->getHashType();
    for (i = 0; i < NumSupportedHashes; i++) {
        if (!memcmp(cp, supportedHashes[i], ZRTP_WORD_SIZE)) {
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
    cp = commit->getPubKeysType();
    for (i = 0; i < NumSupportedPubKeys; i++) {
        if (!memcmp(cp, supportedPubKey[i], ZRTP_WORD_SIZE)) {
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
    cp = commit->getSasType();
    for (i = 0; i < NumSupportedSASTypes; i++) {
        if (!memcmp(cp, supportedSASType[i], ZRTP_WORD_SIZE)) {
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

    if (cipher == Aes256 && pubKey != Dh4096) {
        sendInfo(Warning, "Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096");
        // generate a warning
    }

    // check if a cleanup is required 
    if (dhContext != NULL) {
        delete dhContext;
        dhContext = NULL;
    }
    // setup the DH context and generate a fresh DH key pair
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

    /*
     * If a DH2 packet was computed then also the retained secret ids were
     * computed. This maybe a leftover acting as Initiator. Delete the DH2
     * packet only and keep the computed retained secretd ids. 
     * If no DH2 packet exists just compute the reteined secrets.
     */
    if (zpDH2 != NULL) {        // DH2 and retained secrets already computed but
        delete zpDH2;           // we are responder, DH2 packet not needed anymore
        zpDH2 = NULL;
    }
    else {                      // need to compute retained secrets
        // We may have not received a Hello at all at this point .
        // Set our peer's ZID
        memcpy(peerZid, commit->getZid(), 12);

        // prepare IV data that we will use during confirm packet handling.
        // if a DH2 packet was created then we switched roles and an IV was
        // already generated (see prepareCommit() )
        dhContext->random(randomIV, sizeof(randomIV));

        // Initialize a ZID record to get retained secrets for this peer
        ZIDRecord zidRec(peerZid);	
        ZIDFile *zid = ZIDFile::getInstance();
        zid->getRecord(&zidRec);

        /*
         * Compute the shared Secret Ids. Because here we are responder the real
         * keys, salt, and HAMACS are computed after we got the DHPart2.
         */
        computeSharedSecretSet(zidRec);
    }

    // Construct and setup a DHPart1 packet.
    ZrtpPacketDHPart *zpDH = new ZrtpPacketDHPart(pubKey);
    zpDH->setMessageType((uint8_t*)DHPart1Msg);
    zpDH->setRs1Id(rs1IDr);
    zpDH->setRs2Id(rs2IDr);
    zpDH->setSigsId(sigsIDr);
    zpDH->setSrtpsId(srtpsIDr);
    zpDH->setOtherSecretId(otherSecretIDr);
    zpDH->setPv(pubKeyBytes);

    // We are definitly responder. Save the peer's hvi for later compare.
    myRole = Responder;
    memcpy(peerHvi, commit->getHvi(), SHA256_DIGEST_LENGTH);

    // Because we are responder close a possibly pre-computed SHA256 context
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
    sha256Ctx(msgShaContext, (unsigned char*)zpDH->getHeaderBase(),
              zpDH->getLength() * ZRTP_WORD_SIZE);

    return zpDH;
}

/*
 * At this point we will take the role of the Initiator.
 */
ZrtpPacketDHPart* ZRtp::prepareDHPart2(ZrtpPacketDHPart *dhPart1, uint32_t* errMsg) {

    uint8_t* pvr;
    uint8_t sas[SHA256_DIGEST_LENGTH+1];

    sendInfo(Info, "Initiator: DHPart1 received, preparing DHPart2");

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

    // Get precomputed DHPart2 packet and set internal pointer to NULL. The
    // DHPart2 packet is handed over to ZrtpStateClass. The method 
    // evWaitConfirm1() deletes this packet after it was sent to our peer.
    ZrtpPacketDHPart *zpDH = zpDH2;
    zpDH2 = NULL;

    myRole = Initiator;

    // We are Inititaor: the Responder's Hello and the Initiator's (our) Commit
    // are already hashed in the context. Now hash the Responder's DH1 and then
    // the Initiator's (our) DH2 in that order.
    sha256Ctx(msgShaContext, (unsigned char*)dhPart1->getHeaderBase(), dhPart1->getLength() * ZRTP_WORD_SIZE);
    sha256Ctx(msgShaContext, (unsigned char*)zpDH->getHeaderBase(), zpDH->getLength() * ZRTP_WORD_SIZE);

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

    return zpDH;
}

/*
 * At this point we are Responder.
 */
ZrtpPacketConfirm* ZRtp::prepareConfirm1(ZrtpPacketDHPart* dhPart2, uint32_t* errMsg) {

    uint8_t* pvi;
    uint8_t sas[SHA256_DIGEST_LENGTH+1];

    sendInfo(Info, "Responder: DHPart2 received, preparing Confirm1");

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

    // Create a Confirm1 packet and fill it.
    ZrtpPacketConfirm* zpConf = new ZrtpPacketConfirm(static_cast<uint8_t>(0));
    zpConf->setMessageType((uint8_t*)Confirm1Msg);

    // Check if user verfied the SAS in a previous call and thus verfied
    // the retained secret.
    if (zidRec.isSasVerified()) {
        zpConf->setSASFlag();
    }
    zpConf->setExpTime(0xFFFFFFFF);
    zpConf->setIv(randomIV);

    uint8_t confMac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;

    // Encrypt and HMAC with Responder's key - we are Respondere here
    int16_t hmlen = (zpConf->getLength() - 9) * ZRTP_WORD_SIZE;
    aesCfbEncrypt(zrtpKeyR, (cipher == Aes128) ? 16 : 32, randomIV,
                  (unsigned char*)zpConf->getFiller(), hmlen);
    hmac_sha256(hmacKeyR, SHA256_DIGEST_LENGTH, (unsigned char*)zpConf->getFiller(),
                hmlen, confMac, &macLen);

    zpConf->setHmac(confMac);
    return zpConf;
}

ZrtpPacketConfirm* ZRtp::prepareConfirm2(ZrtpPacketConfirm *confirm1, uint32_t* errMsg) {

    sendInfo(Info, "Initiator: Confirm1 received, preparing Confirm2");

    uint8_t confMac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;

    // Use the Responder's keys here because we are Initiator here and
    // receive packets from Responder
    int16_t hmlen = (confirm1->getLength() - 9) * ZRTP_WORD_SIZE;
    hmac_sha256(hmacKeyR, SHA256_DIGEST_LENGTH, (unsigned char*)confirm1->getFiller(),
                hmlen, confMac, &macLen);

    if (memcmp(confMac, confirm1->getHmac(), 2*ZRTP_WORD_SIZE) != 0) {
        *errMsg = ConfirmHMACWrong;
        sendInfo(Error, "HMAC verification of Confirm1 message failed");
        return NULL;
    }
    aesCfbDecrypt(zrtpKeyR, (cipher == Aes128) ? 16 : 32, 
                  (unsigned char*)confirm1->getIv(),
                  (unsigned char*)confirm1->getFiller(), hmlen);
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
    const char* c = (cipher == Aes128) ? "AES-CM-128" : "AES-CM-256";
    const char* s = (zidRec.isSasVerified()) ? NULL : SAS.c_str();
    callback->srtpSecretsOn(c, s);

    // now we are ready to save the new RS1 which inherits the verified
    // flag from old RS1
    zidRec.setNewRs1((const uint8_t*)newRs1);
    zid->saveRecord(&zidRec);

    // now generate my Confirm2 message
    ZrtpPacketConfirm* zpConf = new ZrtpPacketConfirm(static_cast<uint8_t>(0));
    zpConf->setMessageType((uint8_t*)Confirm2Msg);
    if (sasFlag) {
        zpConf->setSASFlag();
    }
    zpConf->setExpTime(0xFFFFFFFF);
    zpConf->setIv(randomIV);

    // Encrypt and HMAC with Initiator's key - we are Initiator here
    hmlen = (zpConf->getLength() - 9) * ZRTP_WORD_SIZE;
    aesCfbEncrypt(zrtpKeyI, (cipher == Aes128) ? 16 : 32, randomIV,
                  (unsigned char*)zpConf->getFiller(), hmlen);
    hmac_sha256(hmacKeyI, SHA256_DIGEST_LENGTH, (unsigned char*)zpConf->getFiller(),
                hmlen, confMac, &macLen);

    zpConf->setHmac(confMac);
    return zpConf;
}

ZrtpPacketConf2Ack* ZRtp::prepareConf2Ack(ZrtpPacketConfirm *confirm2, uint32_t* errMsg) {

    sendInfo(Info, "Responder: Confirm2 received, preparing Conf2Ack");

    uint8_t confMac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;

    // Use the Initiator's keys here because we are Responder here and
    // reveice packets from Initiator
    int16_t hmlen = (confirm2->getLength() - 9) * ZRTP_WORD_SIZE;
    hmac_sha256(hmacKeyI, SHA256_DIGEST_LENGTH, (unsigned char*)confirm2->getFiller(),
                hmlen, confMac, &macLen);

    if (memcmp(confMac, confirm2->getHmac(), 2*ZRTP_WORD_SIZE) != 0) {
        *errMsg = ConfirmHMACWrong;
        sendInfo(Error, "HMAC verification of Confirm2 message failed");
        return NULL;
    }
    aesCfbDecrypt(zrtpKeyI, (cipher == Aes128) ? 16 : 32, 
                  (unsigned char*)confirm2->getIv(),
                  (unsigned char*)confirm2->getFiller(), hmlen);

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
    const char* c = (cipher == Aes128) ? "AES-CM-128" : "AES-CM-256";
    const char* s = (zidRec.isSasVerified()) ? NULL : SAS.c_str();
    callback->srtpSecretsOn(c, s);

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

void ZRtp::computeHvi(ZrtpPacketDHPart* dh, ZrtpPacketHello *hello) {

    unsigned char* data[3];
    unsigned int length[3];
    /*
     * populate the vector to compute the HVI hash according to the
     * ZRTP specification.
     */
    data[0] = (uint8_t*)dh->getHeaderBase();;
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
	dhContext->random(randBuf, RS_LENGTH);
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
	dhContext->random(randBuf, RS_LENGTH);
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
    dhContext->random(randBuf, RS_LENGTH);
    hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)initiator,
		strlen(initiator), sigsIDi, &macLen);
    hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)responder,
		strlen(responder), sigsIDr, &macLen);

    dhContext->random(randBuf, RS_LENGTH);
    hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)initiator,
		strlen(initiator), srtpsIDi, &macLen);
    hmac_sha256(randBuf, RS_LENGTH, (unsigned char*)responder,
		strlen(responder), srtpsIDr, &macLen);

    dhContext->random(randBuf, RS_LENGTH);
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
//    hexdump("S0 (R)", s0, 32);

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

     // perform SAS generation
    uint32_t sasTemp;
    uint8_t sasBytes[4];
    uint8_t hmacTmp[SHA256_DIGEST_LENGTH];

    hmac_sha256(hmacKeyI, SHA256_DIGEST_LENGTH, (unsigned char*)sasString, strlen(sasString),
                hmacTmp, &macLen);
    memcpy(sasValue, hmacTmp, sizeof(sasValue));

    sasBytes[0] = sasValue[0];
    sasBytes[1] = sasValue[1];
    sasBytes[2] = sasValue[2] & 0xf0;
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
}


/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
