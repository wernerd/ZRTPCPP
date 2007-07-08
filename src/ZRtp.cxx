/*
  Copyright (C) 2006 - 2007 Werner Dittmann

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Boston, MA 02111.
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

ZrtpPacketCommit* ZRtp::prepareCommit(ZrtpPacketHello *hello, uint8_t** errMsg) {

    sendInfo(Info, "Hello received, preparing a Commit");

    uint8_t* cid = hello->getClientId();
    memcpy(peerZid, hello->getZid(), 12);

    cipher = findBestCipher(hello);
    if (cipher >= NumSupportedSymCiphers) {
	sendInfo(Error, "Hello message does not contain a supported Cipher");
	return NULL;
    }
    hash = findBestHash(hello);
    if (hash >= NumSupportedHashes) {
	sendInfo(Error, "Hello message does not contain a supported Hash");
	return NULL;
    }
    pubKey = findBestPubkey(hello);
    if (pubKey >= NumSupportedPubKeys) {
	sendInfo(Error, "Hello message does not contain a supported public key algorithm");
	return NULL;
    }
    sasType = findBestSASType(hello);
    if (sasType >= NumSupportedSASTypes) {
	sendInfo(Error, "Hello message does not contain a supported SAS algorithm");
	return NULL;
    }
    authLength = findBestAuthLen(hello);
    if (authLength >= NumSupportedAuthLenghts) {
        sendInfo(Error, "Hello message does not contain a supported authentication length");
        return NULL;
    }

    if (cipher == Aes256 && pubKey != Dh4096) {
	sendInfo(Warning, "Hello offers an AES256 cipher but does not offer a Diffie-Helman 4096");
    }

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
	return NULL;
	// Error - shouldn't happen
    }
    dhContext->generateKey();
    pubKeyLen = dhContext->getPubKeySize();
    dhContext->getPubKeyBytes(pubKeyBytes);

    // prepare IV data that we will use during confirm packet encryption
    dhContext->random(randomIV, sizeof(randomIV));

    /*
     * At this point the code acts as it will take the role of Initiator.
     * Note, if the protocol receives a commit immediatly after it sent its
     * hello then this code is not executed - this is taken care of at
     * prepareDHPart1()
     */

    // Prepare our DHPart2 packet here. Required to compute HVI. If we stay
    // in Initiator role then we reuse this packet later in prepareDHPart2().

    // Initialize a ZID record to get to retained secrets for this peer
    ZIDRecord zidRec(peerZid);

    // ZID file should be opened during initialization step, not here.
    // Thus get the singleton instance to the open file
    ZIDFile *zidFile = ZIDFile::getInstance();
    zidFile->getRecord(&zidRec);
    /*
     * After the next function call my set of shared secrets and the expected
     * set of shared secrets are ready. The expected shared secrets are in the
     * *r variables.
     */
    computeSharedSecretSet(zidRec);

    zpDH2 = new ZrtpPacketDHPart(pubKey);

    // Fill the values in the DHPart2 packet
    zpDH2->setMessageType((uint8_t*)DHPart2Msg);
    zpDH2->setRs1Id(rs1IDi);
    zpDH2->setRs2Id(rs2IDi);
    zpDH2->setSigsId(sigsIDi);
    zpDH2->setSrtpsId(srtpsIDi);
    zpDH2->setOtherSecretId(otherSecretIDi);

    // here the public key value
    zpDH2->setPv(pubKeyBytes);
    computeHvi(zpDH2, hello);

    char buffer[128];
    snprintf((char *)buffer, 128, "Commit: Generated a public DH key of size: %d", dhContext->getPubKeySize());
    sendInfo(Info, buffer);

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

ZrtpPacketDHPart* ZRtp::prepareDHPart1(ZrtpPacketCommit *commit, uint8_t** errMsg) {

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
	sendInfo(Alert, "Cannot find a supported SAS algorithm in Commit message");
	return NULL;
    }
    sasType = (SupportedSASTypes)i;

    if (dhContext != NULL) {
	delete dhContext;
    }

    int32_t maxPubKeySize;

    if (cipher == Aes256 && pubKey != Dh4096) {
	sendInfo(Warning, "Commit contains an AES256 cipher but does not offer a Diffie-Helman 4096");
	// generate a warning
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
	return NULL;
	// Error - shouldn't happen
    }
    // prepare IV data that we will use during confirm packet handling
    dhContext->random(randomIV, sizeof(randomIV));

    dhContext->generateKey();
    pubKeyLen = dhContext->getPubKeySize();

    char buffer[128];
    snprintf(buffer, 128, "DH1Part: Generated a public DH key of size: %d", pubKeyLen);
    sendInfo(Info, buffer);

    if (pubKeyLen > maxPubKeySize) {
	snprintf(buffer, 128, "Generated DH public key too big: %d, max: %d", pubKeyLen, maxPubKeySize);
	sendInfo(Error, buffer);
	return NULL;
    }
    dhContext->getPubKeyBytes(pubKeyBytes);

    if (zpDH2 != NULL) {	// DH2 and retained secrets already computed but
	delete zpDH2;		// we are responder, DH2 packet not needed anymore
	zpDH2 = NULL;
    }
    else {			// need to compute retained secrets
	// Initialize a ZID record to get retained secrets for this peer
	memcpy(peerZid, commit->getZid(), 12);
	ZIDRecord zidRec(peerZid);
	
	// ZID file should be opened during initialization step, not here
	// thus get the singleton instance to the open file
	ZIDFile *zid = ZIDFile::getInstance();
	zid->getRecord(&zidRec);
	
	/*
	 * Compute the shared Secret Ids. Because here we are responder the real
	 * keys, salt, and HAMACS are computed after we got the DHPart2.
	 */
	computeSharedSecretSet(zidRec);
    }
    ZrtpPacketDHPart *zpDH = new ZrtpPacketDHPart(pubKey);

    // Fill the values in the DHPart1 packet
    zpDH->setMessageType((uint8_t*)DHPart1Msg);
    zpDH->setRs1Id(rs1IDr);
    zpDH->setRs2Id(rs2IDr);
    zpDH->setSigsId(sigsIDr);
    zpDH->setSrtpsId(srtpsIDr);
    zpDH->setOtherSecretId(otherSecretIDr);

    // here the public key value
    zpDH->setPv(pubKeyBytes);

    // We are definitly responder. Save the peer's hvi for later compare.
    myRole = Responder;
    memcpy(peerHvi, commit->getHvi(), SHA256_DIGEST_LENGTH);

    // Because we are responder close a pre-computed
    // SHA256 context because this was prepared for Initiator.
    if (msgShaContext != NULL) {
        closeSha256Context(msgShaContext, NULL);
    }
    msgShaContext = createSha256Context();

    // Hash messages to produce overall message hash:
    // First the Responder's (my) Hello message, second the Commit 
    // (always Initator's), then the DH1 message (which is always a 
    // Responder's message)
    sha256Ctx(msgShaContext, (unsigned char*)zrtpHello.getHeaderBase(), zrtpHello.getLength() * ZRTP_WORD_SIZE);
    sha256Ctx(msgShaContext, (unsigned char*)commit->getHeaderBase(), commit->getLength() * ZRTP_WORD_SIZE);
    sha256Ctx(msgShaContext, (unsigned char*)zpDH->getHeaderBase(), zpDH->getLength() * ZRTP_WORD_SIZE);

    return zpDH;
}

ZrtpPacketDHPart* ZRtp::prepareDHPart2(ZrtpPacketDHPart *dhPart1, uint8_t** errMsg) {

    uint8_t* pvr;
    uint8_t sas[SHA256_DIGEST_LENGTH+1];

    sendInfo(Info, "Initiator: DHPart1 received, preparing DHPart2");

    DHss = (uint8_t*)malloc(dhContext->getSecretSize());
    if (DHss == NULL) {
	sendInfo(Error, "Out of memory");	// serious error
	return NULL;
    }
    pvr = dhPart1->getPv();
    if (pubKey == Dh3072) {
        if (!dhContext->checkPubKey(pvr, 384)) {
            sendInfo(Alert, "Wrong/weak public key value (pvr) received from other party");
            return NULL;
        }
	dhContext->computeKey(pvr, 384, DHss);
    }
    else {
        if (!dhContext->checkPubKey(pvr, 512)) {
            sendInfo(Alert, "Wrong/weak public key value (pvr) received from other party");
            return NULL;
        }
        dhContext->computeKey(pvr, 512, DHss);
    }

    // Initialize a ZID record to get to retained secrets for this peer
    ZIDRecord zidRec(peerZid);

    // ZID file should be opened during initialization step, not here.
    // Thus get the singleton instance to the open file
    ZIDFile *zid = ZIDFile::getInstance();
    zid->getRecord(&zidRec);

    // Get precomputed DHPart2 packet and set internal pointer to NULL. The
    // DHPart2 packet is handed over to ZrtpStateClass. The method 
    // evWaitConfirm1() eventually deletes this packet after it was sent 
    // to our peer.

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

    generateS0Initiator(dhPart1, zidRec); // This computes the new RS1 as well
    zid->saveRecord(&zidRec);
    delete dhContext;
    dhContext = NULL;

    return zpDH;
}

ZrtpPacketConfirm* ZRtp::prepareConfirm1(ZrtpPacketDHPart* dhPart2, uint8_t** errMsg) {

    uint8_t* pvi;
    uint8_t sas[SHA256_DIGEST_LENGTH+1];

    sendInfo(Info, "Responder: DHPart2 received, preparing Confirm1");

    DHss = (uint8_t*)malloc(dhContext->getSecretSize());
    if (DHss == NULL) {
	// serious error
	return NULL;
    }
    pvi = dhPart2->getPv();
    if (pubKey == Dh3072) {
        if (!dhContext->checkPubKey(pvi, 384)) {
            sendInfo(Alert, "Wrong/weak public key value (pvi) received from other party");
            return NULL;
        }
        dhContext->computeKey(pvi, 384, DHss);
    }
    else {
        if (!dhContext->checkPubKey(pvi, 512)) {
            sendInfo(Alert, "Wrong/weak public key value (pvi) received from other party");
            return NULL;
        }
        dhContext->computeKey(pvi, 512, DHss);
    }

    // Now we have the peer's pvi. Because we are responder re-compute my hvi
    // using my Hello packet and the Initiator's pv (DHPart2) and compare with
    // hvi sent in commit packet. If it doesn't macht then a MitM attack
    // may have occured.
    computeHvi(dhPart2, &zrtpHello);
    if (memcmp(hvi, peerHvi, SHA256_DIGEST_LENGTH) != 0) {
        sendInfo(Alert, "Mismatch of HVI values. Possible MitM problem?");
        return NULL;
    }
    // Hash the Initiator's DH2 into the message Hash (other messages already
    // prepared, see 
    sha256Ctx(msgShaContext, (unsigned char*)dhPart2->getHeaderBase(), dhPart2->getLength() * ZRTP_WORD_SIZE);

    closeSha256Context(msgShaContext, messageHash);
    msgShaContext = NULL;

    // Initialize a ZID record to get peer's retained secrets
    ZIDRecord zidRec(peerZid);

    // ZID file should be opened during initialization step, not here
    // thus get the singleton instance to the open file
    ZIDFile *zid = ZIDFile::getInstance();
    zid->getRecord(&zidRec);
    int sasFlag = zidRec.isSasVerified() ? 1 : 0;

    /*
     * The expected shared secret Ids were already computed when we built the
     * DHPart1 packet. Generate s0, all depended keys, and the new RS1 value
     * for the ZID record.
     */
    generateS0Responder(dhPart2, zidRec);

    delete dhContext;
    dhContext = NULL;

    zid->saveRecord(&zidRec);

    ZrtpPacketConfirm* zpConf = new ZrtpPacketConfirm(static_cast<uint8_t>(0));
    zpConf->setMessageType((uint8_t*)Confirm1Msg);
    if (sasFlag) {
        zpConf->setSASFlag();
    }
    zpConf->setExpTime(0xFFFFFFFF);
    zpConf->setIv(randomIV);

    uint8_t confMac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;

    // Encrypt and HMAC with Responder's key - we are Respondere here
//    TODO: int16_t hmlen = (zpConf->getLength() - 9) * ZRTP_WORD_SIZE;
    int16_t hmlen = (zpConf->getLength() - 11) * ZRTP_WORD_SIZE;

    aesCfbEncrypt(zrtpKeyR, (cipher == Aes128) ? 16 : 32, randomIV,
                  (unsigned char*)zpConf->getFiller(), hmlen);
    hmac_sha256(hmacKeyR, SHA256_DIGEST_LENGTH, (unsigned char*)zpConf->getFiller(),
                hmlen, confMac, &macLen);

    zpConf->setHmac(confMac);
    return zpConf;
}

ZrtpPacketConfirm* ZRtp::prepareConfirm2(ZrtpPacketConfirm *confirm1, uint8_t** errMsg) {

    sendInfo(Info, "Initiator: Confirm1 received, preparing Confirm2");

    uint8_t confMac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;

    // Use the Responder's keys here because we are Initiator here and
    // receive packets from Responder
//    TODO: int16_t hmlen = (confirm1->getLength() - 9) * ZRTP_WORD_SIZE;
    int16_t hmlen = (confirm1->getLength() - 11) * ZRTP_WORD_SIZE;

    hmac_sha256(hmacKeyR, SHA256_DIGEST_LENGTH, (unsigned char*)confirm1->getFiller(),
                hmlen, confMac, &macLen);

    if (memcmp(confMac, confirm1->getHmac(), 2*ZRTP_WORD_SIZE) != 0) {
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
//    TODO: hmlen = (zpConf->getLength() - 9) * ZRTP_WORD_SIZE;
    hmlen = (zpConf->getLength() - 11) * ZRTP_WORD_SIZE;

    aesCfbEncrypt(zrtpKeyI, (cipher == Aes128) ? 16 : 32, randomIV,
                  (unsigned char*)zpConf->getFiller(), hmlen);
    hmac_sha256(hmacKeyI, SHA256_DIGEST_LENGTH, (unsigned char*)zpConf->getFiller(),
                hmlen, confMac, &macLen);

    zpConf->setHmac(confMac);
    return zpConf;
}

ZrtpPacketConf2Ack* ZRtp::prepareConf2Ack(ZrtpPacketConfirm *confirm2, uint8_t** errMsg) {

    sendInfo(Info, "Responder: Confirm2 received, preparing Conf2Ack");

    uint8_t confMac[SHA256_DIGEST_LENGTH];
    uint32_t macLen;

    // Use the Initiator's keys here because we are Responder here and
    // reveice packets from Initiator
//    TODO: int16_t hmlen = (confirm2->getLength() - 9) * ZRTP_WORD_SIZE;
    int16_t hmlen = (confirm2->getLength() - 11) * ZRTP_WORD_SIZE;
    hmac_sha256(hmacKeyI, SHA256_DIGEST_LENGTH, (unsigned char*)confirm2->getFiller(),
                hmlen, confMac, &macLen);

    if (memcmp(confMac, confirm2->getHmac(), 2*ZRTP_WORD_SIZE) != 0) {
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

// TODO Implement GoClear handling
ZrtpPacketClearAck* ZRtp::prepareClearAck(ZrtpPacketGoClear* gpkt)
{
    sendInfo(Warning, "Received a GoClear message");
    return &zrtpClearAck;
}

ZrtpPacketGoClear* ZRtp::prepareGoClear(uint8_t* errMsg)
{
    uint8_t msg[16];
    ZrtpPacketGoClear* gclr = &zrtpGoClear;
    gclr->clrClearHmac();
    if (errMsg != NULL) {
	int len = strlen((const char*)errMsg);
	len = (len > 16) ? 16 : len;
	strncpy((char*)msg, (const char*)errMsg, len);
	for (; len < 16; len++) {
	    msg[len] = ' ';
	}
    }
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

void ZRtp::generateS0Initiator(ZrtpPacketDHPart *dhPart, ZIDRecord& zidRec) {
    uint8_t* setC[5];
    const uint8_t* setD[5];
    const uint8_t* setE[5];
    int32_t rsFound = 0;

    setC[0] = (memcmp(rs1IDr, dhPart->getRs1Id(), 8) == 0) ? rs1IDr : NULL;
    setC[1] = (memcmp(rs2IDr, dhPart->getRs2Id(), 8) == 0) ? rs2IDr : NULL;
    setC[2] = (memcmp(sigsIDr, dhPart->getSigsId(), 8) == 0) ? sigsIDr : NULL;
    setC[3] = (memcmp(srtpsIDr, dhPart->getSrtpsId(), 8) == 0) ? srtpsIDr : NULL;
    setC[4] = (memcmp(otherSecretIDr, dhPart->getOtherSecretId(), 8) == 0) ? otherSecretIDr : NULL;

    setD[0] = setE[0] = NULL;
    setD[1] = setE[1] = NULL;
    setD[2] = setE[2] = NULL;
    setD[3] = setE[3] = NULL;
    setD[4] = setE[4] = NULL;

    /*
     * SetC contains the intersection of shared secret Ids in the order seen
     * above. Now select the real secrets into setD and the secret Ids of DHPart1
     * message into setE in same order.
     */
    int matchingSecrets = 0;
    if (setC[0] != NULL) {
	DEBUGOUT((fprintf(stdout, "%c: Match for Rs1 found\n", zid[0])));
        setD[matchingSecrets] = zidRec.getRs1();
	setE[matchingSecrets++] = rs1IDi;
        rsFound = 0x1;
    }
    if (setC[1] != NULL) {
	DEBUGOUT((fprintf(stdout, "%c: Match for Rs2 found\n", zid[0])));
        setD[matchingSecrets] = zidRec.getRs2();
	setE[matchingSecrets++] = rs2IDi;
        rsFound |= 0x2;
    }

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

    int32_t i;
#if 0
    const uint8_t* tmpP;
    int32_t notDone = 1;
    if (matchingSecrets) {
	/*
	 * only very few elements, a simple bubble sort will do here
	 */
        while (notDone) {
	   notDone = 0;
	   for (i = 0; i < matchingSecrets - 1; i++) {
//               if (memcmp(setE[i], setE[i+1], 8) > 0) { // as defined in specifcation
               if (memcmp(setD[i], setD[i+1], SHA256_DIGEST_LENGTH) > 0) { // as implemented in Zfone-beta2

	           tmpP = setE[i];
	           setE[i] = setE[i+1];
	           setE[i+1] = tmpP;
	           tmpP = setD[i];
	           setD[i] = setD[i+1];
	           setD[i+1] = tmpP;
	           notDone = 1;
	       }
	   }
        }
    }
#endif 

    /*
     * ready to generate s0 here.
     * The formular to compute S0:
      s0 = hash( counter | DHResult | "ZRTP-HMAC-KDF" | ZIDi | ZIDr | \
      total_hash | len(s1) | s1 | len(s2) | s2 | len(s3) | s3 | len(s4) | s4 | len(s5) | s5 )
    *
    * Note: in this function we are Initiator, thus ZIDi is our zid, ZIDr is the
    * peer's zid (peerZid)
    */

    // According to the formula the max number of elements to hash is 17, add one for the 
    // terminating "NULL"
    unsigned char* data[18];
    unsigned int   length[18];

    // we need a number of length data items, so define them here 
    uint32_t counter,
             DHResultLen,
             totalHashLen,
             sLen[5], 
             pos;
    // first hash the DH result (computed during protocol handling)
    // sha256(DHss, dhContext->getSecretSize(), DHss); gone since 4j

    // Now prepare structure to hash anything 
    pos = 0;
    counter = 1;
    counter = htonl(counter);
    data[pos] = (unsigned char*)&counter;
    length[pos++] = sizeof(uint32_t);

    // setup length of DH result as 32 bit big-endian number
//    DHResultLen = dhContext->getSecretSize();
//    DHResultLen = htonl(DHResultLen);

    // Hash the length oh DHResult (DHss) as big-endian number
//    data[pos] = (unsigned char*)&DHResultLen;
//    length[pos++] = sizeof(uint32_t);

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

    // Next is the length of total hash (messageHash) as 32bit big-endian number 
    // length of total_hash is SHA256_DIGEST_LENGTH 
//    totalHashLen = SHA256_DIGEST_LENGTH;
//    totalHashLen = htonl(totalHashLen);
//    data[pos] = (unsigned char*)&totalHashLen;
//    length[pos++] = sizeof(uint32_t);

    // Next ist total hash (messageHash) itself 
    data[pos] = messageHash;
    length[pos++] = SHA256_DIGEST_LENGTH;

    // Now for each matching shared secret hash the length of 
    // the shared secret as 32 bit big-endian number and then the 
    // shared secret itself. The length of a shared seceret is 
    // currently fixed to SHA256_DIGEST_LENGTH. If a shared 
    // secret is not used _only_ its length is hased as zero 
    // length. 

    int secretHashLen = SHA256_DIGEST_LENGTH;
    secretHashLen = htonl(secretHashLen);        // prepare 32 bit big-endian number 

    for (i = 0; i < 5; i++) {
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

void ZRtp::generateS0Responder(ZrtpPacketDHPart *dhPart, ZIDRecord& zidRec) {
    uint8_t* setC[5];
    const uint8_t* setD[5];
    const uint8_t* setE[5];     // Set E is the "compressed" C (no NULLs) for sort
    int32_t rsFound = 0;

    setC[0] = (memcmp(rs1IDi, dhPart->getRs1Id(), 8) == 0) ? rs1IDi : NULL;
    setC[1] = (memcmp(rs2IDi, dhPart->getRs2Id(), 8) == 0) ? rs2IDi : NULL;
    setC[2] = (memcmp(sigsIDi, dhPart->getSigsId(), 8) == 0) ? sigsIDi : NULL;
    setC[3] = (memcmp(srtpsIDi, dhPart->getSrtpsId(), 8) == 0) ? srtpsIDi : NULL;
    setC[4] = (memcmp(otherSecretIDi, dhPart->getOtherSecretId(), 8) == 0) ? otherSecretIDi : NULL;

    setD[0] = setE[0] = NULL;
    setD[1] = setE[1] = NULL;
    setD[2] = setE[2] = NULL;
    setD[3] = setE[3] = NULL;
    setD[4] = setE[4] = NULL;

    /*
    * SetC contains the intersection of shared secret Ids in the order seen
    * above. Now select the real secrets into setD and the secret Ids of DHPart1
    * message into setE in same order.
    */
    int matchingSecrets = 0;
    if (setC[0] != NULL) {
	DEBUGOUT((fprintf(stdout, "%c: Match for Rs1 found\n", zid[0])));
        setD[matchingSecrets] = zidRec.getRs1();
	setE[matchingSecrets++] = rs1IDi;
        rsFound = 0x1;
    }

    if (setC[1] != NULL) {
	DEBUGOUT((fprintf(stdout, "%c: Match for Rs2 found\n", zid[0])));
        setD[matchingSecrets] = zidRec.getRs2();
	setE[matchingSecrets++] = rs2IDi;  // rs2IDi will be sent in DHPart2 message
        rsFound |= 0x2;
    }
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

    int32_t i;
#if 0
    const uint8_t* tmpP;
    int32_t notDone = 1;
    if (matchingSecrets > 1) {
	/*
	* only very few elements, a simple bubble sort will do here
	*/
	while (notDone) {
	    notDone = 0;
	    for (i = 0; i < matchingSecrets - 1; i++) {
//                if (memcmp(setE[i], setE[i+1], 8) > 0) { // orignal spec
                if (memcmp(setD[i], setD[i+1], SHA256_DIGEST_LENGTH) > 0) { // as implemented in Zfone beta2
		    tmpP = setE[i];
		    setE[i] = setE[i+1];
		    setE[i+1] = tmpP;
		    tmpP = setD[i];
		    setD[i] = setD[i+1];
		    setD[i+1] = tmpP;
		    notDone = 1;
		}
	    }
        }
    }
#endif

    /*
     * ready to generate s0 here.
     * The formular to compute S0:
      s0 = hash( counter | DHResult | "ZRTP-HMAC-KDF" | ZIDi | ZIDr | \
      total_hash | len(s1) | s1 | len(s2) | s2 | len(s3) | s3 | len(s4) | s4 | len(s5) | s5 )
    *
    * Note: in this function we are Responder, thus ZIDi is the peer's zid (peerZid), ZIDr
    * is our zid.
    */

    // According to the formula the max number of elements to hash is 17, add one for the 
    // terminating "NULL"
    unsigned char* data[19];
    unsigned int   length[19];

    // we need a number of length data items, so define them here 
    uint32_t counter, 
             DHResultLen,
             totalHashLen,
             sLen[5],
             pos;
    // first hash the DH result (computed during protocol handling)
    // sha256(DHss, dhContext->getSecretSize(), DHss); gone since 4j

    // Now prepare structure to hash anything 

    pos = 0;             // position of data to hash 
    counter = 1;
    counter = htonl(counter);
    data[pos] = (unsigned char*)&counter;
    length[pos++] = sizeof(uint32_t);

    // setup length of DH result as 32 bit big-endian number
//    DHResultLen = dhContext->getSecretSize();
//    DHResultLen = htonl(DHResultLen);

    // Hash the length oh DHResult (DHss) as big-endian number
//    data[pos] = (unsigned char*)&DHResultLen;
//    length[pos++] = sizeof(uint32_t);

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

    // Next is the length of total hash (messageHash) as 32bit big-endian number 
    // length of total_hash is SHA256_DIGEST_LENGTH 
//    totalHashLen = SHA256_DIGEST_LENGTH;
//    totalHashLen = htonl(totalHashLen);
//    data[6] = (unsigned char*)&totalHashLen;
//    length[6] = sizeof(uint32_t);

    // Next ist total hash (messageHash) itself 
    data[pos] = messageHash;
    length[pos++] = SHA256_DIGEST_LENGTH;

    // Now for each matching shared secret hash the length of 
    // the shared secret as 32 bit big-endian number and then the 
    // shared secret itself. The length of a shared seceret is 
    // currently fixed to SHA256_DIGEST_LENGTH. If a shared 
    // secret is not used _only_ its length is hased as zero 
    // length. 

    int secretHashLen = SHA256_DIGEST_LENGTH;
    secretHashLen = htonl(secretHashLen);        // prepare 32 bit big-endian number 

    for (i = 0; i < 5; i++) {
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

void ZRtp::srtpSecretsReady(EnableSecurity part) {

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

    callback->srtpSecretsReady(&sec, part);
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
    const char* tmp = "                                ";
    if (id.size() < 31) {
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
