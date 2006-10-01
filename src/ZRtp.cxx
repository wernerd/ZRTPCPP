/*
  Copyright (C) 2006 Werner Dittmann

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
 * This method simplifies detection of libzrtpcpp inside configure
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

    zrtpHello = NULL;
    zrtpHelloAck = NULL;
    zrtpConf2Ack = NULL;
    DHss = NULL;
    pubKeyBytes = NULL;
    Zfone = 0;

    memcpy(zid, myZid, 12);
    zrtpHello = new ZrtpPacketHello();
    zrtpHello->setZid(zid);
    zrtpHelloAck = new ZrtpPacketHelloAck();
    zrtpConf2Ack = new ZrtpPacketConf2Ack();

    stateEngine = new ZrtpStateClass(this);
}

ZRtp::~ZRtp() {
    stopZrtp();

    if (DHss != NULL) {
	free(DHss);
        DHss = NULL;
    }
    if (pubKeyBytes != NULL) {
        free(pubKeyBytes);
        pubKeyBytes = NULL;
    }
    if (zrtpHello != NULL) {
	delete zrtpHello;
        pubKeyBytes = NULL;
    }
    if (zrtpHelloAck != NULL) {
	delete zrtpHelloAck;
        zrtpHelloAck = NULL;
    }
    if (zrtpConf2Ack != NULL) {
	delete zrtpConf2Ack;
        zrtpConf2Ack = NULL;
    }
    if (stateEngine != NULL) {
	delete stateEngine;
        stateEngine = NULL;
    }
    if (dhContext != NULL) {
	delete dhContext;
        dhContext = NULL;
    }
    memset(hmacSrtp, 0, SHA256_DIGEST_LENGTH);
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

int32_t ZRtp::processExtensionHeader(uint8_t *extHeader, uint8_t* content) {
    Event_t ev;

    ev.type = ZrtpPacket;
    ev.data.packet = extHeader;
    ev.content = content;

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
    ev.content = NULL;
    int32_t ret;
    if (stateEngine != NULL) {
        ret = stateEngine->processEvent(&ev);
    }
    return ret;

}

bool ZRtp::handleGoClear(uint8_t *extHeader)
{
    char *msg, first, last;

    msg = (char *)extHeader + 4;
    first = tolower(*msg);
    last = tolower(*(msg+6));

    if (first == 'g' && last == 'r') {
        Event_t ev;

        ev.type = ZrtpGoClear;
        ev.data.packet = extHeader;
        ev.content = NULL;
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

ZrtpPacketCommit* ZRtp::prepareCommit(ZrtpPacketHello *hello) {

    memcpy(peerZid, hello->getZid(), 12);

    sendInfo(Info, "Hello received, preparing a Commit");

    uint8_t* cid = hello->getClientId();
    if (*cid == 'Z') {  // TODO Zfone hack regarding reused sequence numbers
        Zfone = 1;
    }

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
    pubKeyBytes = (uint8_t*)malloc(pubKeyLen);
    if (pubKeyBytes == NULL) {
        sendInfo(Error, "Out of memory");	// serious error
        return NULL;
    }
    dhContext->getPubKeyBytes(pubKeyBytes);

    // Here we act as Initiator. Take other peer's Hello packet and my
    // PVI (public value initiator) and compute the HVI (hash value initiator)
    computeHvi(pubKeyBytes, maxPubKeySize, hello);

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
    return commit;
}

ZrtpPacketDHPart* ZRtp::prepareDHPart1(ZrtpPacketCommit *commit) {

    int i;

    sendInfo(Info, "Responder: Commit received, preparing DHPart1");

    // check if we support the commited Cipher type
    uint8_t *cp = commit->getCipherType();
    for (i = 0; i < NumSupportedSymCiphers; i++) {
	if (!memcmp(cp, supportedCipher[i], 8)) {
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
        if (!memcmp(cp, supportedAuthLen[i], 8)) {
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
	if (!memcmp(cp, supportedHashes[i], 8)) {
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
	if (!memcmp(cp, supportedPubKey[i], 8)) {
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
	if (!memcmp(cp, supportedSASType[i], 8)) {
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
    // setup the DH context and generate a fresh public / secret key
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

    char buffer[128];
    snprintf(buffer, 128, "DH1Part: Generated a public DH key of size: %d", pubKeyLen);
    sendInfo(Info, buffer);

    if (pubKeyLen > maxPubKeySize) {
	snprintf(buffer, 128, "Generated DH public key too big: %d, max: %d", pubKeyLen, maxPubKeySize);
	sendInfo(Error, buffer);
	return NULL;
    }
    pubKeyBytes = (uint8_t*)malloc(pubKeyLen);
    if (pubKeyBytes == NULL) {
        sendInfo(Error, "Out of memory");	// serious error
        return NULL;
    }
    dhContext->getPubKeyBytes(pubKeyBytes);

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

    ZrtpPacketDHPart *zpDH = new ZrtpPacketDHPart(pubKey);

    // Fill the values in the DHPart1 packet
    zpDH->setMessage((uint8_t*)DHPart1Msg);
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

    return zpDH;
}

ZrtpPacketDHPart* ZRtp::prepareDHPart2(ZrtpPacketDHPart *dhPart1) {

    uint8_t* pvr;
    uint8_t *data[4];
    unsigned int length[4];
    uint8_t sas[SHA256_DIGEST_LENGTH+1];
    uint32_t sasTemp;

    sendInfo(Info, "Initiator: DHPart1 received, preparing DHPart2");

    DHss = (uint8_t*)malloc(dhContext->getSecretSize());
    if (DHss == NULL) {
	sendInfo(Error, "Out of memory");	// serious error
	return NULL;
    }
    data[0] = pubKeyBytes;
    length[0] = pubKeyLen;

    data[1] = pvr = dhPart1->getPv();

    data[2] = (uint8_t *)sasString;
    length[2] = strlen(sasString);
    data[3] = NULL;

    if (pubKey == Dh3072) {
        if (!dhContext->checkPubKey(pvr, 384)) {
            sendInfo(Alert, "Wrong/weak public key value (pvr) received from other party");
            return NULL;
        }
	dhContext->computeKey(pvr, 384, DHss);
        length[1] = 384;
        sha256(data, length, sas);

    }
    else {
        if (!dhContext->checkPubKey(pvr, 512)) {
            sendInfo(Alert, "Wrong/weak public key value (pvr) received from other party");
            return NULL;
        }
        dhContext->computeKey(pvr, 512, DHss);
        length[1] = 512;
        sha256(data, length, sas);
    }
    sas[SHA256_DIGEST_LENGTH] = 0;
    sasTemp = *(uint32_t*)(sas + SHA256_DIGEST_LENGTH - 3);
    sasTemp = ntohl(sasTemp);
    sasTemp <<= 4;
    *(uint32_t*)sas = htonl(sasTemp);
    SAS = Base32(sas, 20).getEncoded();

    // Initialize a ZID record to get peer's retained secrets
    ZIDRecord zidRec(peerZid);

    // ZID file should be opened during initialization step, not here.
    // Thus get the singleton instance to the open file
    ZIDFile *zid = ZIDFile::getInstance();
    zid->getRecord(&zidRec);
    /*
     * After the next function call my set of shared secrets and the expected
     * set of shared secrets are ready. The expected shared secrets are in the
     * *r variables. This is "set A" as defined in the ZRTP specification. The
     * received DHPart1 packet contains the "Set B". Now go on and select the
     * real shared secrets that we will use to generate s0, all depended
     * keys, and the new RS1 value of the ZID record.
     */
    computeSharedSecretSet(zidRec);
    generateS0Initiator(dhPart1, zidRec);
    zid->saveRecord(&zidRec);

    ZrtpPacketDHPart *zpDH = new ZrtpPacketDHPart(pubKey);

    // Fill the values in the DHPart2 packet
    zpDH->setMessage((uint8_t*)DHPart2Msg);
    zpDH->setRs1Id(rs1IDi);
    zpDH->setRs2Id(rs2IDi);
    zpDH->setSigsId(sigsIDi);
    zpDH->setSrtpsId(srtpsIDi);
    zpDH->setOtherSecretId(otherSecretIDi);

    // here the public key value
    zpDH->setPv(pubKeyBytes);

    myRole = Initiator;

    delete dhContext;
    dhContext = NULL;

    return zpDH;
}

ZrtpPacketConfirm* ZRtp::prepareConfirm1(ZrtpPacketDHPart *dhPart2) {

    uint8_t* pvi;
    uint8_t *data[4];
    unsigned int length[4];
    uint8_t sas[SHA256_DIGEST_LENGTH+1];
    uint32_t sasTemp;

    sendInfo(Info, "Responder: DHPart2 received, preparing Confirm1");

    DHss = (uint8_t*)malloc(dhContext->getSecretSize());
    if (DHss == NULL) {
	// serious error
	return NULL;
    }
    data[0] = pvi = dhPart2->getPv();
    /*
     * Prepare the data to compute the SAS hash.
     */
    data[1] = pubKeyBytes;
    length[1] = pubKeyLen;

    data[2] = (uint8_t*)sasString;
    length[2] = strlen(sasString);
    data[3] = NULL;

    if (pubKey == Dh3072) {
        if (!dhContext->checkPubKey(pvi, 384)) {
            sendInfo(Alert, "Wrong/weak public key value (pvi) received from other party");
            return NULL;
        }
	dhContext->computeKey(pvi, 384, DHss);
        length[0] = 384;
        sha256(data, length, sas);
    }
    else {
        if (!dhContext->checkPubKey(pvi, 512)) {
            sendInfo(Alert, "Wrong/weak public key value (pvi) received from other party");
            return NULL;
        }
        dhContext->computeKey(pvi, 512, DHss);
        length[0] = 512;
        sha256(data, length, sas);
    }
    sas[SHA256_DIGEST_LENGTH] = 0;
    sasTemp = *(uint32_t*)(sas + SHA256_DIGEST_LENGTH - 3);
    sasTemp = ntohl(sasTemp);
    sasTemp <<= 4;
    *(uint32_t*)sas = htonl(sasTemp);
    SAS = Base32(sas, 20).getEncoded();

    // Here we have the peers pv. Because we are responder re-compute my hvi
    // using my Hello packet and the Initiator's pv and compare with
    // hvi sent in commit packet. If it doesn't macht then a MitM attack
    // may have occured.
    computeHvi(pvi, ((pubKey == Dh3072) ? 384 : 512), zrtpHello);
    if (memcmp(hvi, peerHvi, SHA256_DIGEST_LENGTH) != 0) {
	sendInfo(Alert, "Mismatch of HVI values. Possible MitM problem?");
	return NULL;
    }

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

    ZrtpPacketConfirm* zpConf = new ZrtpPacketConfirm();
    zpConf->setMessage((uint8_t*)Confirm1Msg);
    zpConf->setPlainText((uint8_t*)knownPlain);
    zpConf->setSASFlag(sasFlag);
    zpConf->setExpTime(0);

    uint8_t confMac[SHA256_DIGEST_LENGTH];
    unsigned int macLen;

    // The HMAC with length 20 includes the SAS flag inside the Confirm packet
    // TODO: Be aware of specific handling of stay secure flag !!!
    hmac_sha256(hmacSrtp, SHA256_DIGEST_LENGTH, (unsigned char*)zpConf->getPlainText(),
		20, confMac, &macLen);

    zpConf->setHmac(confMac);
    return zpConf;
}

ZrtpPacketConfirm* ZRtp::prepareConfirm2(ZrtpPacketConfirm *confirm1) {

    sendInfo(Info, "Initiator: Confirm1 received, preparing Confirm2");

    uint8_t sasFlag = confirm1->getSASFlag();

    if (memcmp(knownPlain, confirm1->getPlainText(), 15) != 0) {
	sendInfo(Error, "Cannot read confirm1 message");
	return NULL;
    }
    uint8_t confMac[SHA256_DIGEST_LENGTH];
    unsigned int macLen;

    // The HMAC with length 16 includes the SAS flag inside the Confirm packet
    // TODO: Be aware of specific handling of stay secure flag !!!
    hmac_sha256(hmacSrtp, SHA256_DIGEST_LENGTH, (unsigned char*)confirm1->getPlainText(),
		20, confMac, &macLen);

    if (memcmp(confMac, confirm1->getHmac(), SHA256_DIGEST_LENGTH) != 0) {
	sendInfo(Error, "HMAC verification of Confirm1 message failed");
	return NULL;
    }
    /*
     * The Confirm1 is ok, handle the Retained secret stuff and inform
     * GUI about state.
     */

    // Initialize a ZID record to get peer's retained secrets
    ZIDRecord zidRec(peerZid);

    ZIDFile *zid = ZIDFile::getInstance();
    zid->getRecord(&zidRec);

    // Our peer did not confirm the SAS in last session, thus reset
    // our SAS flag too.
    if (!(sasFlag & 0x1)) {
      zidRec.resetSasVerified();
    }

    // get verified flag from current RS1 before set a new RS1. This
    // may not be set even if peer's flag is set in confirm1 message.
    sasFlag = zidRec.isSasVerified() ? 1 : 0;

    // Inform GUI about security state and SAS state
    const char* c = (cipher == Aes128) ? "AES-CM-128" : "AES-CM-256";
    const char* s = (zidRec.isSasVerified()) ? NULL : SAS.c_str();
    callback->srtpSecretsOn(c, s);

    // now we are ready to save the new RS1 which inherits the verified
    // flag from old RS1
    zidRec.setNewRs1((const uint8_t*)newRs1);
    zid->saveRecord(&zidRec);

    // now generate my Confirm2 message
    ZrtpPacketConfirm* zpConf = new ZrtpPacketConfirm();
    zpConf->setMessage((uint8_t*)Confirm2Msg);
    zpConf->setPlainText((uint8_t*)knownPlain);
    zpConf->setSASFlag(sasFlag);
    zpConf->setExpTime(0);

    // The HMAC with length 16 includes the SAS flag inside the Confirm packet
    // TODO: Be aware of specific handling of stay secure flag !!!
    hmac_sha256(hmacSrtp, SHA256_DIGEST_LENGTH, (unsigned char*)zpConf->getPlainText(),
		20, confMac, &macLen);

    zpConf->setHmac(confMac);
    return zpConf;
}

ZrtpPacketConf2Ack* ZRtp::prepareConf2Ack(ZrtpPacketConfirm *confirm2) {

    sendInfo(Info, "Respnder: Confirm2 received, preparing Conf2Ack");

    uint8_t sasFlag = confirm2->getSASFlag();

    if (memcmp(knownPlain, confirm2->getPlainText(), 15) != 0) {
     	sendInfo(Error, "Cannot read confirm2 message");
	return NULL;
    }
    uint8_t confMac[SHA256_DIGEST_LENGTH];
    unsigned int macLen;

    // The hmac with length 16 includes the SAS flag inside the Confirm packet
    // TODO: Be aware of specific handling of stay secure flag !!!
    hmac_sha256(hmacSrtp, SHA256_DIGEST_LENGTH, (unsigned char*)confirm2->getPlainText(),
		20, confMac, &macLen);

    if (memcmp(confMac, confirm2->getHmac(), SHA256_DIGEST_LENGTH) != 0) {
	sendInfo(Error, "HMAC verification of Confirm2 message failed");
	return NULL;
    }

    /*
     * The Confirm2 is ok, handle the Retained secret stuff and inform
     * GUI about state.
     */

    // Initialize a ZID record to get peer's retained secrets
    ZIDRecord zidRec(peerZid);

    ZIDFile *zid = ZIDFile::getInstance();
    zid->getRecord(&zidRec);

    // Our peer did not confirm the SAS in last session, thus reset
    // our SAS flag too.
    if (!(sasFlag & 0x1)) {
      zidRec.resetSasVerified();
    }

    // Inform GUI about security state and SAS state
    const char* c = (cipher == Aes128) ? "AES-CM-128" : "AES-CM-256";
    const char* s = (zidRec.isSasVerified()) ? NULL : SAS.c_str();
    callback->srtpSecretsOn(c, s);

    // save new RS1, this inherits the verified flag from old RS1
    zidRec.setNewRs1((const uint8_t*)newRs1);
    zid->saveRecord(&zidRec);

    return zrtpConf2Ack;
}

// TODO Implement GoClear handling
ZrtpPacketClearAck* ZRtp::prepareClearAck(ZrtpPacketGoClear* gpkt)
{
    sendInfo(Warning, "Received a GoClear message");
    return NULL;
}


SupportedHashes ZRtp::findBestHash(ZrtpPacketHello *hello) {

    int i;
    int ii;

    for (i = 0; i < NumSupportedHashes; i++) {
	for (ii = 0; ii < 5; ii++) {
	    if (!memcmp(hello->getHashType(ii), supportedHashes[i], 8)) {
		break;
	    }
	}
	// if ii < 5 we found the hash i in the packet, done
	if (ii < 5) {
	    break;
	}
    }
    return (SupportedHashes)i;
}

SupportedSymCiphers ZRtp::findBestCipher(ZrtpPacketHello *hello) {

    int i;
    int ii;

    for (i = 0; i < NumSupportedSymCiphers; i++) {
	for (ii = 0; ii < 5; ii++) {
	    if (!memcmp(hello->getCipherType(ii), supportedCipher[i], 8)) {
		break;
	    }
	}
	// if ii < 5 we found the cipher i in the packet, done
	if (ii < 5) {
	    break;
	}
    }
    return (SupportedSymCiphers)i;
}

SupportedPubKeys ZRtp::findBestPubkey(ZrtpPacketHello *hello) {

    int i;
    int ii;

    for (i = 0; i < NumSupportedPubKeys; i++) {
	for (ii = 0; ii < 5; ii++) {
	    if (!memcmp(hello->getPubKeysType(ii), supportedPubKey[i], 8)) {
		break;
	    }
	}
	// if ii < 5 we found the cipher i in the packet, done
	if (ii < 5) {
	    break;
	}
    }
    return (SupportedPubKeys)i;
}

SupportedSASTypes ZRtp::findBestSASType(ZrtpPacketHello *hello) {

    int  i;
    int ii;

    for (i = 0; i < NumSupportedSASTypes ; i++) {
	for (ii = 0; ii < 5; ii++) {
	    if (!memcmp(hello->getSasType(ii), supportedSASType[i], 8)) {
		break;
	    }
	}
	// if ii < 5 we found the cipher i in the packet, done
	if (ii < 5) {
	    break;
	}
    }
    return (SupportedSASTypes)i;
}

SupportedAuthLengths ZRtp::findBestAuthLen(ZrtpPacketHello *hello) {

    int  i;
    int ii;

    for (i = 0; i < NumSupportedAuthLenghts ; i++) {
        for (ii = 0; ii < 5; ii++) {
            if (!memcmp(hello->getAuthLen(ii), supportedAuthLen[i], 8)) {
                break;
            }
        }
        // if ii < 5 we found the cipher i in the packet, done
        if (ii < 5) {
            break;
        }
    }
    return (SupportedAuthLengths)i;
}

void ZRtp::computeHvi(uint8_t *pv, uint32_t pvLength, ZrtpPacketHello *hello) {

    unsigned char* data[3];
    unsigned int length[3];
    /*
     * populate the vector to compute the HVI hash according to the
     * ZRTP specification.
     */
    data[0] = pv;
    length[0] = pvLength;

    data[1] = (unsigned char*)hello->getHashType(0);
    length[1] = 5*5*8;

    data[2] = NULL;            // terminate data chunks
    sha256(data, length, hvi);
    return;
}

void ZRtp:: computeSharedSecretSet(ZIDRecord &zidRec) {

   /*
    * Compute the Initiator's and Reponder's retained shared secret Ids.
    */
    uint8_t randBuf[RS_LENGTH];
    unsigned int macLen;

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
	setE[matchingSecrets++] = rs1IDi;  // rs1IDi will be sent in DHPart2 message
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
    /*
     * ready to generate s0 here.
     * Hash the DH shared secret and the available shared secrets (max. 5).
     */
    unsigned char* data[7];
    uint32_t  length[7];

    data[0] = DHss;
    length[0] = dhContext->getSecretSize();
    data[1] = NULL;
    sha256(data, length, DHss);

    data[0] = DHss;
    length[0] = SHA256_DIGEST_LENGTH;

    for (i = 0; i < matchingSecrets; i++) {
	data[1+i] = (unsigned char*)setD[i];
        length[1+i] = SHA256_DIGEST_LENGTH;
    }
    data[1+i] = NULL;
    sha256(data, length, s0);
    // hexdump("S0 (I)", s0, 32);

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
    /*
     * ready to generate s0 here.
     * Hash the DH shared secret and the available shared secrets (max. 5).
     */
    unsigned char* data[7];
    uint32_t  length[7];

    // first hash the DH secret
    data[0] = DHss;
    length[0] = dhContext->getSecretSize();
    data[1] = NULL;
    sha256(data, length, DHss);

    // now take the hashed DH secret and the retained secrets and hash
    // them to get S0
    data[0] = DHss;
    length[0] = SHA256_DIGEST_LENGTH;

    for (i = 0; i < matchingSecrets; i++) {
	data[1+i] = (unsigned char*)setD[i];
        length[1+i] = SHA256_DIGEST_LENGTH;
    }
    data[1+i] = NULL;
    sha256(data, length, s0);

    // hexdump("S0 (R)", s0, 32);
    memset(DHss, 0, dhContext->getSecretSize());
    free(DHss);
    DHss = NULL;

    computeSRTPKeys();
}

void ZRtp::computeSRTPKeys() {

    unsigned int macLen;

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

    // The HMAC key for GoClear
    hmac_sha256(s0, SHA256_DIGEST_LENGTH, (unsigned char*)hmacKey, strlen(hmacKey),
		hmacSrtp, &macLen);

    // Compute the new Retained Secret
    hmac_sha256(s0, SHA256_DIGEST_LENGTH, (unsigned char*)retainedSec, strlen(retainedSec),
		newRs1, &macLen);
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

int32_t ZRtp::sendPacketRTP(ZrtpPacketBase *packet) {
    return ((packet == NULL) ? 0 :
            callback->sendDataRTP(packet->getHeaderBase(), (packet->getLength() * 4) + 4));
}

int32_t ZRtp::sendPacketSRTP(ZrtpPacketBase *packet) {
    return ((packet == NULL) ? 0 :
            callback->sendDataSRTP(packet->getHeaderBase(),
                                   (packet->getLength() * 4) + 4,
                                   ((char *)(packet->getHeaderBase()) + (packet->getLength() * 4) + 4),
                                   52));
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
    const char* tmp = "                ";
    if (id.size() < 15) {
        zrtpHello->setClientId((unsigned char*)tmp);
    }
    zrtpHello->setClientId((unsigned char*)id.c_str());
}
