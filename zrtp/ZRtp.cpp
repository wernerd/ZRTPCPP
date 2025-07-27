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
#include <sstream>

#include "crypto/zrtpDH.h"
#include "crypto/hmac256.h"
#include "crypto/sha256.h"
#include "crypto/hmac384.h"
#include "crypto/sha384.h"

#include "crypto/skeinMac256.h"
#include "crypto/skein256.h"
#include "crypto/skeinMac384.h"
#include "crypto/skein384.h"

#include "libzrtpcpp/ZRtp.h"
#include "libzrtpcpp/ZrtpStateEngineImpl.h"
#include "libzrtpcpp/Base32.h"
#include "libzrtpcpp/EmojiBase32.h"
#include "common/Utilities.h"
#include "libzrtpcpp/ZrtpTextData.h"

using namespace GnuZrtpCodes;
using namespace std;

/*
 * This method simplifies detection of libzrtpcpp inside Automake, configure,
 * and friends
 */
#ifdef __cplusplus
extern "C" {
#endif
[[maybe_unused]] int ZrtpAvailable() {
    return 1;
}
#ifdef __cplusplus
}
#endif

ZRtp::ZRtp(uint8_t const *myZid, std::shared_ptr<ZrtpCallback> const &callback, const string &id,
           shared_ptr<ZrtpConfigure> const &config, bool const mitm, bool const sasSignSupport): callback(callback),
    configureAlgos(config) {
    configureAlgos->setTrustedMitM(mitm);
    configureAlgos->setSasSignature(sasSignSupport);

    initialize(id);
}

ZRtp::ZRtp(const std::string &id, std::shared_ptr<ZrtpCallback> const &callback,
           std::shared_ptr<ZrtpConfigure> const &config) : callback(callback), configureAlgos(config) {
    initialize(id);
}

void ZRtp::initialize(const std::string &id) {
#ifdef ZRTP_SAS_RELAY_SUPPORT
    enableMitmEnrollment = config->isTrustedMitM();
#pragma message "ZRTP SAS relay support is enabled."
#else
    enableMitmEnrollment = false;
#endif

    paranoidMode = configureAlgos->isParanoidMode();

    // Set up the implicit hash function pointers and length. The casts show that we use different
    // functions
    hashLengthImpl = SHA256_DIGEST_LENGTH;
    hashFunctionImpl = sha256;
    hmacFunctionImpl = hmac_sha256;

    ownZid.assign(configureAlgos->getZidCache()->getZid(), ZID_SIZE); // save the ZID

    /*
     * Generate H0 as a random number (256 bits, 32 bytes) and then
     * the hash chain, refer to chapter 9. Use the implicit hash function.
     */
    randomZRTP(H0, HASH_IMAGE_SIZE);
    sha256(H0, HASH_IMAGE_SIZE, H1); // hash H0 and generate H1
    sha256(H1, HASH_IMAGE_SIZE, H2); // H2
    sha256(H2, HASH_IMAGE_SIZE, H3); // H3

    // configure all supported Hello packet versions
    zrtpHello_11.configureHello(*configureAlgos);
    zrtpHello_11.setH3(H3); // set H3 in Hello, included in helloHash
    zrtpHello_11.setZid(ownZid.data());
    zrtpHello_11.setVersion(reinterpret_cast<uint8_t const *>(zrtpVersion_11));


    zrtpHello_12.configureHello(*configureAlgos);
    zrtpHello_12.setH3(H3); // set H3 in Hello, included in helloHash
    zrtpHello_12.setZid(ownZid.data());
    zrtpHello_12.setVersion(reinterpret_cast<uint8_t const *>(zrtpVersion_12));

    if (enableMitmEnrollment) {
        // this session acts for a trusted MitM (PBX)
        zrtpHello_11.setMitmMode();
        zrtpHello_12.setMitmMode();
    }
    if (configureAlgos->isSasSignature()) {
        // the application supports SAS signing
        zrtpHello_11.setSasSign();
        zrtpHello_12.setSasSign();
    }

    // Keep the array in ascending order (greater index -> greater version)
    helloPackets[0].packet = &zrtpHello_11;
    helloPackets[0].version = zrtpHello_11.getVersionInt();
    setClientId(id, &helloPackets[0]); // set id, compute HMAC and final helloHash

    helloPackets[1].packet = &zrtpHello_12;
    helloPackets[1].version = zrtpHello_12.getVersionInt();
    setClientId(id, &helloPackets[1]); // set id, compute HMAC and final helloHash

    currentHelloPacket = helloPackets[SUPPORTED_ZRTP_VERSIONS - 1].packet; // start with the highest supported version
    helloPackets[SUPPORTED_ZRTP_VERSIONS].packet = nullptr;
    peerHelloVersion[0] = 0;

    stateEngine = make_unique<ZrtpStateEngineImpl>(this);
}

ZRtp::~ZRtp() {
    stopZrtp();
    hmacKeyI.clear();
    hmacKeyR.clear();

    zrtpKeyI.clear();
    zrtpKeyR.clear();
    /*
     * Clear the Initiator's srtp key and salt
     */
    srtpKeyI.clear();
    srtpSaltI.clear();
    /*
     * Clear the Responder's srtp key and salt
     */
    srtpKeyR.clear();
    srtpSaltR.clear();

    zrtpSession.clear();

    peerNonces.clear();
}

void ZRtp::processZrtpMessage(uint8_t const *zrtpMessage, uint32_t const pSSRC, size_t const length) {
    Event ev;

    peerSSRC = pSSRC;
    ev.type = ZrtpPacket;
    ev.length = length;
    ev.packet = zrtpMessage;

    if (stateEngine) {
        stateEngine->processEvent(&ev);
    }
}

void ZRtp::processTimeout() const {
    Event ev;

    ev.type = Timer;
    if (stateEngine) {
        stateEngine->processEvent(&ev);
    }
}

#if 0
bool ZRtp::handleGoClear(uint8_t *message)
{
    char *msg, first, last;

    msg = (char *)message + 4;
    first = tolower(*msg);
    last = tolower(*(msg+6));

    if (first == 'g' && last == 'r') {
        Event_t ev;

        ev.type = ZrtpGoClear;
        ev.packet = message;
        if (stateEngine != nullptr) {
            stateEngine->processEvent(&ev);
        }
        return true;
    }
    else {
        return false;
    }
}
#endif

void ZRtp::startZrtpEngine() const {
    Event ev;

    if (stateEngine && stateEngine->inState(Initial)) {
        ev.type = ZrtpInitial;
        stateEngine->processEvent(&ev);
    }
}

void ZRtp::stopZrtp() const {
    Event ev;

    if (stateEngine) {
        ev.type = ZrtpClose;
        stateEngine->processEvent(&ev);
    }
}

bool ZRtp::inState(int32_t const state) const {
    if (stateEngine) {
        return stateEngine->inState(state);
    }
    return false;
}

ZrtpPacketHello *ZRtp::prepareHello() const {
    return currentHelloPacket;
}

ZrtpPacketHelloAck *ZRtp::prepareHelloAck() {
    return &zrtpHelloAck;
}

/*
 * At this point, we will assume the role of Initiator. This role may change
 * in case we have a commit-clash. Refer to chapter 5.2 in the spec how
 * to break this tie.
 */
ZrtpPacketCommit *ZRtp::prepareCommit(ZrtpPacketHello const *hello, uint32_t *errMsg) {
    myRole = Initiator;

    if (!hello->isLengthOk()) {
        *errMsg = CriticalSWError;
        return nullptr;
    }
    // Save data before detailed checks - may aid in analyzing problems
    peerClientId.assign(reinterpret_cast<char const *>(hello->getClientId()), ZRTP_WORD_SIZE * 4);
    memcpy(peerHelloVersion, hello->getVersion(), ZRTP_WORD_SIZE);
    peerHelloVersion[ZRTP_WORD_SIZE] = 0;

    // Save our peer's (presumably the Responder) ZRTP id
    peerZid.assign(hello->getZid(), ZID_SIZE);
    if (peerZid.equals(ownZid, ZID_SIZE)) {
        // peers have same ZID????
        *errMsg = EqualZIDHello;
        return nullptr;
    }
    memcpy(peerH3, hello->getH3(), HASH_IMAGE_SIZE);

    uint32_t const helloLen = hello->getLength() * ZRTP_WORD_SIZE;

    // Calculate hash over the received Hello packet - is peer's hello hash.
    // Use implicit hash algorithm
    hashFunctionImpl(hello->getHeaderBase(), helloLen, peerHelloHash);

    sendInfo(Info, InfoHelloReceived);

    /*
     * The Following section extracts the algorithm from the peer's Hello
     * packet. Always use the preferred offered algorithms. If the received
     * Hello does not contain algo specifiers or offers only unsupported
     * optional algorithms, then replace these with mandatory algorithms and
     * put them into the Commit packet. Refer to the findBest*() functions.
     * If this is a MultiStream ZRTP object, then do not get the cipher and
     * authentication from the 'hello' packet but use the pre-initialized values
     * as proposed by the standard. If we switch to responder mode, the
     * commit packet may contain other algos - see function
     * prepareConfirm2MultiStream(...).
     */
    sasType = findBestSASType(hello);

    if (!multiStream) {
        pubKey = findBestPubkey(hello); // Check for public key algorithm first, must set 'hash' as well
        if (hash == nullptr) {
            *errMsg = UnsuppHashType;
            return nullptr;
        }
        // If the other party offered NP algorithms, then these are top of the list
        // and selected. To give some more time to compute the NP keys, increase
        // T2 timer
        if (strncmp(pubKey->getName(), np06, 4) == 0 ||
            strncmp(pubKey->getName(), np09, 4) == 0 ||
            strncmp(pubKey->getName(), np12, 4) == 0) {
            isNpAlgorithmActive = true;
        }

        if (cipher == nullptr) // public key selection may have set the cipher already
            cipher = findBestCipher(hello, pubKey);
        if (authLength == nullptr) // public key selection may have set the SRTP authLen already
            authLength = findBestAuthLen(hello);
        multiStreamAvailable = checkMultiStream(hello);
    } else {
        if (checkMultiStream(hello)) {
            return prepareCommitMultiStream(hello);
        }
        // we are in multi-stream, but peer does not offer multi-stream
        // return error code to the other party - unsupported PK, must be Mult
        *errMsg = UnsuppPKExchange;
        return nullptr;
    }
    setNegotiatedHash(hash);

    // Modify here when introducing new DH key agreement, for example,
    // elliptic curves.
    dhContext = make_unique<ZrtpDH>(pubKey->getName());

    dhContext->getPubKeyBytes(pubKeyBytes, ZrtpDH::Commit);
    sendInfo(Info, InfoCommitDHGenerated);

    // Prepare IV data that we will use during confirm packet encryption.
    randomZRTP(randomIV, sizeof(randomIV));

    /*
     * Prepare our DHPart2 packet here. Required to compute HVI. If we stay
     * in the Initiator role, then we reuse this packet later in prepareDHPart2().
     * To create this DH packet, we have to compute the retained secret ids,
     * thus get our peer's retained secret data first.
     */
    zidRec = getZidCache()->getRecord(peerZid.data());

    //Compute the Initiator's and Responder's retained secret ids.
    computeSharedSecretSet(*zidRec);

#ifdef ZRTP_SAS_RELAY_SUPPORT
    // Check if a PBX application set the MitM flag.
    mitmSeen = hello->isMitmMode();
#endif

    signSasSeen = hello->isSasSign();

    // Construct a DHPart2 message (Initiator's DH message). This packet
    // is required to compute the HVI (Hash Value Initiator), refer to
    // chapter 5.4.1.1.

    // Fill the values in the DHPart2 packet. When using NP algorithms, use the optimized
    // protocol flow and the new packet set up for DHPart2 which does _not_ contain any
    // public key data
    if (!isNpAlgorithmActive) {
        zrtpDH2.setPacketLength(pubKeyBytes.size());
        zrtpDH2.setPv(pubKeyBytes.data());
    } else {
        zrtpDH2.setPacketLength(0);
    }
    zrtpDH2.setMessageType(DHPart2Msg);
    zrtpDH2.setRs1Id(rs1IDi);
    zrtpDH2.setRs2Id(rs2IDi);
    zrtpDH2.setAuxSecretId(auxSecretIDi);
    zrtpDH2.setPbxSecretId(pbxSecretIDi);
    zrtpDH2.setH1(H1);

    uint32_t len = zrtpDH2.getLength() * ZRTP_WORD_SIZE;

    // Compute HMAC over DH2, excluding the HMAC field (HMAC_SIZE)
    // and store in DH2. Key to HMAC is H0, use HASH_IMAGE_SIZE bytes only.
    // Must use implicit HMAC functions.
    zrtp::ImplicitDigest hmac;
    hmacFunctionImpl(H0, HASH_IMAGE_SIZE, zrtpDH2.getHeaderBase(), len - HMAC_SIZE, hmac);
    zrtpDH2.setHMAC(hmac);

    // Compute the HVI, refer to chapter 5.4.1.1 of the specification
    computeHvi(&zrtpDH2, hello);

    zrtpCommit.setH2(H2);
    zrtpCommit.setZid(ownZid.data());
    zrtpCommit.setHashType(reinterpret_cast<uint8_t const *>(hash->getName()));
    zrtpCommit.setCipherType(reinterpret_cast<uint8_t const *>(cipher->getName()));
    zrtpCommit.setAuthLen(reinterpret_cast<uint8_t const *>(authLength->getName()));
    zrtpCommit.setPubKeyType(reinterpret_cast<uint8_t const *>(pubKey->getName()));
    zrtpCommit.setSasType(reinterpret_cast<uint8_t const *>(sasType->getName()));
    zrtpCommit.setHvi(hvi);
    if (isNpAlgorithmActive) {
        zrtpCommit.setPacketLength(pubKeyBytes.size());
        zrtpCommit.setPv(pubKeyBytes.data());
    }

    len = zrtpCommit.getLength() * ZRTP_WORD_SIZE;

    // Compute HMAC over Commit, excluding the HMAC field (HMAC_SIZE)
    // and store in Hello. Key to HMAC is H1, use HASH_IMAGE_SIZE bytes only.
    // Must use implicit HMAC functions.
    hmacFunctionImpl(H1, HASH_IMAGE_SIZE, zrtpCommit.getHeaderBase(), len - HMAC_SIZE, hmac);
    zrtpCommit.setHMAC(hmac);

    // Hash first messages to produce overall message hash
    // First the Responder's Hello message, second the Commit (always Initiator's).
    // Must use the negotiated hash.
    // In the case of a new client (Zrtp2022), thus isNpAlgorithmActive == true, use:
    // total_hash = hash(Hello of initiator ||
    //                   Hello of responder ||
    //                   Commit || DHPart1 ||
    //                   DHPart2)
    msgShaContext = createHashCtx();
    if (isNpAlgorithmActive) {
        hashCtxFunction(msgShaContext, currentHelloPacket->getHeaderBase(),
                        currentHelloPacket->getLength() * ZRTP_WORD_SIZE);
    }
    hashCtxFunction(msgShaContext, hello->getHeaderBase(), helloLen);
    hashCtxFunction(msgShaContext, zrtpCommit.getHeaderBase(), len);

    // store Hello data temporarily until we can check HMAC after receiving Commit as
    // Responder or DHPart1 as Initiator
    storeMsgTemp(hello);
    return &zrtpCommit;
}

ZrtpPacketCommit *ZRtp::prepareCommitMultiStream(ZrtpPacketHello const *hello) {
    randomZRTP(hvi, ZRTP_WORD_SIZE * 4); // This is the Multi-Stream NONCE size

    zrtpCommit.setZid(ownZid.data());
    zrtpCommit.setHashType(reinterpret_cast<uint8_t const *>(hash->getName()));
    zrtpCommit.setCipherType(reinterpret_cast<uint8_t const *>(cipher->getName()));
    zrtpCommit.setAuthLen(reinterpret_cast<uint8_t const *>(authLength->getName()));
    zrtpCommit.setPubKeyType(reinterpret_cast<uint8_t const *>(mult)); // this is fixed because of Multi-Stream mode
    zrtpCommit.setSasType(reinterpret_cast<uint8_t const *>(sasType->getName()));
    zrtpCommit.setNonce(hvi);
    zrtpCommit.setH2(H2);

    uint32_t const len = zrtpCommit.getLength() * ZRTP_WORD_SIZE;

    // Compute HMAC over Commit, excluding the HMAC field (HMAC_SIZE)
    // and store in Hello. Key to HMAC is H1, use HASH_IMAGE_SIZE bytes only.
    // Must use the implicit HMAC function.
    zrtp::ImplicitDigest hmac;
    hmacFunctionImpl(H1, HASH_IMAGE_SIZE, zrtpCommit.getHeaderBase(), len - HMAC_SIZE, hmac);
    zrtpCommit.setHMACMulti(hmac);


    // Hash first messages to produce overall message hash.
    // First the Responder's Hello message, second the Commit
    // (always Initator's message).
    // Must use the negotiated hash.
    msgShaContext = createHashCtx();

    uint32_t const helloLen = hello->getLength() * ZRTP_WORD_SIZE;
    hashCtxFunction(msgShaContext, hello->getHeaderBase(), helloLen);
    hashCtxFunction(msgShaContext, zrtpCommit.getHeaderBase(), len);

    // store Hello data temporarily until we can check HMAC after receiving Commit as
    // Responder or DHPart1 as Initiator
    storeMsgTemp(hello);

    return &zrtpCommit;
}

/*
 * At this point, we will take the role of the Responder. We have been in
 * the role of the Initiator before and already sent a commit packet that
 * may have clashed with a commit packet from our peer. If our HVI was lower than our
 * peer's HVI, then we switched to Responder. Handle our peer's commit packet
 * here. This method takes care to delete and refresh data left over from a
 * possible Initiator preparation. This belongs to prepared DH data, message
 * hash SHA context.
 */
ZrtpPacketDHPart *ZRtp::prepareDHPart1(ZrtpPacketCommit const *commit, uint32_t *errMsg) {
    sendInfo(Info, InfoRespCommitReceived);

    if (!commit->isLengthOk(ZrtpPacketCommit::DhExchange)) {
        *errMsg = CriticalSWError;
        return nullptr;
    }

    // Check if ZID in Commit is the same as we got in Hello
    secUtilities::SecureArray<ZID_SIZE> tmpZid;
    tmpZid.assign(commit->getZid(), ZID_SIZE);
    if (!peerZid.equals(tmpZid, ZID_SIZE)) {
        // ZIDs do not match????
        sendInfo(Severe, SevereProtocolError);
        *errMsg = CriticalSWError;
        return nullptr;
    }

    // The following code checks the hash chain according chapter 10 to detect false ZRTP packets.
    // Must use the implicit hash function.
    uint8_t tmpH3[IMPL_MAX_DIGEST_LENGTH];
    memcpy(peerH2, commit->getH2(), HASH_IMAGE_SIZE);
    hashFunctionImpl(peerH2, HASH_IMAGE_SIZE, tmpH3);

    if (memcmp(tmpH3, peerH3, HASH_IMAGE_SIZE) != 0) {
        *errMsg = IgnorePacket;
        return nullptr;
    }

    // Check HMAC of the previous Hello packet stored in temporary buffer. The
    // HMAC key of peer's Hello packet is peer's H2 that is contained in the
    // Commit packet. Refer to chapter 9.1.
    if (!checkMsgHmac(peerH2)) {
        sendInfo(Severe, SevereHelloHMACFailed);
        *errMsg = CriticalSWError;
        return nullptr;
    }

    // check if we support the committed Cipher type
    AlgorithmEnum *cp = &zrtpSymCiphers.getByName(reinterpret_cast<const char *>(commit->getCipherType()));
    if (!cp->isValid()) {
        // no match - something went wrong
        *errMsg = UnsuppCiphertype;
        return nullptr;
    }
    cipher = cp;

    // check if we support the committed Authentication length
    cp = &zrtpAuthLengths.getByName(reinterpret_cast<const char *>(commit->getAuthLen()));
    if (!cp->isValid()) {
        // no match - something went wrong
        *errMsg = UnsuppSRTPAuthTag;
        return nullptr;
    }
    authLength = cp;

    // check if we support the committed hash type
    cp = &zrtpHashes.getByName(reinterpret_cast<const char *>(commit->getHashType()));
    if (!cp->isValid()) {
        // no match - something went wrong
        *errMsg = UnsuppHashType;
        return nullptr;
    }
    // Check if the peer's committed hash is the same that we used when
    // preparing our commit packet. If not, then perform the necessary resets and
    // recompute some data.
    if (strncmp(hash->getName(), cp->getName(), 4) != 0) {
        hash = cp;
        setNegotiatedHash(hash);
        // Compute the Initiator's and Responder's retained secret ids
        // with the committed hash.
        computeSharedSecretSet(*zidRec);
    }
    // check if we support the committed pub key type
    cp = &zrtpPubKeys.getByName(reinterpret_cast<char const *>(commit->getPubKeysType()));
    if (!cp->isValid()) {
        // no match - something went wrong
        *errMsg = UnsuppPKExchange;
        return nullptr;
    }
    // If committed pub-key type is strong, then check for strong hashes as well.
    // Security levels must match
    if (strncmp(cp->getName(), ec38, 4) == 0 ||
        strncmp(cp->getName(), e414, 4) == 0 ||
        strncmp(cp->getName(), np06, 4) == 0 ||
        strncmp(cp->getName(), np09, 4) == 0 ||
        strncmp(cp->getName(), np12, 4) == 0) {
        if (!(strncmp(hash->getName(), s384, 4) == 0 || strncmp(hash->getName(), skn3, 4) == 0)) {
            *errMsg = UnsuppHashType;
            return nullptr;
        }
    }
    pubKey = cp;

    // check if we support the committed SAS type
    cp = &zrtpSasTypes.getByName(reinterpret_cast<const char *>(commit->getSasType()));
    if (!cp->isValid()) {
        // no match - something went wrong
        *errMsg = UnsuppSASScheme;
        return nullptr;
    }
    sasType = cp;

    // dhContext cannot be nullptr - always setup during prepareCommit()
    // check if we can use the dhContext prepared by prepareCommit(),
    // if not delete old DH context and generate new one
    // The algorithm names are 4 chars only, thus we can cast to int32_t
    if (strncmp(dhContext->getDHtype(), pubKey->getName(), 4) == 0) {
        dhContext = make_unique<ZrtpDH>(pubKey->getName());
    }

    // When using NPxx algorithm, the Commit packet contains the Initiator's public keys of NPxx
    // and E414. Compute the Responder's shared secrets now. This *must* be done *before*
    // getting the Responder's public key data. `computeSecretKey` computes the Responder's
    // cipher data and public key of the NPxx/EC 414 algorithm respectively.
    if (isNpAlgorithmActive) {
        dhContext->computeSecretKey(commit->getPv(), DHss, ZrtpDH::Commit);
    }
    sendInfo(Info, InfoDH1DHGenerated);

    // In the case of NPxx algorithms: the public key data contains the SNTRUP cipher text
    // and my E414 public key. `computeSecreteKey` above computed the SNTRUP cipher text
    // which is the encrypted shared key of SNTRUP.
    dhContext->getPubKeyBytes(pubKeyBytes, ZrtpDH::DhPart1);

    // Re-compute auxSecretIDr because we changed roles *IDr with my H3, *IDi with peer's H3
    // Set up a DHPart1 packet.
    myRole = Responder;
    computeAuxSecretIds(); // recompute AUX secret ids because we are now Responder, use different H3

    zrtpDH1.setPacketLength(pubKeyBytes.size());
    zrtpDH1.setMessageType(DHPart1Msg);
    zrtpDH1.setRs1Id(rs1IDr);
    zrtpDH1.setRs2Id(rs2IDr);
    zrtpDH1.setAuxSecretId(auxSecretIDr);
    zrtpDH1.setPbxSecretId(pbxSecretIDr);
    zrtpDH1.setPv(pubKeyBytes.data());
    zrtpDH1.setH1(H1);

    int32_t const len = zrtpDH1.getLength() * ZRTP_WORD_SIZE;

    // Compute HMAC over DHPart1, excluding the HMAC field (HMAC_SIZE)
    // and store in DHPart1.
    // Use implicit Hash function
    zrtp::ImplicitDigest hmac;
    hmacFunctionImpl(H0, HASH_IMAGE_SIZE, zrtpDH1.getHeaderBase(), len - HMAC_SIZE, hmac);
    zrtpDH1.setHMAC(hmac);

    // We are definitely responder. Save the peer's hvi for later compare.
    memcpy(peerHvi, commit->getHvi(), HVI_SIZE);

    // We are the responder. Release the pre-computed hash context because it was prepared for Initiator.
    // Setup and compute for Responder.
    if (msgShaContext != nullptr) {
        zrtp::NegotiatedArray dummy;
        closeHashCtx(msgShaContext, dummy);
    }
    msgShaContext = createHashCtx();

    // Hash messages to produce overall message hash:
    // First the Initiator's hello message, then Responder's (my) Hello message, second the Commit (always Initiator's),
    // then the DH1 message (which is always a Responder's message).
    // Must use negotiated hash.
    if (isNpAlgorithmActive) {
        ZrtpPacketHello const helloPkt(otherHelloPacket.data());
        hashCtxFunction(msgShaContext, helloPkt.getHeaderBase(),
                        helloPkt.getLength() * ZRTP_WORD_SIZE);
    }
    hashCtxFunction(msgShaContext, currentHelloPacket->getHeaderBase(),
                    currentHelloPacket->getLength() * ZRTP_WORD_SIZE);

    hashCtxFunction(msgShaContext, commit->getHeaderBase(), commit->getLength() * ZRTP_WORD_SIZE);
    hashCtxFunction(msgShaContext, zrtpDH1.getHeaderBase(), zrtpDH1.getLength() * ZRTP_WORD_SIZE);

    // store Commit data temporarily until we can check HMAC after we got DHPart2
    storeMsgTemp(commit);

    return &zrtpDH1;
}

/*
 * At this point, we will take the role of the Initiator.
 */
ZrtpPacketDHPart *ZRtp::prepareDHPart2(ZrtpPacketDHPart const *dhPart1, uint32_t *errMsg) {
    sendInfo(Info, InfoInitDH1Received);

    if (!dhPart1->isLengthOk(isNpAlgorithmActive)) {
        *errMsg = CriticalSWError;
        return nullptr;
    }
    // Because we are the Initiator, the protocol engine didn't receive Commit
    // thus could not store a peer's H2. A two-step SHA256 is required to
    // re-compute H3. Then compare with peer's H3 from peer's Hello packet.
    // Must use implicit hash function.
    uint8_t tmpHash[IMPL_MAX_DIGEST_LENGTH];
    hashFunctionImpl(dhPart1->getH1(), HASH_IMAGE_SIZE, tmpHash); // Compute peer's H2
    memcpy(peerH2, tmpHash, HASH_IMAGE_SIZE);
    hashFunctionImpl(peerH2, HASH_IMAGE_SIZE, tmpHash); // Compute peer's H3 (tmpHash)

    if (memcmp(tmpHash, peerH3, HASH_IMAGE_SIZE) != 0) {
        *errMsg = IgnorePacket;
        return nullptr;
    }

    // Check HMAC of the previous Hello packet stored in temporary buffer. The
    // HMAC key of the Hello packet is peer's H2 that was computed above.
    // Refer to chapter 9.1 and chapter 10.
    if (!checkMsgHmac(peerH2)) {
        sendInfo(Severe, SevereHelloHMACFailed);
        *errMsg = CriticalSWError;
        return nullptr;
    }

    // get and check Responder's public value(s), see chap. 5.4.3 in the spec
    uint8_t *pvr = dhPart1->getPv();
    if (pvr == nullptr) {
        *errMsg = IgnorePacket;
        return nullptr;
    }
    if (!dhContext->checkPubKey(pvr)) {
        *errMsg = DHErrorWrongPV;
        return nullptr;
    }
    // This computes the Initiator's shared secret. Same handling for NPxx or Diffie-Hellman
    // algorithms at this point. ZrtpDH takes care of it.
    if (dhContext->computeSecretKey(pvr, DHss, ZrtpDH::DhPart1) <= 0) {
        *errMsg = DHErrorWrongPV;
        return nullptr;
    }

    // We are the Initiator: the Responder's Hello and the Initiator's (our) Commit
    // are already hashed in the context. Now hash the Responder's DH1 and then
    // the Initiator's (our) DH2 in that order.
    // Use the negotiated hash function.
    hashCtxFunction(msgShaContext, dhPart1->getHeaderBase(), dhPart1->getLength() * ZRTP_WORD_SIZE);
    hashCtxFunction(msgShaContext, zrtpDH2.getHeaderBase(), zrtpDH2.getLength() * ZRTP_WORD_SIZE);

    // Compute the message Hash
    closeHashCtx(msgShaContext, messageHash);
    msgShaContext = nullptr;
    // Now compute the S0, all dependent keys and the new RS1. The function
    // also performs sign SAS callback if it's active.
    generateKeysInitiator(dhPart1, *zidRec);

    dhContext.reset();

    // store DHPart1 data temporarily until we can check HMAC after receiving Confirm1
    storeMsgTemp(dhPart1);
    return &zrtpDH2;
}

// TODO: implement function to setup stripped down Confirm1 - encrypt data in Confirm1 with Initiator's
//       keys
//       Handling of combined DHPart2 and Confirm1 packets -> roles changed when processing Confirm1 (is Responder)
//
// - Responder's DHss was computed in prepareDHPart1,
// - DHPart2 handling needs to generated the responder keys, then decrypt the confirm1 data, create and encrypt Confirm2
// - Confirm1 contains data encrypted with Initiator keys
// - check how to deal with the HMAC checks
/*
 * At this point we are Responder.
 */
ZrtpPacketConfirm *ZRtp::prepareConfirm1(ZrtpPacketDHPart const *dhPart2, uint32_t *errMsg) {
    sendInfo(Info, InfoRespDH2Received);

    if (!dhPart2->isLengthOk(isNpAlgorithmActive)) {
        *errMsg = CriticalSWError;
        return nullptr;
    }
    // Because we are the Responder, we received a Commit and stored its H2.
    // Now re-compute H2 from received H1 and compare with stored peer's H2.
    // Use implicit hash function
    uint8_t tmpHash[IMPL_MAX_DIGEST_LENGTH];
    hashFunctionImpl(dhPart2->getH1(), HASH_IMAGE_SIZE, tmpHash);
    if (memcmp(tmpHash, peerH2, HASH_IMAGE_SIZE) != 0) {
        *errMsg = IgnorePacket;
        return nullptr;
    }

    // Check HMAC of the Commit packet stored in temporary buffer. The
    // HMAC key of the Commit packet is peer's H1 that is contained in
    // DHPart2. Refer to chapter 9.1 and chapter 10.
    if (!checkMsgHmac(dhPart2->getH1())) {
        sendInfo(Severe, SevereCommitHMACFailed);
        *errMsg = CriticalSWError;
        return nullptr;
    }
    // Now we have the peer's pvi. Because we are responder re-compute my hvi
    // using my Hello packet and the Initiator's DHPart2 and compare with
    // hvi sent in the Commit packet. If it doesn't match, then a MitM attack
    // may have occurred.
    computeHvi(dhPart2, currentHelloPacket);
    if (memcmp(hvi, peerHvi, HVI_SIZE) != 0) {
        *errMsg = DHErrorWrongHVI;
        return nullptr;
    }
    // When using NPxx algorithms secret key was computed when preparing DHPart1 above
    if (!isNpAlgorithmActive) {
        // Get and check the Initiator's public value, see chap. 5.4.2 of the spec
        uint8_t *pvi = dhPart2->getPv();
        if (!dhContext->checkPubKey(pvi)) {
            *errMsg = DHErrorWrongPV;
            return nullptr;
        }
        if (dhContext->computeSecretKey(pvi, DHss, ZrtpDH::Ignore) <= 0) {
            *errMsg = DHErrorWrongPV;
            return nullptr;
        }
    }

    // Hash the Initiator's DH2 into the message Hash (other messages already prepared, see method prepareDHPart1()).
    // Use negotiated hash function
    hashCtxFunction(msgShaContext, dhPart2->getHeaderBase(), dhPart2->getLength() * ZRTP_WORD_SIZE);

    closeHashCtx(msgShaContext, messageHash);
    msgShaContext = nullptr;
    /*
     * The expected shared secret Ids were already computed when we built the
     * DHPart1 packet. Generate s0, all dependent keys, and the new RS1 value
     * for the ZID record. The function also performs sign SAS callback if it's
     * active. May reset the verify-flag in ZID record.
     */
    generateKeysResponder(dhPart2, *zidRec);

    dhContext.reset();

    // Fill in the Confirm1 packet.
    zrtpConfirm1.setMessageType(Confirm1Msg);

    // Check if user verified the SAS in a previous call and thus verified
    // the retained secret. Don't set the verified flag if paranoidMode is true.
    if (zidRec->isSasVerified() && !paranoidMode) {
        zrtpConfirm1.setSASFlag();
    }
    if (configureAlgos->isDisclosureFlag()) {
        zrtpConfirm1.setDisclosureFlag();
    }
    zrtpConfirm1.setExpTime(0xFFFFFFFF);
    zrtpConfirm1.setIv(randomIV);
    zrtpConfirm1.setHashH0(H0);

#ifdef ZRTP_SAS_RELAY_SUPPORT
    // if this runs at PBX user agent enrollment service, then set the flag in the Confirm
    // packet and store the MitM key
    if (enrollmentMode) {
        // As clarification to RFC6189: store new PBX secret only if we don't have
        // a matching PBX secret for the peer's ZID.
        if (!peerIsEnrolled) {
            computePBXSecret();
            zidRec->setMiTMData(pbxSecretTmp);
        }
        // Set the flag to enable user's client to ask for confirmation or re-confirmation.
        zrtpConfirm1.setPBXEnrollment();
    }
#endif
    zrtp::ImplicitDigest confMac;

    // Encrypt and HMAC with Responder's key - we are Responder here
    uint32_t const hmLen = (zrtpConfirm1.getLength() - 9U) * ZRTP_WORD_SIZE;
    cipher->getEncrypt()(zrtpKeyR.data(), cipher->getKeylen(), randomIV, zrtpConfirm1.getHashH0(), hmLen);
    hmacFunction(hmacKeyR.data(), hashLength, zrtpConfirm1.getHashH0(), hmLen, confMac);

    zrtpConfirm1.setHmac(confMac);

    // store DHPart2 data temporarily until we can check HMAC after receiving Confirm2
    storeMsgTemp(dhPart2);
    return &zrtpConfirm1;
}

/*
 * At this point we are Responder.
 */
ZrtpPacketConfirm *ZRtp::prepareConfirm1MultiStream(ZrtpPacketCommit const *commit, uint32_t *errMsg) {
    sendInfo(Info, InfoRespCommitReceived);

    if (!commit->isLengthOk(ZrtpPacketCommit::MultiStream)) {
        *errMsg = CriticalSWError;
        return nullptr;
    }
    // The following code checks the hash chain according chapter 10 to detect
    // false ZRTP packets.
    // Use implicit hash function
    uint8_t tmpH3[IMPL_MAX_DIGEST_LENGTH];
    memcpy(peerH2, commit->getH2(), HASH_IMAGE_SIZE);
    hashFunctionImpl(peerH2, HASH_IMAGE_SIZE, tmpH3);

    if (memcmp(tmpH3, peerH3, HASH_IMAGE_SIZE) != 0) {
        *errMsg = IgnorePacket;
        return nullptr;
    }

    // Check HMAC of the previous Hello packet stored in temporary buffer. The
    // HMAC key of peer's Hello packet is peer's H2 that is contained in the
    // Commit packet. Refer to chapter 9.1.
    if (!checkMsgHmac(peerH2)) {
        sendInfo(Severe, SevereHelloHMACFailed);
        *errMsg = CriticalSWError;
        return nullptr;
    }

    if (!checkAndSetNonce(commit->getNonce())) {
        *errMsg = NonceReused;
        return nullptr;
    }
    // check if Commit contains "Mult" as pub key type
    AlgorithmEnum *cp = &zrtpPubKeys.getByName(reinterpret_cast<const char *>(commit->getPubKeysType()));
    if (!cp->isValid() || strncmp(cp->getName(), mult, 4) != 0) {
        *errMsg = UnsuppPKExchange;
        return nullptr;
    }

    // check if we support the committed cipher
    cp = &zrtpSymCiphers.getByName(reinterpret_cast<const char *>(commit->getCipherType()));
    if (!cp->isValid()) {
        // no match - something went wrong
        *errMsg = UnsuppCiphertype;
        return nullptr;
    }
    cipher = cp;

    // check if we support the committed Authentication length
    cp = &zrtpAuthLengths.getByName(reinterpret_cast<const char *>(commit->getAuthLen()));
    if (!cp->isValid()) {
        // no match - something went wrong
        *errMsg = UnsuppSRTPAuthTag;
        return nullptr;
    }
    authLength = cp;

    // check if we support the committed hash type
    cp = &zrtpHashes.getByName(reinterpret_cast<const char *>(commit->getHashType()));
    if (!cp->isValid()) {
        // no match - something went wrong
        *errMsg = UnsuppHashType;
        return nullptr;
    }
    // Check if the peer's committed hash is the same that we used when
    // preparing our commit packet. If not do the necessary resets and
    // recompute some data.
    if (strncmp(hash->getName(), cp->getName(), 4) != 0) {
        hash = cp;
        setNegotiatedHash(hash);
    }
    myRole = Responder;

    // We are the Responder. Release a possibly pre-computed hash context
    // because this was prepared for Initiator. Then create a new one.
    if (msgShaContext != nullptr) {
        zrtp::NegotiatedArray dummy;
        closeHashCtx(msgShaContext, dummy);
    }
    msgShaContext = createHashCtx();

    // Hash messages to produce overall message hash:
    // First the Responder's (my) Hello message, second the Commit
    // (always Initiator's message)
    // use the negotiated hash
    hashCtxFunction(msgShaContext, currentHelloPacket->getHeaderBase(),
                    currentHelloPacket->getLength() * ZRTP_WORD_SIZE);
    hashCtxFunction(msgShaContext, commit->getHeaderBase(), commit->getLength() * ZRTP_WORD_SIZE);

    closeHashCtx(msgShaContext, messageHash);
    msgShaContext = nullptr;

    generateKeysMultiStream();

    // Fill in the Confirm1 packet.
    zrtpConfirm1.setMessageType(Confirm1Msg);
    if (configureAlgos->isDisclosureFlag()) {
        zrtpConfirm1.setDisclosureFlag();
    }
    zrtpConfirm1.setExpTime(0xFFFFFFFF);
    zrtpConfirm1.setIv(randomIV);
    zrtpConfirm1.setHashH0(H0);

    zrtp::ImplicitDigest confMac;

    // Encrypt and HMAC with Responder's key - we are Responder here
    uint32_t const hmLen = (zrtpConfirm1.getLength() - 9U) * ZRTP_WORD_SIZE;
    cipher->getEncrypt()(zrtpKeyR.data(), cipher->getKeylen(), randomIV, zrtpConfirm1.getHashH0(), hmLen);

    // Use negotiated HMAC (hash)
    hmacFunction(hmacKeyR.data(), hashLength, zrtpConfirm1.getHashH0(), hmLen, confMac);

    zrtpConfirm1.setHmac(confMac);

    // Store Commit data temporarily until we can check HMAC after receiving Confirm2
    storeMsgTemp(commit);
    return &zrtpConfirm1;
}

/*
 * At this point we are Initiator.
 */
ZrtpPacketConfirm *ZRtp::prepareConfirm2(ZrtpPacketConfirm const *confirm1, uint32_t *errMsg) {
    sendInfo(Info, InfoInitConf1Received);

    if (!confirm1->isLengthOk()) {
        *errMsg = CriticalSWError;
        return nullptr;
    }
    zrtp::ImplicitDigest confMac;

    // Use the Responder's keys here because we are Initiator here and
    // receive packets from Responder
    uint32_t hmlen = (confirm1->getLength() - 9) * ZRTP_WORD_SIZE;

    // Use negotiated HMAC (hash)
    hmacFunction(hmacKeyR.data(), hashLength, confirm1->getHashH0(), hmlen, confMac);

    if (!confMac.equals(confirm1->getHmac(), HMAC_SIZE)) {
        *errMsg = ConfirmHMACWrong;
        return nullptr;
    }
    cipher->getDecrypt()(zrtpKeyR.data(), cipher->getKeylen(), const_cast<uint8_t *>(confirm1->getIv()),
                         confirm1->getHashH0(),
                         hmlen);

    // Check HMAC of DHPart1 packet stored in temporary buffer. The
    // HMAC key of the DHPart1 packet is peer's H0 that is contained in
    // Confirm1. Refer to chapter 9.
    if (!checkMsgHmac(confirm1->getHashH0())) {
        sendInfo(Severe, SevereDH1HMACFailed);
        *errMsg = CriticalSWError;
        return nullptr;
    }
    /*
     * The Confirm1 is ok, handle the Retained secret stuff and inform
     * GUI about state.
     */
    bool sasFlag = confirm1->isSASFlag();

    // Our peer did not confirm the SAS in the last session, thus reset
    // our SAS flag too. Reset the flag also if paranoidMode is true.
    if (!sasFlag || paranoidMode) {
        zidRec->resetSasVerified();
    }

    // Store the status of the Disclosure flag
    peerDisclosureFlagSeen = confirm1->isDisclosureFlag();

    // Get verified flag from current RS1 before set a new RS1. This
    // may not be set even if peer's flag is set in the Confirm1 message.
    sasFlag = zidRec->isSasVerified();

    signatureLength = confirm1->getSignatureLength();
    if (signSasSeen && signatureLength > 0 && confirm1->isSignatureLengthOk()) {
        signatureData = confirm1->getSignatureData();
        if (auto const ucb = callback.lock()) {
            ucb->checkSASSignature(sasHash.data());
            // error handling if checkSASSignature returns false? -> app (callback) should deal with this IMHO.
        }
    }
    // now we are ready to save the new RS1, which inherits the verified
    // flag from old RS1
    zidRec->setNewRs1(newRs1.data(), RS1_NO_EXPIRATION);

    // now generate my Confirm2 message
    zrtpConfirm2.setMessageType(Confirm2Msg);
    zrtpConfirm2.setHashH0(H0);

    if (sasFlag) {
        zrtpConfirm2.setSASFlag();
    }
    if (configureAlgos->isDisclosureFlag()) {
        zrtpConfirm2.setDisclosureFlag();
    }
    zrtpConfirm2.setExpTime(0xFFFFFFFF);
    zrtpConfirm2.setIv(randomIV);

#ifdef ZRTP_SAS_RELAY_SUPPORT
    // Compute PBX secret if we are in enrollment mode (PBX user agent)
    // or enrollment was enabled at normal user agent and flag in the Confirm packet
    if (enrollmentMode || (enableMitmEnrollment && confirm1->isPBXEnrollment())) {
        computePBXSecret();

        // If this runs at PBX user agent enrollment service, then set the flag in the Confirm
        // packet and store the MitM key. The PBX user agent service always stores
        // its MitM key.
        if (enrollmentMode) {
            // As clarification to RFC6189: store new PBX secret only if we don't have
            // a matching PBX secret for the peer's ZID.
            if (!peerIsEnrolled) {
                computePBXSecret();
                zidRec->setMiTMData(pbxSecretTmp);
            }
            // Set the flag to enable user's client to ask for confirmation or re-confirmation.
            zrtpConfirm2.setPBXEnrollment();
        }
    }
#endif
    if (saveZidRecord) {
        getZidCache()->saveRecord(*zidRec);
    }

    // Encrypt and HMAC with Initiator's key - we are Initiator here
    hmlen = (zrtpConfirm2.getLength() - 9) * ZRTP_WORD_SIZE;
    cipher->getEncrypt()(zrtpKeyI.data(), cipher->getKeylen(), randomIV, zrtpConfirm2.getHashH0(), hmlen);

    // Use negotiated HMAC (hash)
    hmacFunction(hmacKeyI.data(), hashLength, zrtpConfirm2.getHashH0(), hmlen, confMac);

    zrtpConfirm2.setHmac(confMac);

#ifdef ZRTP_SAS_RELAY_SUPPORT
    // Ask for enrollment only if enabled via configuration, and the
    // Confirm1 packet contains the enrollment flag. The enrolling user
    // agent stores the MitM key only if the user accepts the enrollment
    // request.
    if (enableMitmEnrollment && confirm1->isPBXEnrollment()) {
        // As clarification to RFC6189: if already enrolled (having a matching PBX secret)
        // ask for reconfirmation.
        if (!peerIsEnrolled) {
            callback->zrtpAskEnrollment(EnrollmentRequest);
        }
        else {
            callback->zrtpAskEnrollment(EnrollmentReconfirm);
        }
    }
#endif
    return &zrtpConfirm2;
}

/*
 * At this point we are Initiator.
 */
ZrtpPacketConfirm *ZRtp::prepareConfirm2MultiStream(ZrtpPacketConfirm const *confirm1, uint32_t *errMsg) {
    // check the Confirm1 packet using the keys
    // prepare Confirm2 packet
    // don't update SAS, RS
    sendInfo(Info, InfoInitConf1Received);

    if (!confirm1->isLengthOk()) {
        *errMsg = CriticalSWError;
        return nullptr;
    }
    zrtp::ImplicitDigest confMac;

    closeHashCtx(msgShaContext, messageHash);
    msgShaContext = nullptr;
    myRole = Initiator;

    generateKeysMultiStream();

    // Use the Responder's keys here because we are Initiator here and
    // receive packets from Responder
    uint32_t hmLen = (confirm1->getLength() - 9U) * ZRTP_WORD_SIZE;

    // Use negotiated HMAC (hash)
    hmacFunction(hmacKeyR.data(), hashLength, confirm1->getHashH0(), hmLen, confMac);

    if (!confMac.equals(confirm1->getHmac(), HMAC_SIZE)) {
        *errMsg = ConfirmHMACWrong;
        return nullptr;
    }
    // Cast away the const for the IV - the standalone AES CFB modifies IV on return
    cipher->getDecrypt()(zrtpKeyR.data(), cipher->getKeylen(), const_cast<uint8_t *>(confirm1->getIv()),
                         confirm1->getHashH0(),
                         hmLen);

    // Because we are the Initiator, the protocol engine didn't receive Commit, and
    // because we are using multi-stream mode here, we also did not receive a DHPart1 and
    // thus could not store a responder's H2 or H1. A two-step hash is required to
    // re-compute H1, H2.
    // USe implicit hash function.
    uint8_t tmpHash[IMPL_MAX_DIGEST_LENGTH];
    hashFunctionImpl(confirm1->getHashH0(), HASH_IMAGE_SIZE, tmpHash); // Compute peer's H1 in tmpHash
    hashFunctionImpl(tmpHash, HASH_IMAGE_SIZE, tmpHash); // Compute peer's H2 in tmpHash
    memcpy(peerH2, tmpHash, HASH_IMAGE_SIZE); // copy and truncate to peerH2

    // Check HMAC of the previous Hello packet stored in temporary buffer. The
    // HMAC key of the Hello packet is peer's H2 that was computed above.
    // Refer to chapter 9.1 and chapter 10.
    if (!checkMsgHmac(peerH2)) {
        sendInfo(Severe, SevereHelloHMACFailed);
        *errMsg = CriticalSWError;
        return nullptr;
    }
    // Store the status of the Disclosure flag
    peerDisclosureFlagSeen = confirm1->isDisclosureFlag();

    // now generate my Confirm2 message
    zrtpConfirm2.setMessageType(Confirm2Msg);
    if (configureAlgos->isDisclosureFlag()) {
        zrtpConfirm2.setDisclosureFlag();
    }
    zrtpConfirm2.setHashH0(H0);
    zrtpConfirm2.setExpTime(0xFFFFFFFF);
    zrtpConfirm2.setIv(randomIV);

    // Encrypt and HMAC with Initiator's key - we are Initiator here
    hmLen = (zrtpConfirm2.getLength() - 9U) * ZRTP_WORD_SIZE;
    cipher->getEncrypt()(zrtpKeyI.data(), cipher->getKeylen(), randomIV, zrtpConfirm2.getHashH0(), hmLen);

    // Use negotiated HMAC (hash)
    hmacFunction(hmacKeyI.data(), hashLength, zrtpConfirm2.getHashH0(), hmLen, confMac);

    zrtpConfirm2.setHmac(confMac);
    return &zrtpConfirm2;
}

/*
 * At this point we are Responder.
 */
ZrtpPacketConf2Ack *ZRtp::prepareConf2Ack(ZrtpPacketConfirm const *confirm2, uint32_t *errMsg) {
    sendInfo(Info, InfoRespConf2Received);

    if (!confirm2->isLengthOk()) {
        *errMsg = CriticalSWError;
        return nullptr;
    }
    zrtp::ImplicitDigest confMac;

    // Use the Initiator's keys here because we are Responder here and
    // receive packets from Initiator
    uint32_t const hmlen = (confirm2->getLength() - 9) * ZRTP_WORD_SIZE;

    // Use negotiated HMAC (hash)
    hmacFunction(hmacKeyI.data(), hashLength, confirm2->getHashH0(), hmlen, confMac);

    if (!confMac.equals(confirm2->getHmac(), HMAC_SIZE)) {
        *errMsg = ConfirmHMACWrong;
        return nullptr;
    }
    // Cast away the const for the IV - the standalone AES CFB modifies IV on return
    cipher->getDecrypt()(zrtpKeyI.data(), cipher->getKeylen(), const_cast<uint8_t *>(confirm2->getIv()),
                         confirm2->getHashH0(),
                         hmlen);

    if (!multiStream) {
        // Check HMAC of DHPart2 packet stored in temporary buffer. The
        // HMAC key of the DHPart2 packet is peer's H0 that is contained in
        // Confirm2. Refer to chapter 9.1 and chapter 10.
        if (!checkMsgHmac(confirm2->getHashH0())) {
            sendInfo(Severe, SevereDH2HMACFailed);
            *errMsg = CriticalSWError;
            return nullptr;
        }
        /*
         * The Confirm2 is ok, handle the Retained secret stuff and inform
         * GUI about state.
         */
        // Our peer did not confirm the SAS in the last session, thus reset
        // our SAS flag too. Reset the flag also if paranoidMode is true.
        if (bool const sasFlag = confirm2->isSASFlag(); !sasFlag || paranoidMode) {
            zidRec->resetSasVerified();
        }
        signatureLength = confirm2->getSignatureLength();
        if (signSasSeen && signatureLength > 0 && confirm2->isSignatureLengthOk()) {
            signatureData = confirm2->getSignatureData();
            if (auto const ucb = callback.lock()) {
                ucb->checkSASSignature(sasHash.data());
                // error handling if checkSASSignature returns false? -> app (callback) should deal with this IMHO.
            }
        }
        // save new RS1, this inherits the verified flag from old RS1
        zidRec->setNewRs1(newRs1.data(), RS1_NO_EXPIRATION);
        if (saveZidRecord) {
            getZidCache()->saveRecord(*zidRec);
        }

#ifdef ZRTP_SAS_RELAY_SUPPORT
        // Ask for enrollment only if enabled via configuration, and the
        // Confirm packet contains the enrollment flag. The enrolling user
        // agent stores the MitM key only if the user accepts the enrollment
        // request.
        if (enableMitmEnrollment && confirm2->isPBXEnrollment()) {
            computePBXSecret();
            // As clarification to RFC6189: if already enrolled (having a matching PBX secret)
            // ask for reconfirmation.
            if (!peerIsEnrolled) {
                callback->zrtpAskEnrollment(EnrollmentRequest);
            }
            else {
                callback->zrtpAskEnrollment(EnrollmentReconfirm);
            }
        }
#endif
    } else {
        // Check HMAC of the Commit packet stored in temporary buffer. The
        // HMAC key of the Commit packet is initiator's H1
        // use implicit hash function.
        uint8_t tmpHash[IMPL_MAX_DIGEST_LENGTH];
        hashFunctionImpl(confirm2->getHashH0(), HASH_IMAGE_SIZE, tmpHash); // Compute initiator's H1 in tmpHash

        if (!checkMsgHmac(tmpHash)) {
            sendInfo(Severe, SevereCommitHMACFailed);
            *errMsg = CriticalSWError;
            return nullptr;
        }
    }
    // Store the status of the Disclosure flag
    peerDisclosureFlagSeen = confirm2->isDisclosureFlag();

    return &zrtpConf2Ack;
}

ZrtpPacketErrorAck *ZRtp::prepareErrorAck(ZrtpPacketError const *epkt) {
    if (epkt->getLength() < 4)
        sendInfo(ZrtpError, CriticalSWError * -1);
    else
        sendInfo(ZrtpError, static_cast<int32_t>(epkt->getErrorCode()) * -1);
    return &zrtpErrorAck;
}

ZrtpPacketError *ZRtp::prepareError(uint32_t const errMsg) {
    zrtpError.setErrorCode(errMsg);
    return &zrtpError;
}

ZrtpPacketPingAck *ZRtp::preparePingAck(ZrtpPacketPing const *ppkt) {
    if (ppkt->getLength() != 6) // A PING packet must have a length of 6 words
        return nullptr;
    // Because we do not support ZRTP proxy mode, use the truncated ZID.
    // If this code shall be used in ZRTP proxy implementation, the computation
    // of the endpoint hash must be enhanced (see sections 5.15ff and 5.16)
    zrtpPingAck.setLocalEpHash(ownZid.data());
    zrtpPingAck.setRemoteEpHash(ppkt->getEpHash());
    zrtpPingAck.setSSRC(peerSSRC);
    return &zrtpPingAck;
}


constexpr uint32_t MaxSasValue = 0xfffffed8; // 4294967000 decimal
static string sasDigit(const uint8_t *sasHash) {
    // Make sure the compiler properly aligns the byte array to an int boundary
    // so that we can use it as an int
    union alignmentUnion {
        uint32_t toAlign;
        uint8_t bytes[4];
    };

    int32_t found = 0;
    int32_t sasDigits[2];

    // Treat the sasHash as a big endian value: the most significant byte is on the lowest address.
    // Keep that order while looping over the data.
    // The loop creates and checks at most 28 values
    //
    // Set index 0
    // Loop:
    // - Take 4 bytes, create an unsigned int, check against the max value and use it if it fits
    // - If it does not fit continue
    // - increment byte index by one
    // - if not found 2 values and more data available try next value
    // - terminate loop if 2 values found or data exhausted
    for (int32_t i = 0; i < SHA256_DIGEST_LENGTH - 4 && found < 2; i++) {
        alignmentUnion data{};
        data.bytes[0] = sasHash[i];
        data.bytes[1] = sasHash[i + 1];
        data.bytes[2] = sasHash[i + 2];
        data.bytes[3] = sasHash[i + 3];

        // For comparing and further processing, we need the host order
        uint32_t const value = zrtpNtohl(*reinterpret_cast<uint32_t *>(data.bytes));

        if (value > MaxSasValue) {
            continue;
        }
        sasDigits[found] = static_cast<int32_t>(value % 1000); // mod 1000 -> always fits into 32bit signed
        found++;
    }

    if (found != 2) {
        return {};
    }

    char stringBuffer[10];
    snprintf(stringBuffer, 9, "%d%d", sasDigits[0], sasDigits[1]);
    string sas(stringBuffer);
    return sas;
}

ZrtpPacketRelayAck *ZRtp::prepareRelayAck(ZrtpPacketSASrelay const *srly, const uint32_t *errMsg) {
#ifdef ZRTP_SAS_RELAY_SUPPORT
    // Handle and render SAS relay data only if the peer announced that it is a trusted
    // PBX. Don't handle SAS relay in paranoidMode.
    if (!mitmSeen || paranoidMode)
        return &zrtpRelayAck;

    if (!srly->isLengthOk()) {
        *errMsg = CriticalSWError;
        return nullptr;
    }
    uint8_t* hkey, *ekey;
    // If we are the Responder, then the PBX used its Initiator keys
    if (myRole == Responder) {
        hkey = hmacKeyI;
        ekey = zrtpKeyI;
    }
    else {
        hkey = hmacKeyR;
        ekey = zrtpKeyR;
    }

    uint8_t confMac[MAX_DIGEST_LENGTH];
    uint32_t macLen;

    int16_t hmlen = (srly->getLength() - 9) * ZRTP_WORD_SIZE;

    // Use negotiated HMAC (hash)
    hmacFunction(hkey, hashLength, (unsigned char*)srly->getFiller(), hmlen, confMac, &macLen);

    if (memcmp(confMac, srly->getHmac(), HMAC_SIZE) != 0) {
        *errMsg = ConfirmHMACWrong;
        return nullptr;
    }
    // Cast away the const for the IV - the standalone AES CFB modifies IV on return
    cipher->getDecrypt()(ekey, cipher->getKeylen(), (uint8_t*)srly->getIv(), (uint8_t*)srly->getFiller(), hmlen);

    const uint8_t* newSasHash = srly->getTrustedSas();
    bool sasHashNull = true;
    for (int i = 0; i < HASH_IMAGE_SIZE; i++) {
        if (newSasHash[i] != 0) {
            sasHashNull = false;
            break;
        }
    }
    string cs(cipher->getReadable());
    cs.append("/").append(pubKey->getName());

    // Check if new SAS is null or a trusted MitM relationship doesn't exist.
    // If this is the case, then don't render and don't show the new SAS - use
    // our computed SAS hash, but we may use a different SAS rendering algorithm to
    // render the computed SAS.
    if (sasHashNull || !peerIsEnrolled) {
        cs.append("/MitM");
        newSasHash = sasHash;
    }
    else {
        cs.append("/SASviaMitM");
    }
    // If other SAS schemes required - check here and use others
    const uint8_t* render = srly->getSasAlgo();
    AlgorithmEnum* renderAlgo = &zrtpSasTypes.getByName((const char*)render);
    uint8_t sasBytes[4];
    if (renderAlgo->isValid()) {
        sasBytes[0] = newSasHash[0];
        sasBytes[1] = newSasHash[1];
        sasBytes[2] = newSasHash[2] & 0xf0;
        sasBytes[3] = 0;
        if (*(int32_t*)b32 == *(int32_t*)(renderAlgo->getName())) {
            SAS = Base32(sasBytes, 20).getEncoded();
        }
        else if (*(int32_t*)b32e == *(int32_t*)(renderAlgo->getName())) {
            SAS = *EmojiBase32::u32StringToUtf8(EmojiBase32(sasBytes, 20).getEncoded());
        }
        else if (*(int32_t*)b10d == *(int32_t*)(renderAlgo->getName())) {
            SAS = sasDigit(sasHash);
            if (SAS.empty()) {
                // report fatal error
            }
        }
        else {
            SAS.assign(sas256WordsEven[sasBytes[0]]).append(":").append(sas256WordsOdd[sasBytes[1]]);
        }
    }
    bool verify = zidRec->isSasVerified() && srly->isSASFlag();
    callback->srtpSecretsOn(cs, SAS, verify);
#else
    (void) srly;
    (void) errMsg;
#endif
    return &zrtpRelayAck;
}

// NO GoClear handling
#if 0
ZrtpPacketClearAck* ZRtp::prepareClearAck(ZrtpPacketGoClear* gpkt) {
    sendInfo(Warning, WarningGoClearReceived);
    return &zrtpClearAck;
}

ZrtpPacketGoClear* ZRtp::prepareGoClear(uint32_t errMsg) {
    ZrtpPacketGoClear* gclr = &zrtpGoClear;
    gclr->clrClearHmac();
    return gclr;
}
#endif
/*
 * The next functions look up and return a preferred algorithm. These
 * functions work as follows:
 * - If the Hello packet does not contain an algorithm (number of algorithms
 *   is zero) then return the mandatory algorithm.
 * - Build a list of algorithm names and ids from configuration data. If
 *   the configuration data does not contain a mandatory algorithm, append
 *   the mandatory algorithm to the list and ids.
 * - Build a list of algorithm names from the Hello message. If
 *   the Hello message does not contain a mandatory algorithm, append
 *   the mandatory algorithm to the list.
 * - Lookup a matching algorithm. The list built from Hello takes
 *   precedence in the lookup (indexed by the outermost loop).
 *
 * This guarantees that we always return a supported algorithm respecting
 * the order of algorithms in the Hello message
 *
 * The mandatory algorithms are: (internal enums are our preferred algorithms)
 * Hash:                S256 (SHA 256)             (internal enum Sha256)
 * Symmetric Cipher:    AES1 (AES 128)             (internal enum Aes128)
 * SRTP Authentication: HS32 and HS80 (32/80 bits) (internal enum AuthLen32)
 * Key Agreement:       DH3k (3072 Diffie-Hellman)  (internal enum Dh3072)
 *
 */
AlgorithmEnum *ZRtp::findBestHash(ZrtpPacketHello const *hello) const {
    AlgorithmEnum *algosOffered[maxNoOfAlgos + 1];
    AlgorithmEnum *algosConf[maxNoOfAlgos + 1];

    // If Hello does not contain any hash names return Sha256, its mandatory
    auto const num = hello->getNumHashes();
    if (num == 0) {
        return &zrtpHashes.getByName(mandatoryHash);
    }
    // Build a list of configured hash algorithm names.
    auto const numAlgosConf = configureAlgos->getNumConfiguredAlgos(HashAlgorithm);
    for (auto i = 0; i < numAlgosConf; i++) {
        algosConf[i] = &configureAlgos->getAlgoAt(HashAlgorithm, i);
    }

    // Build a list of offered known algos in Hello, append mandatory algos if necessary
    int32_t numAlgosOffered = 0;
    for (auto i = 0; i < num; i++) {
        algosOffered[numAlgosOffered] = &zrtpHashes.getByName(reinterpret_cast<char const *>(hello->getHashType(i)));
        if (!algosOffered[numAlgosOffered]->isValid())
            continue;
        numAlgosOffered++;
    }

    // Lookup offered algos in configured algos.
    for (auto i = 0; i < numAlgosOffered; i++) {
        for (auto ii = 0; ii < numAlgosConf; ii++) {
            if (strncmp(algosOffered[i]->getName(), algosConf[ii]->getName(), 4) == 0) {
                return algosConf[ii];
            }
        }
    }
    return &zrtpHashes.getByName(mandatoryHash);
}


AlgorithmEnum *ZRtp::findBestCipher(ZrtpPacketHello const *hello, AlgorithmEnum const *pk) const {
    AlgorithmEnum *algosOffered[maxNoOfAlgos + 1];
    AlgorithmEnum *algosConf[maxNoOfAlgos + 1];

    auto const num = hello->getNumCiphers();
    if (num == 0 || strncmp(pk->getName(), dh2k, 4) == 0) {
        return &zrtpSymCiphers.getByName(aes1);
    }

    // Build a list of configured cipher algorithm names.
    auto const numAlgosConf = configureAlgos->getNumConfiguredAlgos(CipherAlgorithm);
    for (auto i = 0; i < numAlgosConf; i++) {
        algosConf[i] = &configureAlgos->getAlgoAt(CipherAlgorithm, i);
    }
    // Build a list of offered known algos names in Hello.
    int32_t numAlgosOffered = 0;
    for (auto i = 0; i < num; i++) {
        algosOffered[numAlgosOffered] = &zrtpSymCiphers.getByName(
            reinterpret_cast<char const *>(hello->getCipherType(i)));
        if (!algosOffered[numAlgosOffered]->isValid())
            continue;
        numAlgosOffered++;
    }
    // Lookup offered algos in configured algos.  Prefer algorithms that appear first in the Hello packet (offered).
    for (auto i = 0; i < numAlgosOffered; i++) {
        for (auto ii = 0; ii < numAlgosConf; ii++) {
            if (strncmp(algosOffered[i]->getName(), algosConf[ii]->getName(), 4) == 0) {
                return algosConf[ii];
            }
        }
    }
    // If we don't have a match, use the mandatory algorithm
    return &zrtpSymCiphers.getByName(mandatoryCipher);
}

// We can have the non-NIST in the list of 'orderedAlgos' even if they are not available
// in the code (refer to ZrtpConfigure). If they are not build in, they cannot appear
// in 'configureAlgos' and thus not in the intersection lists. Thus, a ZRTP build that
// does not include the non-NIST curves also works without problems.
//
AlgorithmEnum *ZRtp::findBestPubkey(ZrtpPacketHello const *hello) {
    AlgorithmEnum *peerIntersect[maxNoOfAlgos + 1];
    AlgorithmEnum *ownIntersect[maxNoOfAlgos + 1];

    // Build a list of own pubkey algorithm names, must follow the order
    // defined in RFC 6189, chapter 4.1.2., weakest to strongest
    const char *orderedAlgos[] = {dh2k, e255, ec25, dh3k, e414, ec38, np06, np09, np12};
    constexpr auto numOrderedAlgos = sizeof(orderedAlgos) / sizeof(const char *);

    auto const numAlgosPeer = hello->getNumPubKeys();
    if (numAlgosPeer == 0) {
        hash = findBestHash(hello); // find a hash algorithm
        return &zrtpPubKeys.getByName(mandatoryPubKey);
    }
    // Build own list of intersecting algos, keep own order of algorithms
    // The list must include real public key algorithms only, so skip multi-stream mode,
    // pre-shared and alike.
    auto const numAlgosOwn = configureAlgos->getNumConfiguredAlgos(PubKeyAlgorithm);
    int numOwnIntersect = 0;
    for (auto i = 0; i < numAlgosOwn; i++) {
        ownIntersect[numOwnIntersect] = &configureAlgos->getAlgoAt(PubKeyAlgorithm, i);
        if (strncmp(ownIntersect[numOwnIntersect]->getName(), mult, 4) == 0) {
            continue; // skip multi-stream mode
        }
        for (int ii = 0; ii < numAlgosPeer; ii++) {
            if (strncmp(ownIntersect[numOwnIntersect]->getName(),
                        zrtpPubKeys.getByName(reinterpret_cast<char const *>(hello->getPubKeyType(ii))).getName(),
                        4) == 0) {
                numOwnIntersect++;
                break;
            }
        }
    }
    // Build a list of peer's intersecting algos: take the own list as input and build a
    // list of algorithms that we have in common. The order of the list is according
    // to peer's Hello packet (peer's preferences).
    int numPeerIntersect = 0;
    for (auto i = 0; i < numAlgosPeer; i++) {
        peerIntersect[numPeerIntersect] = &zrtpPubKeys.getByName(
            reinterpret_cast<char const *>(hello->getPubKeyType(i)));
        for (auto ii = 0; ii < numOwnIntersect; ii++) {
            if (strncmp(ownIntersect[ii]->getName(), peerIntersect[numPeerIntersect]->getName(), 4) == 0) {
                numPeerIntersect++;
                break;
            }
        }
    }
    if (numPeerIntersect == 0) {
        // If we don't have a common algorithm - use mandatory algorithms
        hash = findBestHash(hello);
        return &zrtpPubKeys.getByName(mandatoryPubKey);
    }

    // If we have only one algorithm in common or if the first entry matches - take it.
    // Otherwise, determine which algorithm from the intersection lists is first in the
    // list of ordered algorithms and select it (RFC6189, section 4.1.2).
    AlgorithmEnum *useAlgo;
    if (numPeerIntersect > 1 && strncmp(ownIntersect[0]->getName(), peerIntersect[0]->getName(), 4) != 0) {
        int own, peer;

        auto name = ownIntersect[0]->getName();
        for (own = 0; own < numOrderedAlgos; own++) {
            if (strncmp(name, orderedAlgos[own], 4) == 0)
                break;
        }
        name = peerIntersect[0]->getName();
        for (peer = 0; peer < numOrderedAlgos; peer++) {
            if (strncmp(name, orderedAlgos[peer], 4) == 0)
                break;
        }
        if (own < peer) {
            useAlgo = ownIntersect[0];
        } else {
            useAlgo = peerIntersect[0];
        }
    } else {
        useAlgo = peerIntersect[0];
    }
    // select a corresponding strong hash if necessary.
    auto const algoName = useAlgo->getName();
    if (strncmp(algoName, ec38, 4) == 0 ||
        strncmp(algoName, e414, 4) == 0 ||
        strncmp(algoName, np06, 4) == 0 ||
        strncmp(algoName, np09, 4) == 0 ||
        strncmp(algoName, np12, 4) == 0
    ) {
        hash = getStrongHashOffered(hello, algoName);
        cipher = getStrongCipherOffered(hello, algoName);
    } else {
        hash = getHashOffered(hello, algoName);
        cipher = getCipherOffered(hello, algoName);
    }
    authLength = getAuthLenOffered(hello, algoName);
    return useAlgo;
}

AlgorithmEnum *ZRtp::findBestSASType(ZrtpPacketHello const *hello) const {
    AlgorithmEnum *algosOffered[maxNoOfAlgos + 1];
    AlgorithmEnum *algosConf[maxNoOfAlgos + 1];

    auto const num = hello->getNumSas();
    if (num == 0) {
        return &zrtpSasTypes.getByName(mandatorySasType);
    }
    // Build a list of configured SAS algorithm names
    auto const numAlgosConf = configureAlgos->getNumConfiguredAlgos(SasType);
    for (auto i = 0; i < numAlgosConf; i++) {
        algosConf[i] = &configureAlgos->getAlgoAt(SasType, i);
    }
    // Build list of offered known algos in Hello,
    int32_t numAlgosOffered = 0;
    for (auto i = 0; i < num; i++) {
        algosOffered[numAlgosOffered] = &zrtpSasTypes.getByName(reinterpret_cast<const char *>(hello->getSasType(i)));
        if (!algosOffered[numAlgosOffered]->isValid())
            continue;
        numAlgosOffered++;
    }
    // Lookup offered algos in configured algos. Prefer algorithms that appear first in the Hello packet (offered).
    for (auto i = 0; i < numAlgosOffered; i++) {
        for (auto ii = 0; ii < numAlgosConf; ii++) {
            if (strncmp(algosOffered[i]->getName(), algosConf[ii]->getName(), 4) == 0) {
                return algosConf[ii];
            }
        }
    }
    // If we don't have a match - use the mandatory algorithm
    return &zrtpSasTypes.getByName(mandatorySasType);
}

AlgorithmEnum *ZRtp::findBestAuthLen(ZrtpPacketHello const *hello) const {
    AlgorithmEnum *algosOffered[maxNoOfAlgos + 2];
    AlgorithmEnum *algosConf[maxNoOfAlgos + 2];

    auto const num = hello->getNumAuth();
    if (num == 0) {
        return &zrtpAuthLengths.getByName(mandatoryAuthLen_1);
    }

    // Build a list of configured Authentication tag length algorithm names.
    auto const numAlgosConf = configureAlgos->getNumConfiguredAlgos(AuthLength);
    for (auto i = 0; i < numAlgosConf; i++) {
        algosConf[i] = &configureAlgos->getAlgoAt(AuthLength, i);
    }

    // Build a list of offered known algos in Hello.
    int32_t numAlgosOffered = 0;
    for (auto i = 0; i < num; i++) {
        algosOffered[numAlgosOffered] = &zrtpAuthLengths.
                getByName(reinterpret_cast<const char *>(hello->getAuthLen(i)));
        if (!algosOffered[numAlgosOffered]->isValid())
            continue;
        numAlgosOffered++;
    }

    // Lookup offered algos in configured algos. Prefer algorithms that appear first in the Hello packet (offered).
    for (auto i = 0; i < numAlgosOffered; i++) {
        for (auto ii = 0; ii < numAlgosConf; ii++) {
            if (strncmp(algosOffered[i]->getName(), algosConf[ii]->getName(), 4) == 0) {
                return algosConf[ii];
            }
        }
    }
    // If we don't have a match - use the mandatory algorithm
    return &zrtpAuthLengths.getByName(mandatoryAuthLen_1);
}

// The following set of functions implement a 'non-NIST first policy' if nonNist computes
// to true. They prefer nonNist algorithms if these are available. Otherwise, they use the NIST
// counterpart or simply call the according findBest*(...) function.
//
// Only the findBestPubkey(...) function calls them after it selected the public key algorithm.
// If the public key algorithm is non-NIST, and if the policy is set to PreferNonNist then
// nonNist becomes true.
//
// The functions work according to the RFC6189 spec: the initiator can select every algorithm
// that both parties support. Thus, the Initiator can even select an algorithm the wasn't offered
// in its own Hello packet but that the Initiator found in the peer's Hello and that is available
// for it.
//
AlgorithmEnum *ZRtp::getStrongHashOffered(ZrtpPacketHello const *hello, char const *algoName) const {
    auto const numHash = hello->getNumHashes();
    if ((strncmp(algoName, e414, 4) == 0 || strncmp(algoName, e255, 4) == 0) && configureAlgos->
        getSelectionPolicy() == ZrtpConfigure::PreferNonNist) {
        for (int i = 0; i < numHash; i++) {
            if (strncmp(reinterpret_cast<char const *>(hello->getHashType(i)), skn3, 4) == 0) {
                return &zrtpHashes.getByName(reinterpret_cast<char const *>(hello->getHashType(i)));
            }
        }
    }
    for (int i = 0; i < numHash; i++) {
        if (auto const nm = reinterpret_cast<char const *>(hello->getHashType(i)); strncmp(nm, s384, 4) == 0 || strncmp(nm, skn3, 4) == 0) {
            return &zrtpHashes.getByName(nm);
        }
    }
    return nullptr; // returning nullptr -> prepareCommit(...) terminates ZRTP, missing strong hash is an error
}

AlgorithmEnum *ZRtp::getStrongCipherOffered(ZrtpPacketHello const *hello, char const *algoName) const {
    auto const num = hello->getNumCiphers();
    if ((strncmp(algoName, e414, 4) == 0 || strncmp(algoName, e255, 4) == 0) && configureAlgos->
        getSelectionPolicy() == ZrtpConfigure::PreferNonNist) {
        for (int i = 0; i < num; i++) {
            if (strncmp(reinterpret_cast<char const *>(hello->getCipherType(i)), two3, 4) == 0) {
                return &zrtpSymCiphers.getByName(reinterpret_cast<char const *>(hello->getCipherType(i)));
            }
        }
    }
    for (int i = 0; i < num; i++) {
        if (auto const nm = reinterpret_cast<char const *>(hello->getCipherType(i)); strncmp(nm, aes3, 4) == 0 || strncmp(nm, two3, 4) == 0) {
            return &zrtpSymCiphers.getByName(nm);
        }
    }
    return nullptr; // returning nullptr -> prepareCommit(...) finds the best cipher
}

AlgorithmEnum *ZRtp::getHashOffered(ZrtpPacketHello const *hello, char const *algoName) const {
    auto const num = hello->getNumHashes();
    if ((strncmp(algoName, e414, 4) == 0 || strncmp(algoName, e255, 4) == 0) && configureAlgos->
        getSelectionPolicy() == ZrtpConfigure::PreferNonNist) {
        for (int i = 0; i < num; i++) {
            if (auto const nm = reinterpret_cast<char const *>(hello->getHashType(i)); strncmp(nm, skn2, 4) == 0 || strncmp(nm, skn3, 4) == 0) {
                return &zrtpHashes.getByName(nm);
            }
        }
    }
    return findBestHash(hello);
}

AlgorithmEnum *ZRtp::getCipherOffered(ZrtpPacketHello const *hello, char const *algoName) const {
    auto const num = hello->getNumCiphers();
    if ((strncmp(algoName, e414, 4) == 0 || strncmp(algoName, e255, 4) == 0) && configureAlgos->
        getSelectionPolicy() == ZrtpConfigure::PreferNonNist) {
        for (int i = 0; i < num; i++) {
            if (auto const nm = reinterpret_cast<char const *>(hello->getCipherType(i)); strncmp(nm, two2, 4) == 0 || strncmp(nm, two3, 4) == 0) {
                return &zrtpSymCiphers.getByName(nm);
            }
        }
    }
    return nullptr; // returning nullptr -> prepareCommit(...) finds the best cipher
}

AlgorithmEnum *ZRtp::getAuthLenOffered(ZrtpPacketHello const *hello, char const *algoName) const {
    auto const num = hello->getNumAuth();
    if ((strncmp(algoName, e414, 4) == 0 || strncmp(algoName, e255, 4) == 0) && configureAlgos->
        getSelectionPolicy() == ZrtpConfigure::PreferNonNist) {
        for (int i = 0; i < num; i++) {
            if (auto const nm = reinterpret_cast<char const *>(hello->getAuthLen(i)); strncmp(nm, sk32, 4) == 0 || strncmp(nm, sk64, 4) == 0) {
                return &zrtpAuthLengths.getByName(nm);
            }
        }
    }
    return findBestAuthLen(hello);
}

bool ZRtp::checkMultiStream(ZrtpPacketHello const *hello) {
    auto const num = hello->getNumPubKeys();

    // Multi Stream mode is mandatory, thus if nothing is offered then it is supported :-)
    if (num == 0) {
        return true;
    }
    for (auto i = 0; i < num; i++) {
        if (strncmp(reinterpret_cast<char const *>(hello->getPubKeyType(i)), mult, 4) == 0) {
            return true;
        }
    }
    return false;
}

bool ZRtp::verifyH2(ZrtpPacketCommit const *commit) const {
    uint8_t tmpH3[IMPL_MAX_DIGEST_LENGTH];

    // The packet does not have the correct size, treat H2 verification as failed.
    if (!commit->isLengthOk(multiStream ? ZrtpPacketCommit::MultiStream : ZrtpPacketCommit::DhExchange))
        return false;

    sha256(commit->getH2(), HASH_IMAGE_SIZE, tmpH3);
    return memcmp(tmpH3, peerH3, HASH_IMAGE_SIZE) == 0;
}

void ZRtp::computeHvi(ZrtpPacketDHPart const *dh, ZrtpPacketHello const *hello) {
    std::vector<const uint8_t *> data(3);
    std::vector<uint64_t> length(3);
    /*
     * populate the vector to compute the HVI hash according to the
     * ZRTP specification.
     */
    data.push_back(dh->getHeaderBase());
    length.push_back(dh->getLength() * ZRTP_WORD_SIZE);

    data.push_back(hello->getHeaderBase());
    length.push_back(hello->getLength() * ZRTP_WORD_SIZE);
    hashListFunction(data, length, hvi);
}

void ZRtp::computeSharedSecretSet(ZIDRecord &zidRecord) {
    /*
     * Compute the Initiator's and Responder's retained shared secret Ids.
     * Use negotiated HMAC.
     */
    uint8_t randBuf[RS_LENGTH];

    detailInfo.secretsCached = 0;
    if (!zidRecord.isRs1Valid()) {
        randomZRTP(randBuf, RS_LENGTH);
        hmacFunction(randBuf, RS_LENGTH, reinterpret_cast<uint8_t const *>(initiator),
                     static_cast<uint32_t>(strlen(initiator)), rs1IDi);
        hmacFunction(randBuf, RS_LENGTH, reinterpret_cast<uint8_t const *>(responder),
                     static_cast<uint32_t>(strlen(responder)), rs1IDr);
    } else {
        rs1Valid = true;
        hmacFunction(zidRecord.getRs1(), RS_LENGTH, reinterpret_cast<uint8_t const *>(initiator),
                     static_cast<uint32_t>(strlen(initiator)), rs1IDi);
        hmacFunction(zidRecord.getRs1(), RS_LENGTH, reinterpret_cast<uint8_t const *>(responder),
                     static_cast<uint32_t>(strlen(responder)), rs1IDr);
        detailInfo.secretsCached = Rs1;
    }

    if (!zidRecord.isRs2Valid()) {
        randomZRTP(randBuf, RS_LENGTH);
        hmacFunction(randBuf, RS_LENGTH, reinterpret_cast<uint8_t const *>(initiator),
                     static_cast<uint32_t>(strlen(initiator)), rs2IDi);
        hmacFunction(randBuf, RS_LENGTH, reinterpret_cast<uint8_t const *>(responder),
                     static_cast<uint32_t>(strlen(responder)), rs2IDr);
    } else {
        rs2Valid = true;
        hmacFunction(zidRecord.getRs2(), RS_LENGTH, reinterpret_cast<uint8_t const *>(initiator),
                     static_cast<uint32_t>(strlen(initiator)), rs2IDi);
        hmacFunction(zidRecord.getRs2(), RS_LENGTH, reinterpret_cast<uint8_t const *>(responder),
                     static_cast<uint32_t>(strlen(responder)), rs2IDr);
        detailInfo.secretsCached |= Rs2;
    }

    if (!zidRecord.isMITMKeyAvailable()) {
        randomZRTP(randBuf, RS_LENGTH);
        hmacFunction(randBuf, RS_LENGTH, reinterpret_cast<uint8_t const *>(initiator),
                     static_cast<uint32_t>(strlen(initiator)),
                     pbxSecretIDi);
        hmacFunction(randBuf, RS_LENGTH, reinterpret_cast<uint8_t const *>(responder),
                     static_cast<uint32_t>(strlen(responder)),
                     pbxSecretIDr);
    } else {
        hmacFunction(zidRecord.getMiTMData(), RS_LENGTH, reinterpret_cast<uint8_t const *>(initiator),
                     static_cast<uint32_t>(strlen(initiator)), pbxSecretIDi);
        hmacFunction(zidRecord.getMiTMData(), RS_LENGTH, reinterpret_cast<uint8_t const *>(responder),
                     static_cast<uint32_t>(strlen(responder)), pbxSecretIDr);
        detailInfo.secretsCached |= Pbx;
    }
    computeAuxSecretIds();
}

void ZRtp::computeAuxSecretIds() {
    if (!auxSecret) {
        uint8_t randBuf[RS_LENGTH];
        randomZRTP(randBuf, RS_LENGTH);
        hmacFunction(randBuf, RS_LENGTH, H3, HASH_IMAGE_SIZE, auxSecretIDi);
        hmacFunction(randBuf, RS_LENGTH, H3, HASH_IMAGE_SIZE, auxSecretIDr);
    } else {
        if (myRole == Initiator) {
            // I'm initiator thus use my H3 for initiator's IDi, peerH3 for responder's IDr
            hmacFunction(auxSecret.get(), auxSecretLength, H3, HASH_IMAGE_SIZE, auxSecretIDi);
            hmacFunction(auxSecret.get(), auxSecretLength, peerH3, HASH_IMAGE_SIZE, auxSecretIDr);
        } else {
            hmacFunction(auxSecret.get(), auxSecretLength, peerH3, HASH_IMAGE_SIZE, auxSecretIDi);
            hmacFunction(auxSecret.get(), auxSecretLength, H3, HASH_IMAGE_SIZE, auxSecretIDr);
        }
    }
}

/*
 * The DH packet for this function is DHPart1 and contains the Responder's
 * retained secret ids. Compare them with the expected secret ids (refer
 * to chapter 5.3 in the specification).
 * When using this method, then we are in Initiator role.
 */
void ZRtp::generateKeysInitiator(ZrtpPacketDHPart const *dhPart, ZIDRecord &zidRecord) {
    const uint8_t *setD[3];
    int32_t rsFound = 0;

    setD[0] = setD[1] = setD[2] = nullptr;

    detailInfo.secretsMatchedDH = 0;
    if (rs1IDr.equals(dhPart->getRs1Id(), HMAC_SIZE) || rs1IDr.equals(dhPart->getRs2Id(), HMAC_SIZE))
        detailInfo.secretsMatchedDH |= Rs1;
    if (rs2IDr.equals(dhPart->getRs1Id(), HMAC_SIZE) || rs2IDr.equals(dhPart->getRs2Id(), HMAC_SIZE))
        detailInfo.secretsMatchedDH |= Rs2;
    /*
     * Select the real secrets into setD. The dhPart is DHpart1 message
     * received from responder. rs1IDr and rs2IDr are the expected ids using
     * the initiator's cached retained secrets.
     */
    // Check which RS we shall use for first place (s1)
    detailInfo.secretsMatched = 0;
    if (rs1IDr.equals(dhPart->getRs1Id(), HMAC_SIZE)) {
        setD[0] = zidRecord.getRs1();
        rsFound = 0x1;
        detailInfo.secretsMatched = Rs1;
    } else if (rs1IDr.equals(dhPart->getRs2Id(), HMAC_SIZE)) {
        setD[0] = zidRecord.getRs1();
        rsFound = 0x2;
        detailInfo.secretsMatched = Rs1;
    } else if (rs2IDr.equals(dhPart->getRs1Id(), HMAC_SIZE)) {
        setD[0] = zidRecord.getRs2();
        rsFound = 0x4;
        detailInfo.secretsMatched = Rs2;
    } else if (rs2IDr.equals(dhPart->getRs2Id(), HMAC_SIZE)) {
        setD[0] = zidRecord.getRs2();
        rsFound = 0x8;
        detailInfo.secretsMatched = Rs2;
    }

    if (auxSecretIDr.equals(dhPart->getAuxSecretId(), 8)) {
        setD[1] = auxSecret.get();
        detailInfo.secretsMatched |= Aux;
        detailInfo.secretsMatchedDH |= Aux;
    }
    if (auxSecret && (detailInfo.secretsMatched & Aux) == 0) {
        sendInfo(Warning, WarningNoExpectedAuxMatch);
    }

#ifdef ZRTP_SAS_RELAY_SUPPORT
    // check if we have a matching PBX secret and place it third (s3)
    if (memcmp(pbxSecretIDr, dhPart->getPbxSecretId(), HMAC_SIZE) == 0) {
        DEBUGOUT((fprintf(stdout, "%c: Match for Other_secret found\n", zid[0])));
        setD[2] = zidRecord->getMiTMData();
        detailInfo.secretsMatched |= Pbx;
        detailInfo.secretsMatchedDH |= Pbx;
        // Flag to record that fact that we have a MitM key of the other peer.
        peerIsEnrolled = true;
    }
#endif
    // Check if some retained secrets found
    if (rsFound == 0) {
        // no RS matches found
        if (rs1Valid || rs2Valid) {
            // but valid RS records in cache
            sendInfo(Warning, WarningNoExpectedRSMatch);
            zidRecord.resetSasVerified();
            saveZidRecord = false; // Don't save RS until user verified/confirmed SAS
        } else {
            // No valid RS record in cache
            sendInfo(Warning, WarningNoRSMatch);
        }
    } else {
        // at least one RS matches
        sendInfo(Info, InfoRSMatchFound);
    }
    /*
     * Ready to generate s0 here.
     * The formula to compute S0 (Refer to ZRTP specification 5.4.4):
     *
      s0 = hash( counter | DHResult | "ZRTP-HMAC-KDF" | ZIDi | ZIDr | \
      total_hash | len(s1) | s1 | len(s2) | s2 | len(s3) | s3)
     *
     * Note: in this function we are Initiator, thus ZIDi is our zid
     * (zid), ZIDr is the peer's zid (peerZid).
     */

    /*
     * These vectors hold the pointers and lengths of the data that must be
     * hashed to create S0.
     */
    std::vector<uint8_t const *> data;
    std::vector<uint64_t> length;

    // we need a number of length data items, so define them here
    uint32_t sLen[3];

    // The very first element is a fixed counter, big endian
    uint32_t counter = 1;
    counter = zrtpHtonl(counter);
    data.push_back(reinterpret_cast<uint8_t const *>(&counter));
    length.push_back(sizeof(uint32_t));

    // Next is the DH result itself
    data.push_back(DHss.data());
    length.push_back(DHss.size());

    // Next the fixed string "ZRTP-HMAC-KDF"
    data.push_back(reinterpret_cast<uint8_t const *>(KDFString));
    length.push_back(static_cast<uint32_t>(strlen(KDFString)));

    // Next is Initiator's id (ZIDi), in this case as Initiator
    // it is zid
    data.push_back(ownZid.data());
    length.push_back(ZID_SIZE);

    // Next is Responder's id (ZIDr), in this case, our peer's id
    data.push_back(peerZid.data());
    length.push_back(ZID_SIZE);

    // Next ist total hash (messageHash) itself
    data.push_back(messageHash.data());
    length.push_back(messageHash.size());

    /*
     * For each matching shared secret hash the length of
     * the shared secret as 32-bit big-endian number followed by the
     * shared secret itself. The length of a shared secret is
     * currently fixed to RS_LENGTH. If a shared
     * secret is not used _only_ its length is hashed as a zero
     * length. NOTE: if implementing auxSecret and/or pbxSecret -> check
     * this length stuff again.
     */
    uint32_t secretHashLen = RS_LENGTH;
    secretHashLen = zrtpHtonl(secretHashLen); // prepare 32-bit big-endian number

    for (int32_t i = 0; i < 3; i++) {
        if (setD[i] != nullptr) {
            // a matching secret, set length, then secret
            sLen[i] = secretHashLen;
            data.push_back(reinterpret_cast<uint8_t const *>(&sLen[i]));
            length.push_back(sizeof(uint32_t));
            data.push_back(setD[i]);
            length.push_back(i != 1 ? RS_LENGTH : auxSecretLength);
        } else {
            // no matching secret, set length 0, skip secret
            sLen[i] = 0;
            data.push_back(reinterpret_cast<uint8_t const *>(&sLen[i]));
            length.push_back(sizeof(uint32_t));
        }
    }
    hashListFunction(data, length, s0.data());

    DHss.clear();

    computeSRTPKeys();
    s0.clear();
}

/*
 * The DH packet for this function is DHPart2 and contains the Initiator's
 * retained secret ids. Compare them with the expected secret ids (refer
 * to chapter 5.3.1 in the specification).
 */
void ZRtp::generateKeysResponder(ZrtpPacketDHPart const *dhPart, ZIDRecord &zidRecord) {
    const uint8_t *setD[3];
    uint32_t rsFound = 0;

    setD[0] = setD[1] = setD[2] = nullptr;

    detailInfo.secretsMatchedDH = 0;
    if (rs1IDi.equals(dhPart->getRs1Id(), HMAC_SIZE) || rs1IDi.equals(dhPart->getRs2Id(), HMAC_SIZE))
        detailInfo.secretsMatchedDH |= Rs1;
    if (rs2IDi.equals(dhPart->getRs1Id(), HMAC_SIZE) || rs2IDi.equals(dhPart->getRs2Id(), HMAC_SIZE))
        detailInfo.secretsMatchedDH |= Rs2;

    /*
     * Select the real secrets into setD
     */
    // Check which RS we shall use for first place (s1)
    detailInfo.secretsMatched = 0;
    if (rs1IDi.equals(dhPart->getRs1Id(), HMAC_SIZE)) {
        setD[0] = zidRecord.getRs1();
        rsFound = 0x1;
        detailInfo.secretsMatched = Rs1;
    } else if (rs1IDi.equals(dhPart->getRs2Id(), HMAC_SIZE)) {
        setD[0] = zidRecord.getRs1();
        rsFound = 0x2;
        detailInfo.secretsMatched = Rs1;
    } else if (rs2IDi.equals(dhPart->getRs1Id(), HMAC_SIZE)) {
        setD[0] = zidRecord.getRs2();
        rsFound |= 0x4U;
        detailInfo.secretsMatched = Rs2;
    } else if (rs2IDi.equals(dhPart->getRs2Id(), HMAC_SIZE)) {
        setD[0] = zidRecord.getRs2();
        rsFound |= 0x8U;
        detailInfo.secretsMatched = Rs2;
    }

    if (auxSecretIDi.equals(dhPart->getAuxSecretId(), 8)) {
        setD[1] = auxSecret.get();
        detailInfo.secretsMatched |= Aux;
        detailInfo.secretsMatchedDH |= Aux;
    }
    // If we have an auxSecret but no match from peer - report this.
    if (auxSecret && (detailInfo.secretsMatched & Aux) == 0) {
        sendInfo(Warning, WarningNoExpectedAuxMatch);
    }

#ifdef ZRTP_SAS_RELAY_SUPPORT
    if (memcmp(pbxSecretIDi, dhPart->getPbxSecretId(), 8) == 0) {
        DEBUGOUT((fprintf(stdout, "%c: Match for PBX secret found\n", ownZid[0])));
        setD[2] = zidRecord->getMiTMData();
        detailInfo.secretsMatched |= Pbx;
        detailInfo.secretsMatchedDH |= Pbx;
        peerIsEnrolled = true;
    }
#endif
    // Check if some retained secrets found
    if (rsFound == 0) {
        // no RS matches found
        if (rs1Valid || rs2Valid) {
            // but valid RS records in cache
            sendInfo(Warning, WarningNoExpectedRSMatch);
            zidRecord.resetSasVerified();
            saveZidRecord = false; // Don't save RS until user verified/confirmed SAS
        } else {
            // No valid RS record in cache
            sendInfo(Warning, WarningNoRSMatch);
        }
    } else {
        // at least one RS matches
        sendInfo(Info, InfoRSMatchFound);
    }

    /*
     * ready to generate s0 here.
     * The formula to compute S0 (Refer to ZRTP specification 5.4.4):
     *
      s0 = hash( counter | DHResult | "ZRTP-HMAC-KDF" | ZIDi | ZIDr | \
      total_hash | len(s1) | s1 | len(s2) | s2 | len(s3) | s3)
     *
     * Note: in this function we are Responder, thus ZIDi is the peer's zid
     * (peerZid), ZIDr is our zid.
     */

    /*
     * These vectors hold the pointers and lengths of the data that must be
     * hashed to create S0.
     */
    std::vector<uint8_t const *> data;
    std::vector<uint64_t> length;

    // We need a number of length data items, so define them here
    uint32_t sLen[3];

    // The very first element is a fixed counter, big endian
    uint32_t counter = 1;
    counter = zrtpHtonl(counter);
    data.push_back(reinterpret_cast<uint8_t const *>(&counter));
    length.push_back(sizeof(uint32_t));

    // Next is the DH result itself
    data.push_back(DHss.data());
    length.push_back(DHss.size());

    // Next the fixed string "ZRTP-HMAC-KDF"
    data.push_back(reinterpret_cast<uint8_t const *>(KDFString));
    length.push_back(static_cast<uint32_t>(strlen(KDFString)));

    // Next is Initiator's id (ZIDi), in this case as Responder
    // it is peerZid
    data.push_back(peerZid.data());
    length.push_back(ZID_SIZE);

    // Next is Responder's id (ZIDr), in this case our own zid
    data.push_back(ownZid.data());
    length.push_back(ZID_SIZE);

    // Next ist total hash (messageHash) itself
    data.push_back(messageHash.data());
    length.push_back(messageHash.size());

    /*
     * For each matching shared secret hash the length of
     * the shared secret as 32-bit big-endian number followed by the
     * shared secret itself. The length of a shared secret is
     * currently fixed to SHA256_DIGEST_LENGTH. If a shared
     * secret is not used _only_ its length is hashed as a zero
     * length. NOTE: if implementing auxSecret and/or pbxSecret -> check
     * this length stuff again.
     */
    uint32_t secretHashLen = RS_LENGTH;
    secretHashLen = zrtpHtonl(secretHashLen); // prepare 32-bit big-endian number

    for (int32_t i = 0; i < 3; i++) {
        if (setD[i] != nullptr) {
            // a matching secret, set length, then secret
            sLen[i] = secretHashLen;
            data.push_back(reinterpret_cast<uint8_t const *>(&sLen[i]));
            length.push_back(sizeof(uint32_t));
            data.push_back(setD[i]);
            length.push_back(i != 1 ? RS_LENGTH : auxSecretLength);
        } else {
            // no matching secret, set length 0, skip secret
            sLen[i] = 0;
            data.push_back(reinterpret_cast<uint8_t const *>(&sLen[i]));
            length.push_back(sizeof(uint32_t));
        }
    }
    hashListFunction(data, length, s0.data());

    DHss.clear();

    computeSRTPKeys();
    s0.clear();
}


void ZRtp::KDF(uint8_t const *key, size_t const keyLength, char const *label, size_t const labelLength,
               uint8_t const *context, size_t const contextLength, size_t const L, zrtp::NegotiatedArray &output) const {
    std::vector<uint8_t const *> data(5);
    std::vector<uint64_t> length(5);

    // The very first element is a fixed counter, big endian
    uint32_t counter = 1;
    counter = zrtpHtonl(counter);
    data.push_back(reinterpret_cast<uint8_t *>(&counter));
    length.push_back(sizeof(uint32_t));

    // The next element is the label, null terminated, labelLength includes null byte.
    data.push_back(reinterpret_cast<uint8_t const *>(label));
    length.push_back(labelLength);

    // Next is the KDF context
    data.push_back(context);
    length.push_back(contextLength);

    // The last element is the HMAC length in bits, big endian
    uint32_t len = zrtpHtonl(static_cast<uint32_t>(L));
    data.push_back(reinterpret_cast<uint8_t *>(&len));
    length.push_back(sizeof(uint32_t));

    // Use negotiated hash.
    hmacListFunction(key, keyLength, data, length, output);
}

// Compute the Multi Stream mode s0
void ZRtp::generateKeysMultiStream() {
    // allocate the required capacity
    secUtilities::SecureArrayFlex kdfContext(peerZid.size() + ownZid.size() + hashLength);
    size_t const kdfSize = kdfContext.capacity();

    if (myRole == Responder) {
        kdfContext.assign(peerZid).append(ownZid);
    } else {
        kdfContext.assign(ownZid).append(peerZid);
    }
    kdfContext.append(messageHash);

    KDF(zrtpSession.data(), hashLength, zrtpMsk, strlen(zrtpMsk) + 1, kdfContext.data(), kdfSize, hashLength * 8, s0);

    computeSRTPKeys();
}

void ZRtp::computePBXSecret() {
#ifdef ZRTP_SAS_RELAY_SUPPORT
    // Construct the KDF context as per ZRTP specification chap 7.3.1:
    // ZIDi || ZIDr
    uint8_t KDFcontext[sizeof(peerZid)+sizeof(ownZid)];
    int32_t kdfSize = sizeof(peerZid)+sizeof(ownZid);

    if (myRole == Responder) {
        memcpy(KDFcontext, peerZid, sizeof(peerZid));
        memcpy(KDFcontext+sizeof(peerZid), ownZid, sizeof(ownZid));
    }
    else {
        memcpy(KDFcontext, ownZid, sizeof(ownZid));
        memcpy(KDFcontext+sizeof(ownZid), peerZid, sizeof(peerZid));
    }

    KDF(zrtpSession, hashLength, (unsigned char*)zrtpTrustedMitm, strlen(zrtpTrustedMitm)+1, KDFcontext,
        kdfSize, SHA256_DIGEST_LENGTH * 8, pbxSecretTmpBuffer);

    pbxSecretTmp = pbxSecretTmpBuffer;  // set pointer to buffer, signal PBX secret was computed
#endif
}

void ZRtp::computeSRTPKeys() {
    // allocate the required capacity
    secUtilities::SecureArrayFlex kdfContext(peerZid.size() + ownZid.size() + hashLength);
    size_t const kdfSize = kdfContext.capacity();

    size_t const keyLen = cipher->getKeylen() * 8UL;

    if (myRole == Responder) {
        kdfContext.assign(peerZid).append(ownZid);
    } else {
        kdfContext.assign(ownZid).append(peerZid);
    }
    kdfContext.append(messageHash);

    // Initiator key and salt
    KDF(s0.data(), hashLength, iniMasterKey, strlen(iniMasterKey) + 1, kdfContext.data(), kdfSize, keyLen, srtpKeyI);
    KDF(s0.data(), hashLength, iniMasterSalt, strlen(iniMasterSalt) + 1, kdfContext.data(), kdfSize, 112, srtpSaltI);

    // Responder key and salt
    KDF(s0.data(), hashLength, respMasterKey, strlen(respMasterKey) + 1, kdfContext.data(), kdfSize, keyLen, srtpKeyR);
    KDF(s0.data(), hashLength, respMasterSalt, strlen(respMasterSalt) + 1, kdfContext.data(), kdfSize, 112, srtpSaltR);

    KDF(s0.data(), hashLength, iniHmacKey, strlen(iniHmacKey) + 1, kdfContext.data(), kdfSize, hashLength * 8,
        hmacKeyI);
    KDF(s0.data(), hashLength, respHmacKey, strlen(respHmacKey) + 1, kdfContext.data(), kdfSize, hashLength * 8,
        hmacKeyR);

    // The keys for Confirm messages
    KDF(s0.data(), hashLength, iniZrtpKey, strlen(iniZrtpKey) + 1, kdfContext.data(), kdfSize, keyLen, zrtpKeyI);
    KDF(s0.data(), hashLength, respZrtpKey, strlen(respZrtpKey) + 1, kdfContext.data(), kdfSize, keyLen, zrtpKeyR);

    detailInfo.pubKey = detailInfo.sasType = nullptr;
    if (!multiStream) {
        // Compute the new Retained Secret
        KDF(s0.data(), hashLength, retainedSec, strlen(retainedSec) + 1, kdfContext.data(), kdfSize,
            SHA256_DIGEST_LENGTH * 8, newRs1);

        // Compute the ZRTP Session Key
        KDF(s0.data(), hashLength, zrtpSessionKey, strlen(zrtpSessionKey) + 1, kdfContext.data(), kdfSize,
            hashLength * 8, zrtpSession);

        // Compute the exported Key
        KDF(s0.data(), hashLength, zrtpExportedKey, strlen(zrtpExportedKey) + 1, kdfContext.data(), kdfSize,
            hashLength * 8, zrtpExport);
        // perform generation according to chapter 5.5 and 8.
        // we don't need a special sasValue filed. sasValue is the first
        // (leftmost) 32 bits (4 bytes) of sasHash
        uint8_t sasBytes[4];
        KDF(s0.data(), hashLength, sasString, strlen(sasString) + 1, kdfContext.data(), kdfSize,
            SHA256_DIGEST_LENGTH * 8, sasHash);

        // according to chapter 8, only the leftmost 20 bits of sasValue (aka
        // sasHash) are used to create the character SAS string of type SAS
        // base 32 (5 bits per character)
        sasBytes[0] = sasHash[0];
        sasBytes[1] = sasHash[1];
        sasBytes[2] = sasHash[2] & static_cast<uint8_t>(0xf0);
        sasBytes[3] = 0;
        if (strncmp(b32, sasType->getName(), 4) == 0) {
            SAS = Base32(sasBytes, 20).getEncoded();
        } else if (strncmp(b32e, sasType->getName(), 4) == 0) {
            SAS = *EmojiBase32::u32StringToUtf8(EmojiBase32(sasBytes, 20).getEncoded());
        } else if (strncmp(b10d, sasType->getName(), 4) == 0) {
            SAS = sasDigit(sasHash.data());
            if (SAS.empty()) {
                // report fatal error
            }
        } else {
            SAS.assign(sas256WordsEven[sasBytes[0]]).append(":").append(sas256WordsOdd[sasBytes[1]]);
        }

        if (signSasSeen) {
            if (auto const ucb = callback.lock()) {
                ucb->signSAS(sasHash.data());
            }
        }

        detailInfo.pubKey = pubKey->getReadable();
        detailInfo.sasType = sasType->getReadable();
    }
    // set algorithm names into detailInfo structure
    detailInfo.authLength = authLength->getReadable();
    detailInfo.cipher = cipher->getReadable();
    detailInfo.hash = hash->getReadable();
}

bool ZRtp::srtpSecretsReady(EnableSecurity const part) {
    SrtpSecret_t sec;

    sec.symEncAlgorithm = cipher->getAlgoId();

    sec.keyInitiator = srtpKeyI.data();
    sec.initKeyLen = cipher->getKeylen() * 8;
    sec.saltInitiator = srtpSaltI.data();
    sec.initSaltLen = 112;

    sec.keyResponder = srtpKeyR.data();
    sec.respKeyLen = cipher->getKeylen() * 8;
    sec.saltResponder = srtpSaltR.data();
    sec.respSaltLen = 112;

    sec.authAlgorithm = authLength->getAlgoId();
    sec.srtpAuthTagLen = authLength->getKeylen();

    sec.sas = SAS;
    sec.role = myRole;

    bool rc = false;
    if (auto const ucb = callback.lock()) {
        // if no callback available: returning false leads to a ZRTP error and abort
        rc = ucb->srtpSecretsReady(&sec, part);
    }

    if (!rc) {
        return false;
    }
    // The call state engine calls 'srtpSecretsReady' with part 'ForSender'
    // always after 'ForReceiver'. Because of this fixed sequence forward
    // cipher info and SAS only if this call is 'ForSender'.

    // The state machine enters secure state if this function returns
    // and part is 'ForSender'. The state machine sends Info with
    // substate InfoSecureStateOn once its state is 'Secure'
    if (part == ForSender) {
        string cs(cipher->getReadable());
        if (!multiStream) {
            cs.append("/").append(pubKey->getName());
            if (mitmSeen)
                cs.append("/EndAtMitM");
            if (auto const ucb = callback.lock()) {
                ucb->srtpSecretsOn(cs, SAS, zidRec->isSasVerified());
            }
        } else {
            if (mitmSeen)
                cs.append("/EndAtMitM");
            if (auto const ucb = callback.lock()) {
                string const cs1;
                ucb->srtpSecretsOn(cs, cs1, true);
            }
        }
    }
    return true;
}

void ZRtp::setNegotiatedHash(AlgorithmEnum const *hashNegotiated) {
    switch (zrtpHashes.getOrdinal(*hashNegotiated)) {
        case 0:
            hashLength = SHA256_DIGEST_LENGTH;
            hashListFunction = sha256;
            // static_cast<void (*)(const vector<const uint8_t*>&, const vector<uint64_t>&, uint8_t *)>(sha256);;

            hmacFunction = static_cast<void (*)(const uint8_t *, uint64_t, const uint8_t *, uint64_t,
                                                zrtp::RetainedSecArray &)>(hmac_sha256);
            hmacListFunction = static_cast<void (*)(const uint8_t *, uint64_t, const vector<const uint8_t *> &,
                                                    const vector<uint64_t> &, zrtp::RetainedSecArray &)>(hmacSha256);

            createHashCtx = createSha256Context;
            closeHashCtx = closeSha256Context;
            hashCtxFunction = sha256Ctx;
            break;

        case 1:
            hashLength = SHA384_DIGEST_LENGTH;
            hashListFunction = sha384;
            // static_cast<void (*) (const vector<const uint8_t*>&, const vector<uint64_t>&, uint8_t *)>(sha384);

            hmacFunction = hmac_sha384;
            hmacListFunction = static_cast<void (*)(const uint8_t *, uint64_t, const vector<const uint8_t *> &,
                                                    const vector<uint64_t> &, zrtp::RetainedSecArray &)>(hmacSha384);

            createHashCtx = createSha384Context;
            closeHashCtx = closeSha384Context;
            hashCtxFunction = sha384Ctx;
            break;

        case 2:
            hashLength = SKEIN256_DIGEST_LENGTH;
            hashListFunction = static_cast<void (
                *)(const vector<const uint8_t *> &, const vector<uint64_t> &, uint8_t *)>(
                skein256);

            hmacFunction = macSkein256;
            hmacListFunction = static_cast<void (*)(const uint8_t *, uint64_t, const vector<const uint8_t *> &,
                                                    const vector<uint64_t> &, zrtp::RetainedSecArray &)>(macSkein256);

            createHashCtx = createSkein256Context;
            closeHashCtx = closeSkein256Context;
            hashCtxFunction = skein256Ctx;
            break;

        case 3:
            hashLength = SKEIN384_DIGEST_LENGTH;
            hashListFunction = static_cast<void (
                *)(const vector<const uint8_t *> &, const vector<uint64_t> &, uint8_t *)>(
                skein384);

            hmacFunction = macSkein384;
            hmacListFunction = static_cast<void (*)(const uint8_t *, uint64_t, const vector<const uint8_t *> &,
                                                    const vector<uint64_t> &, zrtp::RetainedSecArray &)>(macSkein384);

            createHashCtx = createSkein384Context;
            closeHashCtx = closeSkein384Context;
            hashCtxFunction = skein384Ctx;
            break;

        default:
            break;
    }
}


void ZRtp::srtpSecretsOff(EnableSecurity const part) const {
    if (auto const ucb = callback.lock()) {
        ucb->srtpSecretsOff(part);
    }
}

void ZRtp::SASVerified() {
    if (paranoidMode)
        return;

    zidRec->setSasVerified();
    saveZidRecord = true;
    getZidCache()->saveRecord(*zidRec);
}

void ZRtp::resetSASVerified() const {
    zidRec->resetSasVerified();
    getZidCache()->saveRecord(*zidRec);
}

void ZRtp::setRs2Valid() const {
    if (zidRec != nullptr) {
        zidRec->setRs2Valid();
        if (saveZidRecord) {
            getZidCache()->saveRecord(*zidRec);
        }
    }
}

void ZRtp::sendInfo(MessageSeverity const severity, int32_t const subCode) {
    // We've reached the secure state: overwrite the SRTP master key and master salt.
    if (severity == Info && subCode == InfoSecureStateOn) {
        srtpKeyI.clear();
        srtpSaltI.clear();
        srtpKeyR.clear();
        srtpSaltR.clear();
    }
    if (auto const ucb = callback.lock()) {
        ucb->sendInfo(severity, subCode);
    }
}


void ZRtp::zrtpNegotiationFailed(MessageSeverity const severity, int32_t const subCode) const {
    if (auto const ucb = callback.lock()) {
        ucb->zrtpNegotiationFailed(severity, subCode);
    }
}

void ZRtp::zrtpNotSuppOther() const {
    if (auto const ucb = callback.lock()) {
        ucb->zrtpNotSuppOther();
    }
}

int32_t ZRtp::sendPacketZRTP(ZrtpPacketBase *packet) {
    if (packet == nullptr) {
        return 0;
    }
    if (isNpAlgorithmActive) {
        return sendAsZrtpFrames(packet);
    }
    if (auto const ucb = callback.lock()) {
        return ucb->sendDataZRTP(packet->getHeaderBase(), packet->getLength() * ZRTP_WORD_SIZE + CRC_SIZE);
    }
    return 0;
}

int32_t ZRtp::activateTimer(int32_t const tm) const {
    if (auto const ucb = callback.lock()) {
        return ucb->activateTimer(tm);
    }
    return 0;
}

int32_t ZRtp::cancelTimer() const {
    if (auto const ucb = callback.lock()) {
        return ucb->cancelTimer();
    }
    return 0;
}

void ZRtp::setAuxSecret(uint8_t const *data, uint32_t const length) {
    if (length > 0) {
        auxSecret = make_unique<uint8_t[]>(length);
        auxSecretLength = length;
        memcpy(auxSecret.get(), data, length);
    }
}

void ZRtp::setClientId(string const &id, HelloPacketVersion_t *hpv) const {
    unsigned char tmp[CLIENT_ID_SIZE + 1] = {' '};
    memcpy(tmp, id.c_str(), id.size() > CLIENT_ID_SIZE ? CLIENT_ID_SIZE : id.size());
    tmp[CLIENT_ID_SIZE] = 0;

    hpv->packet->setClientId(tmp);

    uint32_t const len = hpv->packet->getLength() * ZRTP_WORD_SIZE;

    // Hello packets are ready now, compute its HMAC
    // (excluding the HMAC field (2*ZTP_WORD_SIZE)) and store in Hello
    // use the implicit hash function
    zrtp::ImplicitDigest hmac;
    hmacFunctionImpl(H2, HASH_IMAGE_SIZE, hpv->packet->getHeaderBase(), len - 2 * ZRTP_WORD_SIZE, hmac);
    hpv->packet->setHMAC(hmac);

    // calculate hash over the final Hello packet, refer to chap 9.1 how to
    // use this hash in SIP/SDP.
    hashFunctionImpl(hpv->packet->getHeaderBase(), len, hpv->helloHash);
}

void ZRtp::storeMsgTemp(ZrtpPacketBase const *pkt) {
    uint32_t length = pkt->getLength() * ZRTP_WORD_SIZE;
    length = length > sizeof(tempMsgBuffer) ? sizeof(tempMsgBuffer) : length;
    memset(tempMsgBuffer, 0, sizeof(tempMsgBuffer));
    memcpy(tempMsgBuffer, pkt->getHeaderBase(), length);
    lengthOfMsgData = length;
}

bool ZRtp::checkMsgHmac(uint8_t const *key) const {
    zrtp::ImplicitDigest hmac;
    uint32_t const len = lengthOfMsgData - HMAC_SIZE; // compute HMAC, but exclude the stored HMAC :-)

    // Use the implicit hash function
    hmacFunctionImpl(key, HASH_IMAGE_SIZE, tempMsgBuffer, len, hmac);
    return hmac.equals(tempMsgBuffer + len, HMAC_SIZE);
}

string ZRtp::getHelloHash(int32_t const index) const {
    ostringstream stm;

    if (index < 0 || index >= MAX_ZRTP_VERSIONS)
        return {};

    uint8_t const *hp = helloPackets[index].helloHash;

    char version[5] = {};
    strncpy(version, reinterpret_cast<char const *>(helloPackets[index].packet->getVersion()), ZRTP_WORD_SIZE);

    stm << version;
    stm << " ";
    stm.fill('0');
    stm << hex;
    for (int i = 0; i < hashLengthImpl; i++) {
        stm.width(2);
        stm << static_cast<uint32_t>(*hp++);
    }
    return stm.str();
}

string ZRtp::getPeerHelloHash() const {
    ostringstream stm;

    if (peerHelloVersion[0] == 0)
        return {};

    uint8_t const *hp = peerHelloHash;

    stm << peerHelloVersion;
    stm << " ";
    stm.fill('0');
    stm << hex;
    for (int i = 0; i < hashLengthImpl; i++) {
        stm.width(2);
        stm << static_cast<uint32_t>(*hp++);
    }
    return stm.str();
}

string ZRtp::getMultiStrParams(ZRtp **zrtpMaster) {
    // the string will hold binary data - it's opaque to the application
    string str;

    if (inState(SecureState) && !multiStream) {
        char tmp[MAX_DIGEST_LENGTH + 1 + 1 + 1]; // hash length + cipher + authLength + hash
        // construct array that holds zrtpSession, cipher type, auth-length, and hash type
        tmp[0] = static_cast<char>(zrtpHashes.getOrdinal(*hash));
        tmp[1] = static_cast<char>(zrtpAuthLengths.getOrdinal(*authLength));
        tmp[2] = static_cast<char>(zrtpSymCiphers.getOrdinal(*cipher));
        memcpy(tmp + 3, zrtpSession.data(), hashLength);
        str.assign(tmp, hashLength + 1 + 1 + 1); // set chars (bytes) to the string

        if (zrtpMaster != nullptr)
            *zrtpMaster = this;
    }
    return str;
}

void ZRtp::setMultiStrParams(string const &parameters, ZRtp *zrtpMaster) {
    uint8_t tmp[MAX_DIGEST_LENGTH + 1 + 1 + 1]; // max. hash length + cipher + authLength + hash

    // First get negotiated hash from parameters, set algorithms and length
    auto i = parameters.at(0) & 0x7f;
    hash = &zrtpHashes.getByOrdinal(i);
    setNegotiatedHash(hash); // sets hash length

    // use string.copy(buffer, num, start=0) to retrieve chars (bytes) from the string
    parameters.copy(reinterpret_cast<char *>(tmp), hashLength + 1 + 1 + 1, 0);

    i = tmp[1] & 0xff;
    authLength = &zrtpAuthLengths.getByOrdinal(i);
    i = tmp[2] & 0xff;
    cipher = &zrtpSymCiphers.getByOrdinal(i);
    zrtpSession.assign(tmp + 3, hashLength);

    // after setting zrtpSession, cipher, and auth-length set multi-stream to true
    multiStream = true;
    stateEngine->setMultiStream(true);
    if (zrtpMaster != nullptr)
        masterStream = zrtpMaster;
}

bool ZRtp::isMultiStream() const {
    return multiStream;
}

bool ZRtp::isMultiStreamAvailable() const {
    return multiStreamAvailable;
}

void ZRtp::acceptEnrollment(bool accepted) {
#ifdef ZRTP_SAS_RELAY_SUPPORT
    if (!accepted) {
        zidRec->resetMITMKeyAvailable();
        callback->zrtpInformEnrollment(EnrollmentCanceled);
        getZidCacheInstance()->saveRecord(zidRec);
        return;
    }
    if (pbxSecretTmp != nullptr) {
        zidRec->setMiTMData(pbxSecretTmp);
        getZidCacheInstance()->saveRecord(zidRec);
        callback->zrtpInformEnrollment(EnrollmentOk);
    }
    else {
        callback->zrtpInformEnrollment(EnrollmentFailed);
    }
#else
    (void) accepted;
#endif
}

bool ZRtp::setSignatureData(uint8_t const *data, int32_t const length) {
    if (length % 4 != 0)
        return false;

    ZrtpPacketConfirm *cfrm = myRole == Responder ? &zrtpConfirm1 : &zrtpConfirm2;
    cfrm->setSignatureLength(length / 4);
    return cfrm->setSignatureData(data, length);
}

void ZRtp::conf2AckSecure() const {
    Event ev;

    ev.type = ZrtpPacket;
    ev.packet = zrtpConf2Ack.getHeaderBase();
    ev.length = sizeof(Conf2AckPacket_t) + 12; // 12 is fixed ZRTP (RTP) header size

    if (stateEngine) {
        stateEngine->processEvent(&ev);
    }
}

int32_t ZRtp::compareCommit(ZrtpPacketCommit const *commit) const {
    // enhance to compare, according to rules defined in chapter 4.2,
    // but we don't support Pre-shared.
    uint32_t len = 0;
    len = !multiStream ? HVI_SIZE : 4 * ZRTP_WORD_SIZE;
    return memcmp(hvi, commit->getHvi(), len);
}

bool ZRtp::isEnrollmentMode() const {
    return enrollmentMode;
}

void ZRtp::setEnrollmentMode(bool enrollment) {
#ifdef ZRTP_SAS_RELAY_SUPPORT
    enrollmentMode = enrollment;
#else
    (void) enrollment;
    enrollmentMode = false;
#endif
}

bool ZRtp::isPeerEnrolled() const {
    return peerIsEnrolled;
}

bool ZRtp::sendSASRelayPacket(const uint8_t *sh, const string &render) {
#ifdef ZRTP_SAS_RELAY_SUPPORT
    uint8_t confMac[MAX_DIGEST_LENGTH];
    uint32_t macLen;
    uint8_t* hkey, *ekey;

    // If we are the Responder, then the PBX used its Initiator keys
    if (myRole == Responder) {
        hkey = hmacKeyR;
        ekey = zrtpKeyR;
        // check signature length in zrtpConfirm1 and if not, zero copy Signature data
    }
    else {
        hkey = hmacKeyI;
        ekey = zrtpKeyI;
        //  check signature length in zrtpConfirm2 and if not, zero copy Signature data
    }
    // Prepare IV data that we will use during confirm packet encryption.
    randomZRTP(randomIV, sizeof(randomIV));
    zrtpSasRelay.setIv(randomIV);
    zrtpSasRelay.setTrustedSas(sh);
    zrtpSasRelay.setSasAlgo((uint8_t*)render.c_str());

    uint32_t hmlen = (zrtpSasRelay.getLength() - (uint)9) * ZRTP_WORD_SIZE;
    cipher->getEncrypt()(ekey, cipher->getKeylen(), randomIV, (uint8_t*)zrtpSasRelay.getFiller(), hmlen);

    // Use negotiated HMAC (hash)
    hmacFunction(hkey, hashLength, (unsigned char*)zrtpSasRelay.getFiller(), hmlen, confMac, &macLen);

    zrtpSasRelay.setHmac(confMac);

    stateEngine->sendSASRelay(&zrtpSasRelay);
    return true;
#else
    (void) sh;
    (void) render;
    return false;
#endif // ZRTP_SAS_RELAY_SUPPORT
}

bool ZRtp::checkAndSetNonce(uint8_t const *nonce) const {
    // This is for backward compatibility if applications use the old
    // get- and setMultiStrParams functions
    if (masterStream == nullptr)
        return true;

    for (const auto &usedNonce: masterStream->peerNonces) {
        if (memcmp(usedNonce.data(), nonce, ZRTP_WORD_SIZE * 4) == 0) {
            return false;
        }
    }
    // the string holds the binary nonce
    string str;
    str.assign(reinterpret_cast<char const *>(nonce), ZRTP_WORD_SIZE * 4);
    masterStream->peerNonces.push_back(str);
    return true;
}

void ZRtp::saveOtherHelloData(ZrtpPacketHello const &helloPacket) {
    if (otherHelloPacket.empty()) {
        otherHelloPacket.assign(helloPacket.getHeaderBase(), helloPacket.getLength() * ZRTP_WORD_SIZE);
    }
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
