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

#ifndef _ZRTP_H_
#define _ZRTP_H_

#include <cstdlib>

#include <libzrtpcpp/ZrtpPacketHello.h>
#include <libzrtpcpp/ZrtpPacketHelloAck.h>
#include <libzrtpcpp/ZrtpPacketCommit.h>
#include <libzrtpcpp/ZrtpPacketDHPart.h>
#include <libzrtpcpp/ZrtpPacketConfirm.h>
#include <libzrtpcpp/ZrtpPacketConf2Ack.h>
#include <libzrtpcpp/ZrtpPacketGoClear.h>
#include <libzrtpcpp/ZrtpPacketClearAck.h>
#include <libzrtpcpp/ZrtpCallback.h>
#include <libzrtpcpp/ZIDRecord.h>

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

class ZrtpStateClass;
class ZrtpDH;

/**
 * The main ZRTP class.
 *
 * This contains the whole ZRTP implementation. It handles the ZRTP
 * HMAC, DH, and other data management. The user of this class needs
 * to know only a few methods and needs to provide only a few external
 * functions to connect to a Timer mechanism and to send data via RTP
 * and SRTP.
 *
 * <p/>
 *
 * The main entry into the ZRTP class is the <code>
 * processExtensionHeader() </code> method.
 *
 * <p/>
 *
 * This class does not directly handle the protocol states, timers,
 * and packet resend. The protocol state engine is responsible for
 * these actions.
 *
 * @see ZrtpCallback
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class ZRtp {

    public:

        /**
         * Constructor intializes all relevant data but does not start the
         * engine.
         */
	ZRtp(uint8_t* myZid, ZrtpCallback* cb);

        /**
	 * Destructor cleans up.
         */
	~ZRtp();

        /**
	 * Kick off the ZRTP protocol engine.
	 *
	 * This method calls the ZrtpStateClass#evInitial() state of the state
	 * engine. After this call we are able to process ZRTP packets
	 * from our peer and to process them.
         */
	void startZrtpEngine();

        /**
	 * Stop ZRTP security.
	 *
         */
	void stopZrtp();

        /**
	 * Process RTP extension header.
	 *
	 * This method expects to get a pointer to the extension header of
	 * a RTP packet. The method checks if this is really a ZRTP
	 * packet. If this check fails the method returns 0 (false) in
	 * case this is not a ZRTP packet. We return a 1 if we processed
	 * the ZRTP extension header and the caller may process RTP data
	 * after the extension header as usual.  The method return -1 the
	 * call shall dismiss the packet and shall not forward it to
	 * further RTP processing.
	 *
	 * @param extHeader
	 *    A pointer to the first byte of the extension header. Refer to
	 *    RFC3550.
         * @param content
         *    Pointer to the content of the received packet. Required for
         *    Confirm handling.
	 * @return
	 *    Code indicating further packet handling, see description above.
         */
	int32_t processExtensionHeader(uint8_t *extHeader, uint8_t* content);

        /**
	 * Process a timeout event.
	 *
	 * We got a timeout from the timeout provider. Forward it to the
	 * protocol state engine.
	 *
         */
	int32_t processTimeout();

        /**
         * Check for and handle GoClear ZRTP packet header.
         *
         * This method checks if this is a GoClear packet. If not, just return
         * false. Otherwise handle it according to the specification.
         *
         * @param extHeader
         *    A pointer to the first byte of the extension header. Refer to
         *    RFC3550.
         * @return
         *    False if not a GoClear, true otherwise.
         */
        bool handleGoClear(uint8_t *extHeader);

        /**
         * Set the sigs secret.
         *
         * USe this method to set the sigs secret data. Refer to ZRTP
         * specification, chapter 3.2.1
         *
         * @param data
         *     Points to the sigs secret data. The data must have a length
         *     of 32 bytes (length of SHA256 hash)
         */
        void setSigsSecret(uint8_t* data);

       /**
        * Set the srtps secret.
        *
        * USe this method to set the srtps secret data. Refer to ZRTP
        * specification, chapter 3.2.1
        *
        * @param data
        *     Points to the srtps secret data. The data must have a length
        *      of 32 bytes (length of SHA256 hash)
        */
        void setSrtpsSecret(uint8_t* data);

       /**
        * Set the other secret.
        *
        * USe this method to set the other secret data. Refer to ZRTP
        * specification, chapter 3.2.1
        *
        * @param data
        *     Points to the other secret data.
        * @param length
        *     The length in bytes of the data.
        */
        void setOtherSecret(uint8_t* data, int32_t length);

       /**
        * Set the client ID for ZRTP Hello message.
        *
        * The GNU ccRTP client may set its id to identify itself in the
        * ZRTP HELLO message. The maximum length is 15 characters. Shorter
        * id string are allowed, the will be filled with blanks. A Longer id
        * is truncated to 15 characters.
        *
        * @param id
        *     The client's id
        */
       void setClientId(std::string id);

       /**
        * Check current state of the ZRTP state engine
        *
        * @param state
        *    The state to check.
        * @return
        *    Return true id ZRTP engine is in the given state, false otherwise.
        */
       int32_t checkState(int32_t state);

       /**
        * Set SAS as verified.
        *
        * Call this method if the user confirmed (verfied) the SAS. ZRTP
        * remembers this together with the retained secrets data.
        */
       void SASVerified();

 private:
     friend class ZrtpStateClass;

    /**
     * The state engine takes care of protocol processing.
     */
    ZrtpStateClass* stateEngine;

    /**
     * This is my ZID that I send to the peer.
     */
    uint8_t zid[12];

    /**
     * The peer's ZID
     */
    uint8_t peerZid[12];

    /**
     * The callback class provides me with the interface to send
     * data and to deal with timer management of the hosting system.
     */
    ZrtpCallback* callback;

    /**
     * My active Diffie-Helman context
     */
    ZrtpDH* dhContext;

    /**
     * The computed DH shared secret
     */
    uint8_t* DHss;

    /**
     * My computed public key
     */
    uint8_t* pubKeyBytes;
    /**
     * Length off public key
     */
    int32_t pubKeyLen;
    /**
     * My Role in the game
     */
    Role myRole;

    /**
     * The SAS value
     */
    std::string SAS;

    /**
     * The variables for the retained shared secrets
     */
    uint8_t rs1IDr[SHA256_DIGEST_LENGTH];
    uint8_t rs2IDr[SHA256_DIGEST_LENGTH];
    uint8_t sigsIDr[SHA256_DIGEST_LENGTH];
    uint8_t srtpsIDr[SHA256_DIGEST_LENGTH];
    uint8_t otherSecretIDr[SHA256_DIGEST_LENGTH];

    uint8_t rs1IDi[SHA256_DIGEST_LENGTH];
    uint8_t rs2IDi[SHA256_DIGEST_LENGTH];
    uint8_t sigsIDi[SHA256_DIGEST_LENGTH];
    uint8_t srtpsIDi[SHA256_DIGEST_LENGTH];
    uint8_t otherSecretIDi[SHA256_DIGEST_LENGTH];
    /**
     * My hvi
     */
    uint8_t hvi[SHA256_DIGEST_LENGTH];

    /**
     * The peer's hvi
     */
    uint8_t peerHvi[SHA256_DIGEST_LENGTH];

    /**
     * Commited Hash, Cipher, and public key algorithms
     */
    SupportedHashes hash;
    SupportedSymCiphers cipher;
    SupportedPubKeys pubKey;
    /**
     * The selected SAS type.
     */
    SupportedSASTypes sasType;

    /**
     * The selected SAS type.
     */
    SupportedAuthLengths authLength;
    /**
     * The s0
     */
    uint8_t s0[SHA256_DIGEST_LENGTH];

    /**
     * The HMAC key
     */
    uint8_t hmacSrtp[SHA256_DIGEST_LENGTH];

    /**
     * The Initiator's srtp key and salt
     */
    uint8_t srtpKeyI[SHA256_DIGEST_LENGTH];
    uint8_t srtpSaltI[SHA256_DIGEST_LENGTH];

    /**
     * The Responder's srtp key and salt
     */
    uint8_t srtpKeyR[SHA256_DIGEST_LENGTH];
    uint8_t srtpSaltR[SHA256_DIGEST_LENGTH];

    /**
     * Pre-initialized packets to start off the whole game.
     */
    ZrtpPacketHello*    zrtpHello;
    ZrtpPacketHelloAck* zrtpHelloAck;
    ZrtpPacketConf2Ack* zrtpConf2Ack;

    /**
     * Find the best Hash algorithm that was offered in Hello.
     *
     * Find the best, that is the strongest, Hash algorithm that our peer
     * offers in its Hello packet.
     *
     * @param hello
     *    The Hello packet.
     * @return
     *    The Enum that identifies the best offered Hash algortihm. Return
     *    <code>NumSupportedHashes</code> to signal that no matching Hash algorithm
     *     was found at all.
    */
    SupportedHashes findBestHash(ZrtpPacketHello *hello);

    /**
     * Find the best symmetric cipher algorithm that was offered in Hello.
     *
     * Find the best, that is the strongest, cipher algorithm that our peer
     * offers in its Hello packet.
     *
     * @param hello
     *    The Hello packet.
     * @return
     *    The Enum that identifies the best offered Cipher algortihm. Return
     *    <code>NumSupportedSymCiphers</code> to signal that no matching Cipher algorithm
     *    was found at all.
     */
    SupportedSymCiphers findBestCipher(ZrtpPacketHello *hello);

    /**
     * Find the best Public Key algorithm that was offered in Hello.
     *
     * Find the best, that is the strongest, public key algorithm that our peer
     * offers in its Hello packet.
     *
     * @param hello
     *    The Hello packet.
     * @return
     *    The Enum that identifies the best offered Public Key algortihm. Return
     *    <code>NumSupportedPubKeys</code> to signal that no matching Public Key algorithm
     *    was found at all.
     */
    SupportedPubKeys findBestPubkey(ZrtpPacketHello *hello);

    /**
     * Find the best SAS algorithm that was offered in Hello.
     *
     * Find the best, that is the strongest, SAS algorithm that our peer
     * offers in its Hello packet.
     *
     * @param hello
     *    The Hello packet.
     * @return
     *    The Enum that identifies the best offered SAS algortihm. Return
     *    <code>NumSupportedSASTypes</code> to signal that no matching SAS algorithm
     *    was found at all.
     */
    SupportedSASTypes findBestSASType(ZrtpPacketHello *hello);

    /**
     * Find the best authentication length that was offered in Hello.
     *
     * Find the best, that is the strongest, authentication length that our peer
     * offers in its Hello packet.
     *
     * @param hello
     *    The Hello packet.
     * @return
     *    The Enum that identifies the best offered authentication length. Return
     *    <code>NumSupportedAuthLenghts</code> to signal that no matching length
     *    was found at all.
     */
    SupportedAuthLengths findBestAuthLen(ZrtpPacketHello *hello);

    /**
     * Compute my hvi value according to ZRTP specification.
     */
    void computeHvi(uint8_t *pv, uint32_t pvLength, ZrtpPacketHello *hello);

    void computeSharedSecretSet(ZIDRecord& zidRec);

    void computeSRTPKeys(ZIDRecord& zidRec);

    void generateS0Initiator(ZrtpPacketDHPart *dhPart, ZIDRecord& zidRec);

    void generateS0Responder(ZrtpPacketDHPart *dhPart, ZIDRecord& zidRec);

    /*
     * The following methods are helper functions for ZrtpStateClass.
     * ZrtpStateClass calls them to prepare packets, send data, report
     * problems, etc.
     */
    /**
     * Send a ZRTP packet.
     *
     * The state engines calls this method to send a packet via the RTP
     * stack.
     *
     * @param packet
     *    Points to the ZRTP packet.
     * @return
     *    zero if sending failed, one if packet was send
     */
    int32_t sendPacketRTP(ZrtpPacketBase *packet);

    /**
     * Send a ZRTP packet using SRTP.
     *
     * The state engines calls this method to send a packet via the SRTP
     * stack.
     *
     * @param packet
     *    Points to the ZRTP packet.
     * @return
     *    zero if sending failed, one if packet was send
     */
    int32_t sendPacketSRTP(ZrtpPacketBase *packet);

    /**
     * Activate a Timer using the host callback.
     *
     * @param tm
     *    The time in milliseconds.
     * @return
     *    zero if activation failed, one if timer was activated
     */
    int32_t activateTimer(int32_t tm) {return (callback->activateTimer(tm)); }

    /**
     * Cancel the active Timer using the host callback.
     *
     * @return
     *    zero if activation failed, one if timer was activated
     */
    int32_t cancelTimer() {return (callback->cancelTimer()); }

    /**
     * Prepare a Hello packet.
     *
     * Just take the preinitialized Hello packet and return it. No
     * further processing required.
     *
     * @return
     *    A pointer to the initialized Hello packet.
     */
    ZrtpPacketHello *prepareHello() {return zrtpHello; }

    /**
     * Prepare a HelloAck packet.
     *
     * Just take the preinitialized HelloAck packet and return it. No
     * further processing required.
     *
     * @return
     *    A pointer to the initialized HelloAck packet.
     */
    ZrtpPacketHelloAck *prepareHelloAck() {return zrtpHelloAck; }

    /**
     * Prepare a Commit packet.
     *
     * We have received a Hello packet from our peer. Check the offers
     * it makes to us and select the most appropriate. Using the
     * selected values prepare a Commit packet and return it to protocol
     * state engine.
     *
     * @param hello
     *    Points to the received Hello packet
     * @return
     *    A pointer to the prepared Commit packet
     */
    ZrtpPacketCommit *prepareCommit(ZrtpPacketHello *hello);

    /**
     * Prepare the DHPart1 packet.
     *
     * This method prepares a DHPart1 packet. The input to the method is always
     * a Commit packet received from the peer. Also we a in the role of the
     * Responder.
     *
     * <p/>
     *
     * When we receive a Commit packet we get the selected ciphers, hashes, etc
     * and cross-check if this is ok. Then we need to initialize a set of DH
     * keys according to the selected cipher. Using this data we prepare our DHPart1
     * packet.
     */
    ZrtpPacketDHPart *prepareDHPart1(ZrtpPacketCommit *commit);

    /**
     * Prepare the DHPart2 packet.
     *
     * This method prepares a DHPart2 packet. The input to the method is always
     * a DHPart1 packet received from the peer. Our peer sends the DH1Part as
     * response to our Commit packet. Thus we are in the role of the
     * Initiator.
     *
     */
    ZrtpPacketDHPart *prepareDHPart2(ZrtpPacketDHPart *dhPart1);

    /**
     * Prepare the Confirm1 packet.
     *
     * This method prepare the Confirm1 packet. The input to this method is the
     * DHPart2 packect received from our peer. The peer sends the DHPart2 packet
     * as response of our DHPart1. Here we are in the role of the Responder
     *
     */
    ZrtpPacketConfirm *prepareConfirm1(ZrtpPacketDHPart *dhPart2);

    /**
     * Prepare the Confirm2 packet.
     *
     * This method prepare the Confirm2 packet. The input to this method is the
     * Confirm1 packet received from our peer. The peer sends the Confirm1 packet
     * as response of our DHPart2. Here we are in the role of the Initiator
     */
    ZrtpPacketConfirm* prepareConfirm2(ZrtpPacketConfirm *confirm1);

    /**
     * Prepare the Conf2Ack packet.
     *
     * This method prepare the Conf2Ack packet. The input to this method is the
     * Confirm2 packet received from our peer. The peer sends the Confirm2 packet
     * as response of our Confirm1. Here we are in the role of the Initiator
     */
    ZrtpPacketConf2Ack* prepareConf2Ack(ZrtpPacketConfirm *confirm2);

    /**
     * Prepare a ClearAck packet.
     *
     * This method checks if the GoClear message is valid. If yes then switch
     * off SRTP processing, stop sending of RTP packets (pause transmit) and
     * inform the user about the fact. Only if user confirms the GoClear message
     * normal RTP processing is resumed.
     *
     * @return
     *     NULL if GoClear could not be authenticated, a ClearAck packet
     *     otherwise.
     */
    ZrtpPacketClearAck* prepareClearAck(ZrtpPacketGoClear* gpkt);

    /**
     * Compare the hvi values.
     *
     * Compares the hvi hashes of both commit packets, the one we just
     * received and the one we sent in response of peer's hello. The
     * outcome of the compare determines which peer is Initiator or
     * Responder. If the hvi of the commit we sent is smaller then we are
     * Responder, otherwise we are Inititiator.
     *
     * @param commit
     *    Pointer to the peer's commit packet we just received.
     * @return
     *    <0 if our hvi is smaller
     *    >0 if our hvi is bigger
     *     0 shouldn't happen because we compare crypto hashes
     */
    int32_t compareHvi(ZrtpPacketCommit *commit) {
	return (memcmp(hvi, commit->getHvi(), SHA256_DIGEST_LENGTH)); };

    /**
     * Send information messages to the hosting environment.
     *
     * The ZRTP implementation uses this method to send information messages
     * to the host. Along with the message ZRTP provides a severity indicator
     * that defines: Info, Warning, Error, Alert. Refer to the MessageSeverity
     * enum in the ZrtpCallback class.
     *
     * @param severity
     *     This defines the message's severity
     * @param msg
     *     The message string, terminated with a null byte.
     */
    void sendInfo(MessageSeverity severity, char* msg) {
	callback->sendInfo(severity, msg);
    }

    /**
     * ZRTP calls this if the negotiation failed.
     *
     * ZRTP calls this method in case ZRTP negotiation failed. The parameters
     * show the severity as well as some explanatory text.
     *
     * @param severity
     *     This defines the message's severity
     * @param msg
     *     The message string, terminated with a null byte.
     */
    void zrtpNegotiationFailed(MessageSeverity severity, char* msg) {
        callback->zrtpNegotiationFailed(severity, msg);
    }

    /**
     * ZRTP calls this method if the other side does not support ZRTP.
     *
     * If the other side does not answer the ZRTP <em>Hello</em> packets then
     * ZRTP calls this method,
     *
     */
    void zrtpNotSuppOther() {
        callback->zrtpNotSuppOther();
    }

    /**
     * Signal SRTP secrets are ready.
     *
     * This method calls a callback method to inform the host that the SRTP
     * secrets are ready.
     *
     * @param part
     *    Defines for which part (sender or receiver) to switch on security
     */
    void srtpSecretsReady(EnableSecurity part);

    /**
     * Switch off SRTP secrets.
     *
     * This method calls a callback method to inform the host that the SRTP
     * secrets shall be cleared.
     *
     * @param part
     *    Defines for which part (sender or receiver) to clear
     */
    void srtpSecretsOff(EnableSecurity part);
};

#endif // ZRTP

