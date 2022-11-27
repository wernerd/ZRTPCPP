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

/**
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <cstdlib>

#include <mutex>
#include <thread>
#include "libzrtpcpp/ZRtp.h"
#include "libzrtpcpp/ZrtpStateEngineImpl.h"

using namespace std;
using namespace GnuZrtpCodes;

state_t ZrtpStateEngineImpl::states[numberOfStates] = {
        {Initial,      &ZrtpStateEngineImpl::evInitial},
        {Detect,       &ZrtpStateEngineImpl::evDetect},
        {AckDetected,  &ZrtpStateEngineImpl::evAckDetected},
        {AckSent,      &ZrtpStateEngineImpl::evAckSent},
        {WaitCommit,   &ZrtpStateEngineImpl::evWaitCommit},
        {WaitDHPart1,  &ZrtpStateEngineImpl::evWaitDHPart1},
        {WaitDHPart2,  &ZrtpStateEngineImpl::evWaitDHPart2},
        {WaitConfirm1, &ZrtpStateEngineImpl::evWaitConfirm1},
        {WaitConfirm2, &ZrtpStateEngineImpl::evWaitConfirm2},
        {WaitConfAck,  &ZrtpStateEngineImpl::evWaitConfAck},
        {WaitClearAck, &ZrtpStateEngineImpl::evWaitClearAck},
        {SecureState,  &ZrtpStateEngineImpl::evSecureState},
        {WaitErrorAck, &ZrtpStateEngineImpl::evWaitErrorAck}
};


ZrtpStateEngineImpl::ZrtpStateEngineImpl(ZRtp *p) : parent(p), commitPkt(nullptr), t1Resend(20), t1ResendExtend(60),
                                                    t2Resend(10), multiStream(false), secSubState(Normal),
                                                    sentVersion(0) {

    engine = new ZrtpStates(states, Initial);
    memset(retryCounters, 0, sizeof(retryCounters));

    // Set up timers according to ZRTP spec
    T1.start = 50;
    T1.maxResend = t1Resend;
    T1.capping = 800;

    T2.start = 150;
    T2.maxResend = t2Resend;
    T2.capping = 1200;
}

ZrtpStateEngineImpl::~ZrtpStateEngineImpl() {

    if (engine == nullptr) {
        return;
    }
    // If not in Initial state: close the protocol engine
    // before destroying it. This will free pending packets
    // if necessary.
    if (!engine->inState(Initial)) {
        Event ev;

        cancelTimer();
        ev.type = ZrtpClose;
        event = &ev;        // Looks suspicious, however it's safe in this case
        engine->processEvent(*this);
    }
    delete engine;
}

void ZrtpStateEngineImpl::processEvent(Event *ev) {

    std::mutex stateMutex;
    lock_guard<std::mutex> stateGuard(stateMutex);  // process only one packet at a time

    event = ev;                                     // make available to other member functions
    if (event->type == ZrtpPacket) {
        auto const *pkt = event->packet;
        msgType = string(reinterpret_cast<char const *>(pkt + 4), 8);

        // Sanity check of packet size for all states except WaitErrorAck.
        // Actual packet type not known yet, thus use internal knowledge of ZRTP
        // packet layout as specified in RFC6189.

        // Multi-frame packet handling performs sanity checks, sets the length to 0,
        // skip this check here in this case.
        if (!inState(WaitErrorAck) && ev->length > 0) {
            uint16_t totalLength = *(uint16_t *) (pkt + 2);  // ZRTP packet length in bytes 3 and 4, big endian
            totalLength = zrtpNtohs(totalLength) * ZRTP_WORD_SIZE; // ZRTP packet length is in number of ZRTP words
            totalLength += transportOverhead + sizeof(uint32_t);        // add transport overhead and CRC (uint32_t)

            if (totalLength != ev->length) {
                LOGGER(ERROR_LOG, "Total length does not match received length: ", totalLength, " - ", ev->length)
                sendErrorPacket(MalformedPacket);
                return;
            }
        }

        // Check if this is an Error packet.
        if (msgType == ErrorMsg) {
            /*
             * Process a received Error packet.
             *
             * In any case stop timer to prevent resending packets.
             * Use callback method to prepare and get an ErrorAck packet.
             * Modify event type to "ErrorPkt" and hand it over to current
             * state for further processing.
             */
            cancelTimer();
            ZrtpPacketError epkt(pkt);
            ZrtpPacketErrorAck *eapkt = parent->prepareErrorAck(&epkt);
            parent->sendPacketZRTP(eapkt);
            event->type = ErrorPkt;
        } else if (msgType == PingMsg) {
            ZrtpPacketPing ppkt(pkt);
            ZrtpPacketPingAck *ppktAck = parent->preparePingAck(&ppkt);
            if (ppktAck != nullptr) {          // ACK only to valid PING packet, otherwise ignore it
                parent->sendPacketZRTP(ppktAck);
            }
            return;
        } else if (msgType == SasRelayMsg) {
            uint32_t errorCode = 0;
            auto *srly = new ZrtpPacketSASrelay(pkt);
            auto *rapkt = parent->prepareRelayAck(srly, &errorCode);
            parent->sendPacketZRTP(rapkt);
            return;
        }
    }
        /*
         * Shut down protocol state engine: cancel outstanding timer, further
         * processing in current state.
         */
    else if (event->type == ZrtpClose) {
        cancelTimer();
    }
    engine->processEvent(*this);
}


void ZrtpStateEngineImpl::evInitial() {
    LOGGER(VERBOSE, "Enter ", __func__)
    if (event->type == ZrtpInitial) {
        auto *hello = parent->prepareHello();
        sentVersion = hello->getVersionInt();

        // remember packet for easy resend in case timer triggers
        sentPacket = hello;

        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();                 // returns to state Initial
            return;
        }
        if (startTimer(&T1) <= 0) {
            timerFailed(SevereNoTimer);      // returns to state Initial
            return;
        }
        nextState(Detect);
    }
}

/*
 * Detect state.
 *
 * When in this state the protocol engine sent an initial Hello packet
 * to the peer.
 *
 * When entering this state transition function then:
 * - Assume Initiator mode, mode may change later on peer reaction
 * - Instance variable sentPacket contains the sent Hello packet
 * - Hello timer T1 may be active. This is the case if the other peer
 *   has prepared its RTP session and answers our Hello packets nearly 
 *   immediately, i.e. before the Hello timeout counter expires. If the
 *   other peer does not send a Hello during this time the state engine
 *   reports "other peer does not support ZRTP" but stays
 *   in state Detect with no active timer (passiv mode). Staying in state 
 *   Detect allows another peer to start its detect phase any time later.
 *
 *   This restart capability is the reason why we use "startTimer(&T1)" in 
 *   case we received a Hello packet from another peer. This effectively 
 *   restarts the Hello timeout counter.
 *
 *   In this state we also handle ZrtpInitialize event. This forces a
 *   restart of ZRTP discovery if an application calls ZrtpQueue#startZrtp
 *   again. This may happen after a previous discovery phase were not 
 *   successful.
 *
 *   Usually applications use some sort of signaling protocol, for example
 *   SIP, to negotiate the RTP parameters. Thus the RTP sessions setup is
 *   fairly sychronized and thus also the ZRTP detection phase. Applications
 *   that use some other ways to setup the RTP sessions this restart capability
 *   comes in handy because no RTP setup sychronization is necessary.
 * 
 * Possible events in this state are:
 * - timeout for sent Hello packet: causes a resend check and 
 *   repeat sending of Hello packet
 * - received a HelloAck: stop active timer, prepare and send Hello packet,
 *   switch to state AckDeteced.
 * - received a Hello: stop active timer, send HelloAck, prepare Commit 
 *   packet, switch to state AckSent.
 *
 */
void ZrtpStateEngineImpl::evDetect() {
    LOGGER(VERBOSE, "Enter ", __func__, ", with message: ", msgType)

    /*
     * First check the general event type, then discriminate
     * the real event.
     */
    if (event->type == ZrtpPacket) {
        uint32_t errorCode = 0;
        auto const *pkt = event->packet;

        /*
         * HelloAck:
         * - our peer acknowledged our Hello packet, we have not seen the peer's Hello yet
         * - cancel timer T1 to stop resending Hello
         * - switch to state AckDetected, wait for peer's Hello (F3)
         * 
         * When we receive an HelloAck this also means that our partner accepted our protocol version.
         */
        if (msgType == HelloAckMsg) {
            cancelTimer();
            sentPacket = nullptr;
            nextState(AckDetected);
            return;
        }
        /*
         * Hello:
         * - send HelloAck packet to acknowledge the received Hello packet if versions match.
         *   Otherwise, negotiate ZRTP versions.
         * - use received Hello packet to prepare own Commit packet. We need to
         *   do it at this point because we need the hash value computed from
         *   peer's Hello packet. Following states my use the prepared Commit.
         * - switch to new state AckSent which sends own Hello packet until 
         *   peer acknowledges this
         * - Don't clear sentPacket, points to Hello
         */
        if (msgType == HelloMsg) {
            ZrtpPacketHello hpkt(pkt);
            parent->saveOtherHelloData(hpkt);
            cancelTimer();

            /*
             * Check and negotiate the ZRTP protocol version first.
             *
             * This selection mechanism relies on the fact that we sent the highest supported protocol version in
             * the initial Hello packet as stated in RFC6189, section 4.1.1
             */
            auto recvVersion = hpkt.getVersionInt();
            if (recvVersion > sentVersion) {   // We don't support this version, stay in state with timer active
                if (startTimer(&T1) <= 0) {
                    timerFailed(SevereNoTimer);      // returns to state Initial
                }
                return;
            }

            /*
             * The versions don't match. Start negotiating versions. This negotiation stays in the Detect state.
             * Only if the received version matches our own sent version we start to send a HelloAck.
             */
            if (recvVersion != sentVersion) {
                ZRtp::HelloPacketVersion_t *hpv = parent->helloPackets;

                int32_t index;
                for (index = 0; hpv->packet &&
                                hpv->packet != parent->currentHelloPacket; hpv++, index++)   // Find current sent Hello
                    ;

                for (; index >= 0 && hpv->version >
                                     recvVersion; hpv--, index--)   // find a supported version less-equal to received version
                    ;

                if (index < 0) {
                    sendErrorPacket(UnsuppZRTPVersion);
                    return;
                }
                parent->currentHelloPacket = hpv->packet;
                sentVersion = parent->currentHelloPacket->getVersionInt();

                // remember packet for easy resend in case timer triggers
                sentPacket = parent->currentHelloPacket;

                if (!parent->sendPacketZRTP(sentPacket)) {
                    sendFailed();                 // returns to state Initial
                    return;
                }
                if (startTimer(&T1) <= 0) {
                    timerFailed(SevereNoTimer);      // returns to state Initial
                    return;
                }
                return;
            }
            ZrtpPacketHelloAck *helloAck = parent->prepareHelloAck();

            if (!parent->sendPacketZRTP(helloAck)) {
                parent->zrtpNegotiationFailed(Severe, SevereCannotSend);
                return;
            }
            // Use peer's Hello packet to create my commit packet, store commit packet
            // for possible later use in state AckSent
            commitPkt = parent->prepareCommit(&hpkt, &errorCode);

            nextState(AckSent);
            if (commitPkt == nullptr) {
                sendErrorPacket(errorCode);    // switches to Error state
                return;
            }
            if (startTimer(&T1) <= 0) {        // restart own Hello timer/counter
                timerFailed(SevereNoTimer);    // returns to state Initial
            }
            T1.maxResend = t1ResendExtend;     // more retries to extend time, see chap. 6
        }
        return;      // unknown packet for this state - Just ignore it
    }
        // Timer event triggered - this is Timer T1 to resend Hello
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();       // returns to state Initial
            return;
        }
        retryCounters[HelloRetry]++;

        if (nextTimer(&T1) <= 0) {
            commitPkt = nullptr;
            parent->zrtpNotSuppOther();
            nextState(Detect);
        }
    }
        // If application calls zrtpStart() to restart discovery
    else if (event->type == ZrtpInitial) {
        cancelTimer();
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();                 // returns to state Initial
            return;
        }
        if (startTimer(&T1) <= 0) {
            timerFailed(SevereNoTimer);   // returns to state Initial
        }
    } else { // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = nullptr;
        nextState(Initial);
    }
}

/*
 * AckSent state.
 *
 * The protocol engine got a Hello packet from peer and answered with a
 * HelloAck response.  According to the protocol we must also send a 
 * Hello after HelloAck (refer to figure 1 in ZRTP RFC 6189, message
 * HelloACK (F2) must be followed by Hello (F3)). We use the timeout in 
 * this state to send the required Hello (F3).
 *
 * Our peer must acknowledge the Hello with HelloAck. In earlier versions 
 * also a Commit was a valid packet thus the code covers this.
 * Figure 1 in the RFC shows the HelloAck, chapter 7 states that a Commit 
 * may be sent to acknowledge Hello. There is one constraint when using a Commit to
 * acknowledge Hello: refer to chapter 4.1 that requires that both parties
 * have completed the Hello/HelloAck discovery handshake. This implies that 
 * only message F4 may be replaced by a Commit. This constraint guarantees
 * that both peers have seen at least one Hello.
 *
 * When entering this transition function:
 * - The instance variable sentPacket contains own Hello packet
 * - The instance variable commitPkt points to prepared Commit packet
 * - Timer T1 is active
 *
 * Possible events in this state are:
 * - timeout for sent Hello packet: causes a resend check and repeat sending
 *   of Hello packet
 * - HelloAck: The peer answered with HelloAck to own HelloAck/Hello. Send
 *   prepared Commit packet and try Initiator mode.
 * - Commit: The peer answered with Commit to HelloAck/Hello, thus switch to
 *   responder mode.
 * - Hello: If the protocol engine receives another Hello it repeats the
 *   HelloAck/Hello response until Timer T1 exceeds its maximum. This may 
 *   happen if the other peer sends Hello only (maybe due to network problems)
 */
void ZrtpStateEngineImpl::evAckSent() {
    LOGGER(VERBOSE, "Enter ", __func__, ", with message: ", msgType)
    /*
     * First check the general event type, then discriminate
     * the real event.
     */
    if (event->type == ZrtpPacket) {
        uint32_t errorCode = 0;
        auto const *pkt = event->packet;


        /*
         * HelloAck:
         * The peer answers with HelloAck to own HelloAck/Hello. Send Commit
         * and try Initiator mode. The requirement defined in chapter 4.1 to
         * have a complete Hello/HelloAck is fulfilled.
         * - stop Hello timer T1
         * - send own Commit message
         * - switch state to WaitDHPart1, start Commit timer, assume Initiator
         */
        if (msgType == HelloAckMsg) {
            cancelTimer();

            LOGGER(DEBUGGING, "Ack: ", commitPkt->getLength(), ", id: ", std::this_thread::get_id())
            // remember packet for easy resend in case timer triggers
            // Timer trigger received in new state WaitDHPart1
            sentPacket = commitPkt;
            commitPkt = nullptr;                    // now stored in sentPacket
            nextState(WaitDHPart1);
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();             // returns to state Initial
                return;
            }
            if (startTimer(&T2) <= 0) {
                timerFailed(SevereNoTimer);  // returns to state Initial
            }
            return;
        }
        /*
         * Hello:
         * - peer didn't receive our HelloAck
         * - repeat HelloAck response:
         *  -- get HelloAck packet, send it
         *  -- The timeout trigger of T1 sends our Hello packet
         *  -- stay in state AckSent
         *
         * Similar to Detect state: just acknowledge the Hello, the next
         * timeout sends the following Hello.
         */

        if (msgType == HelloMsg) {
            ZrtpPacketHelloAck *helloAck = parent->prepareHelloAck();

            if (!parent->sendPacketZRTP(helloAck)) {
                nextState(Detect);
                parent->zrtpNegotiationFailed(Severe, SevereCannotSend);
            }
            return;
        }
        /*
         * Commit:
         * The peer answers with Commit to HelloAck/Hello, thus switch to
         * responder mode.
         * - stop timer T1
         * - prepare and send our DHPart1
         * - switch to state WaitDHPart2 and wait for peer's DHPart2
         * - don't start timer, we are responder
         */
        if (msgType == CommitMsg) {
            cancelTimer();
            ZrtpPacketCommit cpkt(pkt);

            if (!multiStream) {
                ZrtpPacketDHPart *dhPart1 = parent->prepareDHPart1(&cpkt, &errorCode);

                // Something went wrong during processing of the Commit packet
                if (dhPart1 == nullptr) {
                    if (errorCode != IgnorePacket) {
                        sendErrorPacket(errorCode);
                    }
                    return;
                }
                commitPkt = nullptr;
                sentPacket = dhPart1;
                nextState(WaitDHPart2);
            } else {
                ZrtpPacketConfirm *confirm = parent->prepareConfirm1MultiStream(&cpkt, &errorCode);

                // Something went wrong during processing of the Commit packet
                if (confirm == nullptr) {
                    if (errorCode != IgnorePacket) {
                        sendErrorPacket(errorCode);
                    }
                    return;
                }
                sentPacket = confirm;
                nextState(WaitConfirm2);
            }
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();      // returns to state Initial
            }
        }
    }
        /*
         * Timer:
         * - resend Hello packet, stay in state, restart timer until repeat
         *   counter triggers
         * - if repeat counter triggers switch to state Detect, can't clear
         *   sentPacket, Detect requires it to point to own Hello message
         */
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            return sendFailed();      // returns to state Initial
        }
        retryCounters[HelloRetryAck]++;

        if (nextTimer(&T1) <= 0) {
            parent->zrtpNotSuppOther();
            commitPkt = nullptr;
            // Stay in state Detect to be prepared get a hello from
            // other peer any time later
            nextState(Detect);
        }
    } else {   // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        commitPkt = nullptr;
        sentPacket = nullptr;
        nextState(Initial);
    }
}

/*
 * AckDetected state.
 *
 * The protocol engine received a HelloAck in state Detect, thus the peer 
 * acknowledged our the Hello. According to ZRT RFC 6189 our peer must send
 * its Hello until our protocol engine sees it (refer also to comment for
 * state AckSent). This protocol sequence guarantees that both peers got at
 * least one Hello. 
 *
 * When entering this transition function
 * - instance variable sentPacket is nullptr, Hello timer stopped
 *
 * Possible events in this state are:
 * Hello: we have two choices
 *  1) we can acknowledge the peer's Hello with a HelloAck
 *  2) we can acknowledge the peer's Hello with a Commit
 *
 *  Both choices are implemented and may be enabled by change the #if check
 *  during compile time. Currently, we use choice 1) here because it's more
 *  aligned to the ZRTP specification
 */
void ZrtpStateEngineImpl::evAckDetected() {
    LOGGER(VERBOSE, "Enter ", __func__)
    if (event->type == ZrtpPacket) {
        uint32_t errorCode = 0;
        auto const *pkt = event->packet;


#if 1
        /*
         * Implementation for choice 1)
         * Hello:
         * - Acknowledge peer's Hello, sending HelloACK (F4)
         * - switch to state WaitCommit, wait for peer's Commit
         * - we are going to be in the Responder role
         */

        if (msgType == HelloMsg) {
            // Parse Hello packet and build an own Commit packet even if the
            // Commit is not send to the peer. We need to do this to check the
            // Hello packet and prepare the shared secret stuff.
            ZrtpPacketHello hpkt(pkt);
            parent->saveOtherHelloData(hpkt);
            ZrtpPacketCommit *commit = parent->prepareCommit(&hpkt, &errorCode);

            // Something went wrong during processing of the Hello packet, for
            // example wrong version, duplicate ZID.
            if (commit == nullptr) {
                sendErrorPacket(errorCode);
                return;
            }
            ZrtpPacketHelloAck *helloAck = parent->prepareHelloAck();
            nextState(WaitCommit);

            // remember packet for easy resend
            sentPacket = helloAck;
            if (!parent->sendPacketZRTP(helloAck)) {
                sendFailed();
            }
        }
#else
        /*
         * Implementation for choice 2)
         * Hello:
         * - Acknowledge peer's Hello by sending Commit (F5)
         *   instead of HelloAck (F4)
         * - switch to state CommitSent
         * - Initiator role, thus start timer T2 to monitor timeout for Commit
         */

        if (msgType == HelloMsg) {
            // Parse peer's packet data into a Hello packet
            ZrtpPacketHello hpkt(pkt);
            ZrtpPacketCommit* commit = parent->prepareCommit(&hpkt, &errorCode);
            // Something went wrong during processing of the Hello packet  
            if (commit == nullptr) {
                sendErrorPacket(errorCode);
                return;
            }
            nextState(CommitSent);

            // remember packet for easy resend in case timer triggers
            // Timer trigger received in new state CommitSend
            sentPacket = commit;
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();
                return;
            }
            if (startTimer(&T2) <= 0) {
                timerFailed(SevereNoTimer);
            }
        }
#endif
    } else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        nextState(Initial);
    }
}

/*
 * WaitCommit state.
 *
 * This state is only used if we use choice 1) in AckDetected.
 *
 * When entering this transition function
 * - instance variable sentPacket contains a HelloAck packet
 * 
 * Possible events in this state are:
 * - Hello: just resend our HelloAck
 * - Commit: prepare and send our DHPart1 message to start first
 *   half of DH key agreement. Switch to state WaitDHPart2, don't
 *   start any timer, we are Responder.
 */
void ZrtpStateEngineImpl::evWaitCommit() {
    LOGGER(VERBOSE, "Enter ", __func__)

    if (event->type == ZrtpPacket) {
        uint32_t errorCode = 0;
        auto const *pkt = event->packet;

        /*
         * Hello:
         * - resend HelloAck
         * - stay in WaitCommit
         */
        if (msgType == HelloMsg) {
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();       // returns to state Initial
            }
            return;
        }
        /*
         * Commit:
         * - prepare DH1Part packet or Confirm1 if multi stream mode
         * - send it to peer
         * - switch state to WaitDHPart2 or WaitConfirm2 if multi stream mode
         * - don't start timer, we are responder
         */
        if (msgType == CommitMsg) {
            ZrtpPacketCommit cpkt(pkt);

            if (!multiStream) {
                ZrtpPacketDHPart *dhPart1 = parent->prepareDHPart1(&cpkt, &errorCode);

                // Something went wrong during processing of the Commit packet
                if (dhPart1 == nullptr) {
                    if (errorCode != IgnorePacket) {
                        sendErrorPacket(errorCode);
                    }
                    return;
                }
                sentPacket = dhPart1;
                nextState(WaitDHPart2);
            } else {
                ZrtpPacketConfirm *confirm = parent->prepareConfirm1MultiStream(&cpkt, &errorCode);

                // Something went wrong during processing of the Commit packet
                if (confirm == nullptr) {
                    if (errorCode != IgnorePacket) {
                        sendErrorPacket(errorCode);
                    }
                    return;
                }
                sentPacket = confirm;
                nextState(WaitConfirm2);
            }
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();       // returns to state Initial
            }
        }
    } else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = nullptr;
        nextState(Initial);
    }
}

/*
 * WaitDHPart1 state.
 *
 * This state either handles a DH1Part1 message to start the first
 * half of DH key agreement, or it handles a Commit clash. If handling a
 * Commit clash it may happen that we change our role from Initiator to
 * Responder.
 *
 * When entering this transition function
 * - assume Initiator mode, may change if we receive a Commit here
 * - sentPacket contains Commit packet
 * - Commit timer (T2) active
 *
 * Possible events in this state are:
 * - timeout for sent Commit packet: causes a resend check and repeat sending
 *   of Commit packet
 * - Commit: This is a Commit clash. Break the tie according to chapter 5.2
 * - DHPart1: start first half of DH key agreement. Prepare and send own DHPart2
 *   and switch to state WaitConfirm1.
 */

void ZrtpStateEngineImpl::evWaitDHPart1() {
    LOGGER(VERBOSE, "Enter ", __func__, ", with message: ", msgType)

    if (event->type == ZrtpPacket) {
        uint32_t errorCode = 0;
        auto const *pkt = event->packet;

        /*
         * HelloAck or Hello:
         * - delayed "HelloAck" or "Hello", maybe due to network latency, just 
         *   ignore it
         * - no switch in state, leave timer as it is
         */
        if (msgType == HelloMsg || msgType == HelloAckMsg) {
            return;
        }

        /*
         * Commit:
         * We have a "Commit" clash. Resolve it.
         *
         * - switch off resending Commit
         * - compare my hvi with peer's hvi
         * - if my hvi is greater
         *   - we are Initiator, stay in state, wait for peer's DHPart1 packet
         * - else
         *   - we are Responder, stop timer
         *   - prepare and send DH1Packt,
         *   - switch to state WaitDHPart2, implies Responder path
         */
        if (msgType == CommitMsg) {
            ZrtpPacketCommit zpCo(pkt);

            if (!parent->verifyH2(&zpCo)) {
                return;
            }
            cancelTimer();         // this cancels the Commit timer T2

            if (!zpCo.isLengthOk(multiStream ? ZrtpPacketCommit::MultiStream : ZrtpPacketCommit::DhExchange)) {
                sendErrorPacket(CriticalSWError);
                return;
            }

            // if our hvi is less than peer's hvi: switch to Responder mode and
            // send DHPart1 or Confirm1 packet. Peer (as Initiator) will re-trigger if
            // necessary
            //
            if (parent->compareCommit(&zpCo) < 0) {
                if (!multiStream) {
                    ZrtpPacketDHPart *dhPart1 = parent->prepareDHPart1(&zpCo, &errorCode);

                    // Something went wrong during processing of the Commit packet
                    if (dhPart1 == nullptr) {
                        if (errorCode != IgnorePacket) {
                            sendErrorPacket(errorCode);
                        }
                        return;
                    }
                    nextState(WaitDHPart2);
                    sentPacket = dhPart1;
                } else {
                    ZrtpPacketConfirm *confirm = parent->prepareConfirm1MultiStream(&zpCo, &errorCode);

                    // Something went wrong during processing of the Commit packet
                    if (confirm == nullptr) {
                        if (errorCode != IgnorePacket) {
                            sendErrorPacket(errorCode);
                        }
                        return;
                    }
                    nextState(WaitConfirm2);
                    sentPacket = confirm;
                }
                if (!parent->sendPacketZRTP(sentPacket)) {
                    sendFailed();       // returns to state Initial
                }
            }
            else {
                // Stay in state, we are Initiator, wait for DHPart1 of Confirm1 packet from peer.
                // Resend Commit after timeout until we get a DHPart1 or Confirm1
                if (startTimer(&T2) <= 0) { // restart the Commit timer, gives peer more time to react
                    timerFailed(SevereNoTimer);    // returns to state Initial
                }
            }
            return;
        }

        /*
         * DHPart1:
         * - switch off resending Commit
         * - Prepare and send DHPart2
         * - switch to WaitConfirm1
         * - start timer to resend DHPart2 if necessary, we are Initiator
         */
        if (msgType == DHPart1Msg) {
            cancelTimer();
            sentPacket = nullptr;
            ZrtpPacketDHPart dpkt(pkt);

// OPT            if (!parent->isNpAlgorithmActive) {
                ZrtpPacketDHPart *dhPart2 = parent->prepareDHPart2(&dpkt, &errorCode);

                // Something went wrong during processing of the DHPart1 packet
                if (dhPart2 == nullptr) {
                    if (errorCode != IgnorePacket) {
                        sendErrorPacket(errorCode);
                    } else {
                        if (startTimer(&T2) <= 0) {
                            timerFailed(SevereNoTimer);       // switches to state Initial
                        }
                    }

                    return;
                }
                sentPacket = dhPart2;
                nextState(WaitConfirm1);

                if (!parent->sendPacketZRTP(sentPacket)) {
                    sendFailed();       // returns to state Initial
                    return;
                }
// OPT            } else {
//                // Pack DHPart2 and Confirm1 into on multi-fragment packet, wait for Confirm2 message
//                LOGGER(ERROR_LOG, "ZRTP 2022 no yet implemented")
//                // TODO: implement ZRTP 2022
//                nextState(WaitConfirm2);
//            }
            if (startTimer(&T2) <= 0) {
                timerFailed(SevereNoTimer);       // switches to state Initial
            }
            return;
        }

        /*
         * Confirm1 and multi-stream mode
         * - switch off resending commit
         * - prepare Confirm2
         */
        if (multiStream && msgType == Confirm1Msg) {
            cancelTimer();
            ZrtpPacketConfirm cpkt(pkt);

            ZrtpPacketConfirm *confirm = parent->prepareConfirm2MultiStream(&cpkt, &errorCode);

            // Something went wrong during processing of the Confirm1 packet
            if (confirm == nullptr) {
                sendErrorPacket(errorCode);
                return;
            }
            nextState(WaitConfAck);
            sentPacket = confirm;

            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();         // returns to state Initial
                return;
            }
            if (startTimer(&T2) <= 0) {
                timerFailed(SevereNoTimer);  // returns to state Initial
                return;
            }
            // according to chap 5.6: after sending Confirm2 the Initiator must
            // be ready to receive SRTP data. SRTP sender will be enabled in WaitConfAck
            // state.
            if (!parent->srtpSecretsReady(ForReceiver)) {
                parent->sendInfo(Severe, CriticalSWError);
                sendErrorPacket(CriticalSWError);
                return;
            }
        }
    }
        // Timer event triggered, resend the Commit packet
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();       // returns to state Initial
            return;
        }
        retryCounters[CommitRetry]++;

        if (nextTimer(&T2) <= 0) {
            timerFailed(SevereTooMuchRetries);       // returns to state Initial
        }
    } else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = nullptr;
        nextState(Initial);
    }
}

/*
 * WaitDHPart2 state.
 *
 * This state handles the second part of SH key agreement. Only the Resonder
 * can enter this state.
 *
 * When entering this transition function
 * - sentPacket contains DHPart1 packet, no timer active
 *
 * Possible events in this state are:
 * - Commit: Our peer didn't receive out DHPart1 thus the peer sends Commit again.
 *   Just repeat our DHPart1.
 * - DHPart2: start second half of DH key agreement. Perpare and send own Confirm1
 *   and switch to state WaitConfirm2.
 */
void ZrtpStateEngineImpl::evWaitDHPart2() {
    LOGGER(VERBOSE, "Enter ", __func__)

    if (event->type == ZrtpPacket) {
        uint32_t errorCode = 0;
        auto const *pkt = event->packet;
        /*
         * Commit:
         * - resend DHPart1
         * - stay in state
         */
        if (msgType == CommitMsg) {
            if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();       // returns to state Initial
            }
            return;
        }
        /*
         * DHPart2:
         * - prepare Confirm1 packet
         * - switch to WaitConfirm2
         * - No timer, we are responder
         */
        if (msgType == DHPart2Msg) {
            ZrtpPacketDHPart dpkt(pkt);
// OPT            if (!parent->isNpAlgorithmActive) {
                ZrtpPacketConfirm *confirm = parent->prepareConfirm1(&dpkt, &errorCode);

                if (confirm == nullptr) {
                    if (errorCode != IgnorePacket) {
                        sendErrorPacket(errorCode);
                    }
                    return;
                }
                nextState(WaitConfirm2);
                sentPacket = confirm;
                if (!parent->sendPacketZRTP(sentPacket)) {
                    sendFailed();       // returns to state Initial
                }
            } else {
                // DHPart2 and Confirm1 were packed into on multi-fragment packet, wait for Confirm1 message
                // This message is in same packet, thus will follow immediately. Send the Confirm2 message.
                LOGGER(ERROR_LOG, "ZRTP 2022 no yet implemented")
                // TODO: implement ZRTP 2022: Check DHPart2. Nothing to prepare - advance state only
                sentPacket = nullptr;
                nextState(WaitConfirm1);
            }
        }
// OPT   } else {  // unknown Event type for this state (covers Error and ZrtpClose)
//        if (event->type != ZrtpClose) {
//            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
//        }
//        sentPacket = nullptr;
//        nextState(Initial);
//    }
}

/*
 * WaitConfirm1 state.
 *
 * This state handles a received Confirm1 message and only the Initiator
 * can enter this state.
 *
 * When entering this transition function in DH mode:
 * - Initiator mode or Responder mode when ZRTP 2022 is true
 * - sentPacket contains DHPart2 packet, DHPart2 timer active
 * - ZRTP 2022 mode: timer inactive. sentPacket is null
 *
 * When entering this transition function in Multi stream mode via AckSent:
 * - Initiator mode
 * - sentPacket contains my Commit packet, Commit timer active
 * 
* Possible events in this state are:
 * - timeout for sent DHPart2 packet: causes a resend check and repeat sending
 *   of DHPart2 packet.
 * - Confirm1: Check Confirm1 message. If it is ok then prepare and send own
 *   Confirm2 packet and switch to state WaitConfAck.
 */
void ZrtpStateEngineImpl::evWaitConfirm1() {
    LOGGER(VERBOSE, "Enter ", __func__)

    if (event->type == ZrtpPacket) {
        uint32_t errorCode = 0;
        auto const *pkt = event->packet;

        /*
         * Confirm1:
         * - Switch off resending DHPart2
         * - prepare a Confirm2 packet
         * - switch to state WaitConfAck
         * - set timer to monitor Confirm2 packet, we are initiator
         */
        if (msgType == Confirm1Msg) {
            cancelTimer();
            ZrtpPacketConfirm cpkt(pkt);

            ZrtpPacketConfirm *confirm = parent->prepareConfirm2(&cpkt, &errorCode);

            // Something went wrong during processing of the Confirm1 packet
            if (confirm == nullptr) {
                sendErrorPacket(errorCode);
                return;
            }
            // according to chap 5.8: after sending Confirm2 the Initiator (in case of ZRTP 2022: the Responder)
            // must be ready to receive SRTP data. SRTP sender will be enabled in WaitConfAck
            // state.
            if (!parent->srtpSecretsReady(ForReceiver)) {
                parent->sendInfo(Severe, CriticalSWError);
                sendErrorPacket(CriticalSWError);
                return;
            }
            nextState(WaitConfAck);
            sentPacket = confirm;

            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();         // returns to state Initial
                return;
            }
            if (startTimer(&T2) <= 0) {
                timerFailed(SevereNoTimer);  // returns to state Initial
            }
        }
    } else if (event->type == Timer) {
        // If ZRTP 2022 then we are in Responder mode: no timeout expected
// OPT        if (parent->isNpAlgorithmActive) {
//            LOGGER(ERROR_LOG, "Timeout in WaitConfirm1 but ZRTP 2022 is active")
//            return;
//        }
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();             // returns to state Initial
            return;
        }
        retryCounters[DhPart2Retry]++;

        if (nextTimer(&T2) <= 0) {
            timerFailed(SevereTooMuchRetries);     // returns to state Initial
        }
    } else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = nullptr;
        nextState(Initial);
    }
}

/*
 * WaitConfirm2 state.
 *
 * Handles the Confirm2 message that closes the key agreement handshake. Only
 * the Responder can enter this state. If the Confirm2 message is ok send a 
 * Conf2Ack to our peer. Switch to secure mode after sending Conf2Ack, our 
 * peer switches to secure mode after receiving Conf2Ack.
 *
 * TODO - revise documentation comments
 * 
 * When entering this transition function
 * - Responder mode or Initiator mode when ZRTP 2022 is true
 * - sentPacket contains Confirm1 packet, no timer active
 *
 * Possible events in this state are:
 * - DHPart2: Our peer didn't receive our Confirm1 thus sends DHPart2 again.
 *   Just repeat our Confirm1.
 * - Confirm2: close DH key agreement. Prepare and send own Conf2Ack
 *   and switch to state SecureState.
 * - if ZRTP 2022: timeout for sent multi-frame packet: causes a resend check
 *   and repeat sending multi-frame packet.
 */
void ZrtpStateEngineImpl::evWaitConfirm2() {
    LOGGER(VERBOSE, "Enter ", __func__)

    if (event->type == ZrtpPacket) {
        uint32_t errorCode = 0;
        auto const *pkt = event->packet;

        /*
         * DHPart2 or Commit in multi stream mode:
         * - resend Confirm1 packet
         * - stay in state
         */
        if (msgType == DHPart2Msg || (multiStream && msgType == CommitMsg)) {
// OPT           if (parent->isNpAlgorithmActive) {
//                LOGGER(ERROR_LOG, "WaitConfirm2 received illegal message in ZRTP 2022 mode.")
//            }
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();             // returns to state Initial
            }
            return;
        }
        /*
         * Confirm2:
         * - prepare ConfAck
         * - switch on security (SRTP)
         * - switch to SecureState
         */
        if (msgType == Confirm2Msg) {
            ZrtpPacketConfirm cpkt(pkt);
            ZrtpPacketConf2Ack *confAck = parent->prepareConf2Ack(&cpkt, &errorCode);

            // Something went wrong during processing of the confirm2 packet
            if (confAck == nullptr) {
                sendErrorPacket(errorCode);
                return;
            }
            sentPacket = confAck;

            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();             // returns to state Initial
                return;
            }
            if (!parent->srtpSecretsReady(ForReceiver) || !parent->srtpSecretsReady(ForSender)) {
                parent->sendInfo(Severe, CriticalSWError);
                sendErrorPacket(CriticalSWError);
                return;
            }
            nextState(SecureState);
            parent->sendInfo(Info, InfoSecureStateOn);
        }
    } else if (event->type == Timer) {
        // If ZRTP 2022 then we are in Initiator mode, need to handle timeout
// OPT        if (!parent->isNpAlgorithmActive) {
//            LOGGER(ERROR_LOG, "Timeout in WaitConfirm2 but ZRTP 2022 is not active")
//            return;
//        }
        // TODO: implement ZRTP 2022
        LOGGER(ERROR_LOG, "ZRTP 2022 not yet implemented")
        retryCounters[DhPart2Retry]++;

        if (nextTimer(&T2) <= 0) {
            timerFailed(SevereTooMuchRetries);     // returns to state Initial
        }
    } else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = nullptr;
        nextState(Initial);
    }
}

/*
 * WaitConf2Ack state.
 *
 * This state handles the Conf2Ack message that acknowledges the successful
 * processing of Confirm2. Only the Initiator can enter this state. Switch on
 * secure mode and switch to state SecureState.
 *
 * When entering this transition function
 * - Initiator mode or Responder mode when ZRTP 2022 is true
 * - sentPacket contains Confirm2 packet, Confirm2 timer active
 * - receiver security switched on
 *
 * Possible events in this state are:
 * - timeout for sent Confirm2 packet: causes a resend check and repeat sending
 *   of Confirm2 packet
 * - Conf2Ack: Key agreement was successful, switch to secure mode.
 * - If ZRTP 2022 mode: DHPart2 resend confirm2 packet.
 *   May happen due to multi-frame packet DHPart2 and Confirm1
 */
void ZrtpStateEngineImpl::evWaitConfAck() {
    LOGGER(VERBOSE, "Enter ", __func__)

    if (event->type == ZrtpPacket) {

// OPT       if (parent->isNpAlgorithmActive) {
//            if (msgType == DHPart2Msg) {
//                if (!parent->sendPacketZRTP(sentPacket)) {
//                    sendFailed();             // returns to state Initial
//                }
//            }
//            // Ignore Confirm1 message of the multi-frame packet
//            if (msgType == Confirm1Msg) {
//                return;
//            }
//        }
        /*
        * ConfAck:
        * - Switch off resending Confirm2
        * - switch to SecureState
        */
        if (msgType == Conf2AckMsg) {
            cancelTimer();
            sentPacket = nullptr;
            // Receiver was already enabled after sending Confirm2 packet
            // see previous states.
            if (!parent->srtpSecretsReady(ForSender)) {
                parent->sendInfo(Severe, CriticalSWError);
                sendErrorPacket(CriticalSWError);
                return;
            }
            nextState(SecureState);
            // TODO: call parent to clear signature data at initiator
            parent->sendInfo(Info, InfoSecureStateOn);
        }
    } else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();             // returns to state Initial
            parent->srtpSecretsOff(ForReceiver);
            return;
        }
        retryCounters[Confirm2Retry]++;

        if (nextTimer(&T2) <= 0) {
            timerFailed(SevereTooMuchRetries); // returns to state Initial
            parent->srtpSecretsOff(ForReceiver);
        }
    } else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = nullptr;
        nextState(Initial);
        parent->srtpSecretsOff(ForReceiver);
    }
}

/*
 * When entering this transition function
 * - sentPacket contains GoClear packet, GoClear timer active
 */

void ZrtpStateEngineImpl::evWaitClearAck() {
}


/*
 * WaitErrorAck state.
 *
 * This state belongs to the "error handling state overlay" and handle
 * ErrorAck message. Most of the ZRTP states can send Error message for
 * example if they detect wrong packets. After sending an Error message
 * the protocol engine switches to WaitErrorAck state. Receiving an
 * ErrorAck message completes the ZRTP error handling.
 *
 * When entering this transition function
 * - sentPacket contains Error packet, Error timer active
 *
 * Possible events in this state are:
 * - timeout for sent Error packet: causes a resend check and repeat sending
 *   of Error packet
 * - ErrorAck: Stop timer and switch to state Initial.
 */

void ZrtpStateEngineImpl::evWaitErrorAck() {
    LOGGER(VERBOSE, "Enter ", __func__)

    if (event->type == ZrtpPacket) {
        /*
         * Errorck:
         * - stop resending Error,
         * - switch to state Initial
         */
        if (msgType == ErrorAckMsg) {
            cancelTimer();
            sentPacket = nullptr;
            nextState(Initial);
        }
    }
        // Timer event triggered - this is Timer T2 to resend Error.
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();                 // returns to state Initial
            return;
        }
        retryCounters[ErrorRetry]++;

        if (nextTimer(&T2) <= 0) {
            timerFailed(SevereTooMuchRetries);     // returns to state Initial
        }
    } else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = nullptr;
        nextState(Initial);
    }
}

void ZrtpStateEngineImpl::evSecureState() {
    LOGGER(VERBOSE, "Enter ", __func__)
    /*
     * Handle a possible sub-state. If sub-state handling was ok just return.
     */
    if (secSubState == WaitSasRelayAck) {
        if (subEvWaitRelayAck())
            return;
    }

    if (event->type == ZrtpPacket) {

        /*
         * Confirm2:
         * - resend Conf2Ack packet
         * - stay in state
         */
        if (msgType == Confirm2Msg) {
            if (sentPacket != nullptr && !parent->sendPacketZRTP(sentPacket)) {
                sentPacket = nullptr;
                nextState(Initial);
                parent->srtpSecretsOff(ForSender);
                parent->srtpSecretsOff(ForReceiver);
                parent->zrtpNegotiationFailed(Severe, SevereCannotSend);
            }
            return;
        }
        /*
         * GoClear received, handle it.
         *
        if (first == 'g' && last == 'r') {
            ZrtpPacketGoClear gpkt(pkt);
            ZrtpPacketClearAck* clearAck = parent->prepareClearAck(&gpkt);

            if (!parent->sendPacketZRTP(clearAck)) {
                return;
            }
        }
        */
    } else if (event->type == Timer) {
        // Ignore stray timeout in this state
    }
        // unknown Event type for this state (covers Error and ZrtpClose)
    else {
        // If in secure state ignore error events to avoid Error packet injection
        // attack - found by Dmitry Monakhov (dmonakhov@openvz.org)
        if (event->type == ErrorPkt)
            return;
        sentPacket = nullptr;
        parent->srtpSecretsOff(ForSender);
        parent->srtpSecretsOff(ForReceiver);
        nextState(Initial);
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        parent->sendInfo(Info, InfoSecureStateOff);
    }
}

bool ZrtpStateEngineImpl::subEvWaitRelayAck() {
    LOGGER(VERBOSE, "Enter ", __func__)
    /*
     * First check the general event type, then discriminate the real event.
     */
    if (event->type == ZrtpPacket) {
        /*
         * SAS relayAck:
         * - stop resending SASRelay,
         * - switch to secure substate Normal
         */
        if (msgType == RelayAckMsg) {
            cancelTimer();
            secSubState = Normal;
            sentPacket = nullptr;
        }
        return true;
    }
        // Timer event triggered - this is Timer T2 to resend Error.
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed(); // returns to state Initial
            return false;
        }
        // returns to state initial if timer is <= 0
        // timerFailed(ZrtpCodes.SevereCodes.SevereTooMuchRetries);
        return nextTimer(&T2) > 0;
    }
    return false;
}

int32_t ZrtpStateEngineImpl::startTimer(zrtpTimer_t *t) {

    t->time = t->start;
    t->counter = 0;
    return parent->activateTimer(t->time);
}

int32_t ZrtpStateEngineImpl::nextTimer(zrtpTimer_t *t) {

    t->time += t->time;
    t->time = (t->time > t->capping) ? t->capping : t->time;
    if (t->maxResend > 0) {
        t->counter++;
        if (t->counter > t->maxResend) {
            return -1;
        }
    }
    return parent->activateTimer(t->time);
}

void ZrtpStateEngineImpl::sendErrorPacket(uint32_t errorCode) {
    LOGGER(VERBOSE, "Enter ", __func__)
    cancelTimer();

    ZrtpPacketError *err = parent->prepareError(errorCode);
    parent->zrtpNegotiationFailed(ZrtpError, errorCode);

    sentPacket = err;
    nextState(WaitErrorAck);
    if (!parent->sendPacketZRTP(err) || (startTimer(&T2) <= 0)) {
        sendFailed();
    }
}

void ZrtpStateEngineImpl::sendSASRelay(ZrtpPacketSASrelay *relay) {
    cancelTimer();
    sentPacket = relay;
    secSubState = WaitSasRelayAck;
    if (!parent->sendPacketZRTP(relay) || (startTimer(&T2) <= 0)) {
        sendFailed();
    }
}

void ZrtpStateEngineImpl::sendFailed() {
    sentPacket = nullptr;
    nextState(Initial);
    parent->zrtpNegotiationFailed(Severe, SevereCannotSend);
}

void ZrtpStateEngineImpl::timerFailed(int32_t subCode) {
    sentPacket = nullptr;
    nextState(Initial);
    parent->zrtpNegotiationFailed(Severe, subCode);
}

int ZrtpStateEngineImpl::getNumberOfRetryCounters() {
    return sizeof(retryCounters) / sizeof(int32_t);
}

int ZrtpStateEngineImpl::getRetryCounters(int32_t *counters) {
    memcpy(counters, retryCounters, sizeof(retryCounters));
    return sizeof(retryCounters) / sizeof(int32_t);
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
