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

/**
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <iostream>
#include <cstdlib>
#include <ctype.h>

#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpStateClass.h>

using namespace std;

state_t states[numberOfStates] = {
    {Initial,      &ZrtpStateClass::evInitial },
    {Detect,       &ZrtpStateClass::evDetect },
    {AckDetected,  &ZrtpStateClass::evAckDetected },
    {AckSent,      &ZrtpStateClass::evAckSent },
    {WaitCommit,   &ZrtpStateClass::evWaitCommit },
    {CommitSent,   &ZrtpStateClass::evCommitSent },
    {WaitDHPart2,  &ZrtpStateClass::evWaitDHPart2 },
    {WaitConfirm1, &ZrtpStateClass::evWaitConfirm1 },
    {WaitConfirm2, &ZrtpStateClass::evWaitConfirm2 },
    {WaitConfAck,  &ZrtpStateClass::evWaitConfAck },
    {WaitClearAck, &ZrtpStateClass::evWaitClearAck },
    {SecureState,  &ZrtpStateClass::evSecureState },
    {WaitErrorAck, &ZrtpStateClass::evWaitErrorAck }
};


static const char* sendErrorText = "Cannot send data - connection or peer down?";
static const char* timerError = "Cannot start a timer - internal resources exhausted?";
static const char* resendError = "Too much retries during ZRTP negotiation - connection or peer down?";
static const char* internalProtocolError = "Internal protocol error occured!";
static const char* zrtpClosed = "No more security for this session";
static const char* goClearReceived = "Received a GoClear message - no security processing!";

ZrtpStateClass::ZrtpStateClass(ZRtp *p) {
    parent = p;
    engine = new ZrtpStates(states, numberOfStates, Initial);

    commitPkt = NULL;
    // Set up timers according to ZRTP spec
    T1.start = 50;
    T1.maxResend = 20;
    T1.capping = 200;

    T2.start = 150;
    T2.maxResend = 10;
    T2.capping = 600;
}

ZrtpStateClass::~ZrtpStateClass(void) {

    // If not in Initial state: close the protocol engine
    // before destroying it. This will free pending packets
    // if necessary.
    if (!inState(Initial)) {
        Event_t ev;

        cancelTimer();
        ev.type = ZrtpClose;
        event = &ev;
        engine->processEvent(*this);
    }
    delete engine;
}

int32_t ZrtpStateClass::processEvent(Event_t *ev) {

    event = ev;
    char *msg, first, last;
    uint8_t *pkt;

    parent->synchEnter();

    if (event->type == ZrtpPacket) {
	pkt = event->data.packet;
	msg = (char *)pkt + 4;
	first = tolower(*msg);
	last = tolower(*(msg+4));

        // Check if this is an Error packet.
	if (first == 'e' && last =='r') {
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
            ZrtpPacketErrorAck* eapkt = parent->prepareErrorAck(&epkt);
            parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(eapkt));
            event->type = ErrorPkt;
        }
    }
    /*
     * Shut down protocol state engine: cancel outstanding timer, further
     * processing in current state.
     */
    else if (event->type == ZrtpClose) {
        cancelTimer();
    }
    int32_t retval = engine->processEvent(*this);
    parent->synchLeave();
    return retval;
}


int32_t ZrtpStateClass::evInitial(void) {
    DEBUGOUT((cout << "Checking for match in Initial.\n"));

    if (event->type == ZrtpInitial) {
	ZrtpPacketHello* hello = parent->prepareHello();

	// remember packet for easy resend in case timer triggers
	sentPacket = static_cast<ZrtpPacketBase *>(hello);

        if (!parent->sendPacketZRTP(sentPacket)) {
            return sendFailed();                 // returns to state Initial
        }
        if (startTimer(&T1) <= 0) {
            return timerFailed(timerError);      // returns to state Initial
        }
	nextState(Detect);
    }
    return (Done);
}

/**
 * Detect state.
 *
 * When in this state the protocol engine sent an Hello packet to the peer.
 * (sentPacket contains the pointer to Hello packet)
 * When entering this state transition function then:
 * - Assume Initiator mode, mode may change later on peer reaction
 * - Instance variable sentPacket contains the sent Hello packet
 * - Hello timer T1 is active
 *
 * Possible events in this state are: 
 * timeout for sent Hello packet - causes a resend check an possible resend of
 * Hello packet
 * received a Commit - stop active timer, prepare a DHPart1 packet, switch to 
 * Resonder mode
 * received a HelloAck - stop active timer, prepare and send Hello packet.
 * received a Hello - stop active timer, prepare and send Commit packet.
 * 
 * Refer to state event diagram to see which are valid next states.
 */
int32_t ZrtpStateClass::evDetect(void) {

    DEBUGOUT((cout << "Checking for match in Detect.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    /*
     * First check the general event type, then discrimnate
     * the real event.
     */
    if (event->type == ZrtpPacket) {
	pkt = event->data.packet;
	msg = (char *)pkt + 4;

	first = tolower(*msg);
	last = tolower(*(msg+7));
	/*
	 * HelloAck:
         * - our peer acknowledged our Hello packet
	 * - cancel timer T1 to stop resending Hello
	 * - switch to state AckDetected, wait for peer's Hello (F3)
	 */
	if (first == 'h' && last =='k') {
	    cancelTimer();
	    sentPacket = NULL;
	    nextState(AckDetected);
	    return (Done);
	}
        /*
         * Hello:
         * // - stop timer T1.
         * - send HelloAck packet to acknowledge the received Hello packet 
         * - use received Hello packet to prepare own Commit packet. We need to
         *   do it at this point because we need the hash value computed from
         *   peer's Hello packet. Follwing states my use the prepared Commit.
         * - send own Hello packet until peer acknowledges this (state AckSent)
         * //- reactivate and count up timer T1 because our Hello was not yet 
         * //  acknowledged
         * - switch to new state AckSent
         * - Don't clear sentPacket, points to Hello
         */
        if (first == 'h' && last ==' ') {
//            cancelTimer();
            ZrtpPacketHelloAck* helloAck = parent->prepareHelloAck();

            if (!parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(helloAck))) {
                parent->zrtpNegotiationFailed(Error, sendErrorText);
                return(Fail);
            }
            // Use peer's Hello packet to create my commit packet, store it 
            // for possible later usage in state AckSent
            ZrtpPacketHello hpkt(pkt);
            commitPkt = parent->prepareCommit(&hpkt, &errorCode);

            if (commitPkt == NULL) {
                sendErrorPacket(errorCode);    // switches to Error state
                return (Done);
            }
            // maybe we can let the timeout trigger to send the Hello
            /*
            // sentPacket points to own "Hello" packet, send it and restart T1.
            if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();       // returns to state Initial
            }
            // If resend counter exceeds limit stay in state Detect to be 
            // prepared to get an hello from peer any time later.
            if (nextTimer(&T1) <= 0) {
                commitPkt = NULL;
                parent->zrtpNotSuppOther();
                return (Fail);
            }
            */
            nextState(AckSent);
            return (Done);
        }
        return (Done);      // unknown packet for this state - Just ignore it
    }
    // Timer event triggered - this is Timer T1 to resend Hello
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            return sendFailed();       // returns to state Initial
        }
        if (nextTimer(&T1) <= 0) {
            commitPkt = NULL;
            parent->zrtpNotSuppOther();
            nextState(Detect);  // TODO: DetectPassive?
            return (Fail);
        }
        return (Done);
    }
    else { // unknown Event type for this state (covers Error and ZrtpClose)
        parent->sendInfo(Error, internalProtocolError);
	sentPacket = NULL;
	nextState(Initial);
        return (Fail);
    }
}

/*
 * When entering this transition function:
 * Own protocol engine got a Hello packet from peer and answered with a
 * HelloAck/Hello response. The HelloAck acknowledges that the protocol engine
 * got the Hello from the other peer. The other peer can acknowldge the receipt 
 * either with HelloAck or Commit.
 *
 * - sent packet contains own Hello packet
 * - commitPkt points to prepared Commit packet 
 * - Timer T1 is active
 *
 * If T1 triggers the protocol engine resends Hello until the resend counter
 * reaches its maximum.
 *
 * If the protcol engine receives another Hello it repeats the HelloAck/Hello
 * response until Timer T1 exceeds its maximum. This may happen if the other
 * peer sends Hello only (maybe due to network problems)
 */
int32_t ZrtpStateClass::evAckSent(void) {

    DEBUGOUT((cout << "Checking for match in AckSent.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    /*
     * First check the general event type, then discrimnate
     * the real event.
     */
    if (event->type == ZrtpPacket) {
        pkt = event->data.packet;
	msg = (char *)pkt + 4;

	first = tolower(*msg);
	last = tolower(*(msg+7));

	/*
         * HelloAck:
         * The peer answers with HelloAck to own HelloAck/Hello. Try
         * Initiator mode.
	 * - stop Hello timer, clear sentPacket
	 * - send own Commit message, which is already stored in commitPkt
	 * - switch state to CommitSent, start Commit timer, assume Initiator
	 */
	if (first == 'h' && last =='k') {
	    cancelTimer();

            // remember packet for easy resend in case timer triggers
            // Timer trigger received in new state CommitSend
            sentPacket = static_cast<ZrtpPacketBase *>(commitPkt);
            commitPkt = NULL;                    // now stored in sentPacket
            if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();             // returns to state Initial
            }
            if (startTimer(&T2) <= 0) {
                return timerFailed(timerError);  // returns to state Initial
	    }
	    nextState(CommitSent);
	    return (Done);
        }
        /*
         * Hello:
         * - peer missed HelloAck
         * - repeat HelloAck/Hello response:
         *  -- stop timer T1, get HelloAck packet, send it
         *  -- resend Hello packet (pointer from sentPacket)
         *  -- activate and count up timer T1
         *  -- stay in state AckSent
         *
         * Similar to Detect state: just acknowledge the Hello, the next
         * timeout send the following Hello.
         */

        if (first == 'h' && last ==' ') {
//            cancelTimer();
            ZrtpPacketHelloAck *helloAck = parent->prepareHelloAck();

            if (!parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(helloAck))) {
                nextState(Detect);
                parent->zrtpNegotiationFailed(Error, sendErrorText);
                return(Fail);
            }
            /*
            // sentPacket points to Hello packet, resend it
            if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();      // returns to state Initial
            }
            // Back to state Detect if resend counter of T1 exceeds limit. 
            // This may happen if peer never sends a HelloAck
            if (nextTimer(&T1) <= 0) {
                parent->zrtpNotSuppOther();
                commitPkt = NULL;
                // Switch state Detect to be prepared get an hello from
                // other peer any time later
                nextState(Detect);  // TODO: DetectPassive?
                return (Fail);
            }
            */
            return (Done);
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
	if (first == 'c') {
	    ZrtpPacketCommit cpkt(pkt);
	    ZrtpPacketDHPart* dhPart1 = parent->prepareDHPart1(&cpkt, &errorCode);

	    // Error detected during processing of received commit packet
	    if (dhPart1 == NULL) {
                if (errorCode != IgnorePacket) {
                    sendErrorPacket(errorCode);
                }
		return (Done);
	    }
            commitPkt = NULL;
	    sentPacket = NULL;
            cancelTimer();
	    nextState(WaitDHPart2);

            // remember packet for easy resend in new state
	    sentPacket = static_cast<ZrtpPacketBase *>(dhPart1);
	    if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();      // returns to state Initial
	    }
	    return (Done);
	}
    }
    /*
     * Timer:
     * - resend Hello packet, stay in state, restart timer until repeat 
     *   counter triggers
     * - if repeat counter triggers switch to state Detect, con't clear
     *   sentPacket, Detect requires it to point to own Hello message
     */
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            return sendFailed();      // returns to state Initial
	}
        if (nextTimer(&T1) <= 0) {
            parent->zrtpNotSuppOther();
            commitPkt = NULL;
            // Stay in state Detect to be prepared get an hello from
            // other peer any time later
            nextState(Detect);   // TODO: DetectPassive?
            return (Fail);
        }
        return (Done);
    }
    else {   // unknown Event type for this state (covers Error and ZrtpClose)
        parent->sendInfo(Error, internalProtocolError);
        commitPkt = NULL;
	sentPacket = NULL;
	nextState(Initial);
        return (Fail);
    }
}
/*
 * The protocol engine got a peer's HelloAck state Detect, thus the peer got 
 * the Hello. The peer must send its Hello until the protocol engine sees it 
 * in this state and can acknowledge the peer's Hello with a Commit.
 *
 * This protocol sequence gurantees that both peers got the Hello.
 *
 * When entering this transition function
 * - sentPacket is NULL, Hello timer stopped
 */
int32_t ZrtpStateClass::evAckDetected(void) {

    DEBUGOUT((cout << "Checking for match in AckDetected.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    if (event->type == ZrtpPacket) {
	pkt = event->data.packet;
	msg = (char *)pkt + 4;

	first = tolower(*msg);
	last = tolower(*(msg+7));

#if 0
        /*
	 * Hello:
	 * - Acknowledge peers Hello, sending HelloACK (F4)
	 * - switch to state WaitCommit, wait for peer's Commit
         * - we are going to be in the Responder role
	 */

	if (first == 'h') {
            // Parse Hello packet and build an own Commit packet even if the
            // Commit is not send to the peer. We need to do this to check the
            // Hello packet and prepare the shared secret stuff.
            ZrtpPacketHello hpkt(pkt);
            ZrtpPacketCommit* commit = parent->prepareCommit(&hpkt, &errorCode);
            // Something went wrong during processing of the Hello packet, for
            // example wrong version, duplicate ZID.
            if (commit == NULL) {
                sendErrorPacket(errorCode);
                return (Done);
            }
            ZrtpPacketHelloAck *helloAck = parent->prepareHelloAck();
	    nextState(WaitCommit);

	    if (!parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(helloAck))) {
                return sendFailed();
	    }
	    // remember packet for easy resend
	    sentPacket = static_cast<ZrtpPacketBase *>(helloAck);
	    return (Done);
	}
#else
	/*
	 * Hello:
	 * - Acknowledge peers Hello by sending Commit (F5)
         *   instead of HelloAck (F4)
	 * - switch to state CommitSent
         * - Initiator role, thus start timer T2 to monitor timeout for Commit
	 */

        if (first == 'h') {
            // Parse peer's packet data into a Hello packet
            ZrtpPacketHello hpkt(pkt);
            ZrtpPacketCommit* commit = parent->prepareCommit(&hpkt, &errorCode);
            // Something went wrong during processing of the Hello packet  
            if (commit == NULL) {
                sendErrorPacket(errorCode);
                return (Done);
            }
            nextState(CommitSent);

            // remember packet for easy resend in case timer triggers
            // Timer trigger received in new state CommitSend
            sentPacket = static_cast<ZrtpPacketBase *>(commit);
            if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();
            }
            if (startTimer(&T2) <= 0) {
                return timerFailed(timerError);
            }
            return (Done);
        }
#endif
        return (Done);      // unknown packet for this state - Just ignore it
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        parent->sendInfo(Error, internalProtocolError);
	nextState(Initial);
        return (Fail);
    }
}

/*
 * When entering this transition function
 * - Responder mode
 * - sentPacket contains a HelloAck packet
 */
int32_t ZrtpStateClass::evWaitCommit(void) {

    DEBUGOUT((cout << "Checking for match in WaitCommit.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    if (event->type == ZrtpPacket) {
	pkt = event->data.packet;
	msg = (char *)pkt + 4;

	first = tolower(*msg);
	last = tolower(*(msg+7));

	/*
	 * Hello:
	 * - resend HelloAck
	 * - stay in WaitCommit
	 */
	if (first == 'h') {
	    if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();       // returns to state Initial
	    }
	    return (Done);
	}
	/*
	 * Commit:
	 * - prepare DH1Part packet
	 * - send it to peer
	 * - switch state to WaitDHPart2
	 * - don't start timer, we are responder
	 */
	if (first == 'c') {
	    ZrtpPacketCommit cpkt(pkt);
	    ZrtpPacketDHPart* dhPart1 = parent->prepareDHPart1(&cpkt, &errorCode);

            // Something went wrong during processing of the Commit packet
            if (dhPart1 == NULL) {
                if (errorCode != IgnorePacket) {
                    sendErrorPacket(errorCode);
                }
                return (Done);
            }
	    sentPacket = static_cast<ZrtpPacketBase *>(dhPart1);
	    nextState(WaitDHPart2);

	    if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();       // returns to state Initial
	    }
	    return (Done);
	}
        return (Done);      // unknown packet for this state - Just ignore it
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        parent->sendInfo(Error, internalProtocolError);
        sentPacket = NULL;   // Don't delet sent packet - it's a fixed helloack
	nextState(Initial);
        return (Fail);
    }
}

/*
 * When entering this transition function
 * - assume Initiator mode, may change if we reveice a Commit here
 * - sentPacket contains Commit packet
 * - Commit timer (T2) active
 */

int32_t ZrtpStateClass::evCommitSent(void) {

    DEBUGOUT((cout << "Checking for match in CommitSend.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    if (event->type == ZrtpPacket) {
	pkt = event->data.packet;
	msg = (char *)pkt + 4;

	first = tolower(*msg);
	last = tolower(*(msg+7));

        /*
	 * HelloAck or Hello:
	 * - delayed "HelloAck" or "Hello", maybe due to network latency, just 
         *   ignore it
	 * - no switch in state, leave timer as it is
	 */
	if (first == 'h' && (last =='k' || last == ' ')) {
	    return (Done);
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
	if (first == 'c') {
	    ZrtpPacketCommit zpCo(pkt);

            if (!parent->verifyH2(&zpCo)) {
                return(Done);
            }
            sentPacket = NULL;
	    cancelTimer();         // this cancels the Commit timer T2

	    // if our hvi is less than peer's hvi: switch to Responder mode and
            // send DHPart1 packet. Peer (as Initiator) will retrigger if
            // necessary
            //
	    if (parent->compareHvi(&zpCo) < 0) {
		ZrtpPacketDHPart* dhPart1 = parent->prepareDHPart1(&zpCo, &errorCode);

                // Something went wrong during processing of the Commit packet
                if (dhPart1 == NULL) {
                    if (errorCode != IgnorePacket) {
                        sendErrorPacket(errorCode);
                    }
                    return (Done);
                }
                nextState(WaitDHPart2);
		sentPacket = static_cast<ZrtpPacketBase *>(dhPart1);

		if (!parent->sendPacketZRTP(sentPacket)) {
                    return sendFailed();       // returns to state Initial
		}
	    }
	    // Stay in state, we are Initiator, wait for DHPart1 packet from peer.
            // Resend Commit after timeout until we get a DHPart1
	    else {
		if (startTimer(&T2) <= 0) { // restart the Commit timer, gives peer more time to react
                    return timerFailed(timerError);    // returns to state Initial
		}
	    }
	    return (Done);
	}

	/*
	 * DHPart1:
	 * - switch off resending Commit
	 * - Prepare and send DHPart2
	 * - switch to WaitConfirm1
	 * - start timer to resend DHPart2 if necessary, we are Initiator
	 * - switch on SRTP
	 */
	if (first == 'd') {
	    ZrtpPacketDHPart dpkt(pkt);
	    ZrtpPacketDHPart* dhPart2 = parent->prepareDHPart2(&dpkt, &errorCode);

            // Something went wrong during processing of the DHPart1 packet
            if (dhPart2 == NULL) {
                if (errorCode != IgnorePacket) {
                    sendErrorPacket(errorCode);
                }
                return (Done);
            }
	    cancelTimer();
            sentPacket = static_cast<ZrtpPacketBase *>(dhPart2);
	    nextState(WaitConfirm1);

            if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();       // returns to state Initial
            }
            if (startTimer(&T2) <= 0) {
                return timerFailed(timerError);       // returns to state Initial
            }
	}
        return (Done);      // unknown packet for this state - Just ignore it
    }
    // Timer event triggered, resend the Commit packet
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();       // returns to state Initial
        }
        if (nextTimer(&T2) <= 0) {
            return timerFailed(resendError);       // returns to state Initial
        }
        return (Done);
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        parent->sendInfo(Error, internalProtocolError);
	sentPacket = NULL;
	nextState(Initial);
        return (Fail);
    }
}

/*
 * When entering this transition function
 * - sentPacket contains DHPart1 packet, no timer active
 */
int32_t ZrtpStateClass::evWaitDHPart2(void) {

    DEBUGOUT((cout << "Checking for match in DHPart2.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    if (event->type == ZrtpPacket) {
	pkt = event->data.packet;
	msg = (char *)pkt + 4;

	first = tolower(*msg);
	last = tolower(*(msg+7));

	/*
	 * Commit:
	 * - resend DHPart1
	 * - stay in state
	 */
	if (first == 'c') {
	    if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();       // returns to state Initial
	    }
	    return (Done);
	}
	/*
	 * DHPart2:
	 * - prepare Confirm1 packet
	 * - switch to WaitConfirm2
	 * - No timer, we are responder
	 */
	if (first == 'd') {
	    ZrtpPacketDHPart dpkt(pkt);
	    ZrtpPacketConfirm* confirm = parent->prepareConfirm1(&dpkt, &errorCode);

            if (confirm == NULL) {
                if (errorCode != IgnorePacket) {
                    sendErrorPacket(errorCode);
                }
                return (Done);
            }
	    nextState(WaitConfirm2);
	    sentPacket = static_cast<ZrtpPacketBase *>(confirm);

	    if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();       // returns to state Initial
	    }
	}
        return (Done);      // unknown packet for this state - Just ignore it
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        parent->sendInfo(Error, internalProtocolError);
        sentPacket = NULL;
        nextState(Initial);
        return (Fail);
    }
}

/*
 * When entering this transition function
 * - Initiator mode
 * - sentPacket contains DHPart2 packet, DHPart2 timer active
 */
int32_t ZrtpStateClass::evWaitConfirm1(void) {

    DEBUGOUT((cout << "Checking for match in WaitConfirm1.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    if (event->type == ZrtpPacket) {
	pkt = event->data.packet;
	msg = (char *)pkt + 4;

	first = tolower(*msg);
	last = tolower(*(msg+7));

	/*
	 * Confirm1:
	 * - Switch off resending DHPart2
	 * - prepare a Confirm2 packet
	 * - switch to state WaitConfAck
	 * - set timer to monitor Confirm2 packet, we are initiator
	 */
	if (first == 'c' && last == '1') {
            cancelTimer();
	    ZrtpPacketConfirm cpkt(pkt);
	    sentPacket = NULL;

	    ZrtpPacketConfirm* confirm = parent->prepareConfirm2(&cpkt, &errorCode);

            // Something went wrong during processing of the Confirm1 packet
            if (confirm == NULL) {
                sendErrorPacket(errorCode);
                return (Done);
            }
	    nextState(WaitConfAck);

            sentPacket = static_cast<ZrtpPacketBase *>(confirm);
            if (!parent->sendPacketZRTP(sentPacket)) {
                    return sendFailed();         // returns to state Initial
            }
            if (startTimer(&T2) <= 0) {
                return timerFailed(timerError);  // returns to state Initial
            }
	    return (Done);
	}
        return (Done);      // unknown packet for this state - Just ignore it
    }
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();             // returns to state Initial
        }
        if (nextTimer(&T2) <= 0) {
            return timerFailed(resendError);     // returns to state Initial
        }
        return (Done);
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        parent->sendInfo(Error, internalProtocolError);
        sentPacket = NULL;
	nextState(Initial);
        return (Fail);
    }
}

/*
 * When entering this transition function
 * - Responder mode
 * - sentPacket contains Confirm1 packet, no timer active
 * - Security switched on
 */
int32_t ZrtpStateClass::evWaitConfirm2(void) {

    DEBUGOUT((cout << "Checking for match in WaitConfirm2.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    if (event->type == ZrtpPacket) {
	pkt = event->data.packet;
	msg = (char *)pkt + 4;

	first = tolower(*msg);
	last = tolower(*(msg+7));

	/*
	 * DHPart2:
	 * - resend Confirm1 packet via SRTP
	 * - stay in state
	 */
	if (first == 'd') {
	    if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();             // returns to state Initial
	    }
	    return (Done);
	}
	/*
	 * Confirm2:
	 * - prepare ConfAck
	 * - switch on security
	 * - switch to SecureState
	 */
	if (first == 'c' && last == '2') {
	    ZrtpPacketConfirm cpkt(pkt);
	    sentPacket = NULL;
	    ZrtpPacketConf2Ack* confack = parent->prepareConf2Ack(&cpkt, &errorCode);

            // Something went wrong during processing of the confirm2 packet
            if (confack == NULL) {
                sendErrorPacket(errorCode);
                return (Done);
            }
	    nextState(SecureState);
	    sentPacket = static_cast<ZrtpPacketBase *>(confack);

	    if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();             // returns to state Initial
	    }
	    parent->sendInfo(Info, "Switching to secure state");
            // TODO: error handling here ???
            parent->srtpSecretsReady(ForSender);
            parent->srtpSecretsReady(ForReceiver);

	    return (Done);
	}
        return (Done);      // unknown packet for this state - Just ignore it
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        parent->sendInfo(Error, internalProtocolError);
        sentPacket = NULL;
        nextState(Initial);
        return (Fail);
    }
}

/*
 * When entering this transition function
 * - Initiator mode
 * - sentPacket contains Confirm2 packet, Confirm2 timer active
 * - sender and receiver security switched on
 */
int32_t ZrtpStateClass::evWaitConfAck(void) {

    DEBUGOUT((cout << "Checking for match in WaitConfAck.\n"));

    char *msg, first, last;
    uint8_t *pkt;

    if (event->type == ZrtpPacket) {
	pkt = event->data.packet;
	msg = (char *)pkt + 4;

	first = tolower(*msg);
	last = tolower(*(msg+7));

	/*
	 * ConfAck:
	 * - Switch off resending Confirm2
	 * - switch to SecureState
	 */
	if (first == 'c') {
            cancelTimer();
            sentPacket = NULL;
	    parent->sendInfo(Info, "Switching to secure state");
	    nextState(SecureState);
      // TODO: error handling here ??
            parent->srtpSecretsReady(ForSender);
            parent->srtpSecretsReady(ForReceiver);
	    return (Done);
	}
        return (Done);      // unknown packet for this state - Just ignore it
    }
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            parent->srtpSecretsOff(ForSender);
            parent->srtpSecretsOff(ForReceiver);
            return sendFailed();             // returns to state Initial
        }
        if (nextTimer(&T2) <= 0) {
            parent->srtpSecretsOff(ForSender);
            parent->srtpSecretsOff(ForReceiver);
            return timerFailed(resendError);     // returns to state Initial
        }
        return (Done);
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        parent->sendInfo(Error, internalProtocolError);
	sentPacket = NULL;
	nextState(Initial);
        return (Fail);
    }
}

/*
 * When entering this transition function
 * - sentPacket contains GoClear packet, GoClear timer active
 */

int32_t ZrtpStateClass::evWaitClearAck(void) {
    DEBUGOUT((cout << "Checking for match in ClearAck.\n"));

    char *msg, first, last;
    uint8_t *pkt;

    if (event->type == ZrtpPacket) {
	pkt = event->data.packet;
	msg = (char *)pkt + 4;

	first = tolower(*msg);
	last = tolower(*(msg+7));

	/*
	 * ClearAck:
	 * - stop resending GoClear,
	 * - switch to state AckDetected, wait for peer's Hello
	 */
	if (first == 'c' && last =='k') {
	    cancelTimer();
	    sentPacket = NULL;
	    nextState(Initial);
	}
        return (Done);      // unknown packet for this state - Just ignore it
    }
    // Timer event triggered - this is Timer T2 to resend GoClear w/o HMAC
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            return sendFailed();                 // returns to state Initial
        }
        if (nextTimer(&T2) <= 0) {
            return timerFailed(resendError);     // returns to state Initial
        }
        return (Done);
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        parent->sendInfo(Error, internalProtocolError);
	sentPacket = NULL;
	nextState(Initial);
        return (Fail);
    }
}


/*
 * When entering this transition function
 * - sentPacket contains Error packet, Error timer active ?? TODO
 */

int32_t ZrtpStateClass::evWaitErrorAck(void) {
    DEBUGOUT((cout << "Checking for match in ErrorAck.\n"));

    char *msg, first, last;
    uint8_t *pkt;

    if (event->type == ZrtpPacket) {
	pkt = event->data.packet;
	msg = (char *)pkt + 4;

	first = tolower(*msg);
	last = tolower(*(msg+7));

	/*
	 * ClearAck:
	 * - stop resending GoClear,
	 * - switch to state AckDetected, wait for peer's Hello
	 */
	if (first == 'e' && last =='k') {
	    cancelTimer();
	    sentPacket = NULL;
	    nextState(Initial);
	}
        return (Done);
    }
    // Timer event triggered - this is Timer T2 to resend Error.
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            return sendFailed();                 // returns to state Initial
        }
        if (nextTimer(&T2) <= 0) {
            return timerFailed(resendError);     // returns to state Initial
        }
        return (Done);
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        parent->sendInfo(Error, internalProtocolError);
	sentPacket = NULL;
	nextState(Initial);
        return (Fail);
    }
}

int32_t ZrtpStateClass::evSecureState(void) {

    DEBUGOUT((cout << "Checking for match in SecureState.\n"));

    char *msg, first, last;
    uint8_t *pkt;

    if (event->type == ZrtpPacket) {
	pkt = event->data.packet;
	msg = (char *)pkt + 4;

	first = tolower(*msg);
	last = tolower(*(msg+7));

	/*
	 * Confirm2:
	 * - resend Conf2Ack packet
	 * - stay in state
	 */
	if (first == 'c' && last == '2') {
	    if (sentPacket != NULL && !parent->sendPacketZRTP(sentPacket)) {
		sentPacket = NULL;
		nextState(Initial);
                parent->srtpSecretsOff(ForSender);
                parent->srtpSecretsOff(ForReceiver);
		parent->sendInfo(Error, sendErrorText);
		return(Fail);
	    }
	    return (Done);
	}
        /*
         * GoClear received, handle it. TODO fix go clear handling
         */
        if (first == 'g' && last == 'r') {
            ZrtpPacketGoClear gpkt(pkt);
            ZrtpPacketClearAck* clearAck = parent->prepareClearAck(&gpkt);

            if (!parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(clearAck))) {
                return(Done);
            }
        // TODO Timeout to resend clear ack until user user confirmation
        }
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
	sentPacket = NULL;
        parent->srtpSecretsOff(ForSender);
        parent->srtpSecretsOff(ForReceiver);
	nextState(Initial);
	parent->sendInfo(Info, zrtpClosed);
    }
    return (Done);
}

int32_t ZrtpStateClass::startTimer(zrtpTimer_t *t) {

    t->time = t->start;
    t->counter = 0;
    return parent->activateTimer(t->time);
}

int32_t ZrtpStateClass::nextTimer(zrtpTimer_t *t) {

    t->time += t->time;
    t->time = (t->time > t->capping)? t->capping : t->time;
    t->counter++;
    if (t->counter > t->maxResend) {
	return -1;
    }
    return parent->activateTimer(t->time);
}

int32_t ZrtpStateClass::sendErrorPacket(uint32_t errorCode) {
    ZrtpPacketError* err = parent->prepareError(errorCode);

    cancelTimer();
    if (!parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(err)) || (startTimer(&T2) <= 0)) {
        nextState(Initial);
        parent->sendInfo(Error, sendErrorText);
        return (Fail);
    }
    sentPacket =  static_cast<ZrtpPacketBase *>(err);
    nextState(WaitErrorAck);
    return (Done);
}

int32_t ZrtpStateClass::sendFailed() {
    sentPacket = NULL;
    nextState(Initial);
    parent->sendInfo(Error, sendErrorText);
    return(Fail);
}

int32_t ZrtpStateClass::timerFailed(const char* msg) {
    sentPacket = NULL;
    nextState(Initial);
    parent->sendInfo(Error, msg);
    return(Fail);
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
