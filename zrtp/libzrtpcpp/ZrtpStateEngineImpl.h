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

#ifndef _ZRTPSTATECLASS_H_
#define _ZRTPSTATECLASS_H_

/**
 * @file ZrtpStateEngineImpl.h
 * @brief The ZRTP state handling class
 *
 * @ingroup ZRTP
 * @{
 */

#include "libzrtpcpp/ZrtpStateEngine.h"
#include "libzrtpcpp/ZRtp.h"
#include "libzrtpcpp/ZrtpStates.h"
#include "libzrtpcpp/ZrtpPacketBase.h"

/**
 * The ZRTP states
 *
 * Depending on the role of this state engine and the actual protocl flow
 * not all states are processed during a ZRTP handshake.
 */
enum zrtpStates {
    Initial,            ///< Initial state after starting the state engine
    Detect,             ///< State sending Hello, try to detect answer message
    AckDetected,        ///< HelloAck received
    AckSent,            ///< HelloAck sent after Hello received
    WaitCommit,         ///< Wait for a Commit message
    WaitDHPart1,        ///< Commit message sent
    WaitDHPart2,        ///< Wait for a DHPart2 message
    WaitConfirm1,       ///< Wait for a Confirm1 message
    WaitConfirm2,       ///< Wait for a confirm2 message
    WaitConfAck,        ///< Wait for Conf2Ack
    WaitClearAck,       ///< Wait for clearAck - not used
    SecureState,        ///< This is the secure state - SRTP active
    WaitErrorAck,       ///< Wait for ErrorAck message
    numberOfStates      ///< Gives total number of protocol states
};

enum EventDataType {
    NoEvent = 0,
    ZrtpInitial = 1,    ///< Initial event, enter Initial state
    ZrtpClose,          ///< Close event, shut down state engine
    ZrtpPacket,         ///< Normal ZRTP message event, process according to state
    Timer,              ///< Timer event
    ErrorPkt            ///< Error packet event
};

enum SecureSubStates {
    Normal,
    WaitSasRelayAck,
    numberOfSecureSubStates
};

/// A ZRTP state event
struct Event {
    Event(): type(NoEvent), length(0), packet(nullptr) {}

    EventDataType type; ///< Type of event
    size_t   length;    ///< length of the message data
    uint8_t const * packet;    ///< Event data if available, usually a ZRTP message
};


/**
 * The ZRTP timer structure.
 *
 * This structure holds all necessary data to compute the timer for
 * the protocol timers. The state engine allocate one structure for
 * each timer. ZRTP uses two timers, T1 and T2, to monitor protocol
 * timeouts. As a slight misuse but to make overall handling a bit
 * simpler this structure also contains the resend counter. This is
 * possible in ZRTP because it uses a simple timeout strategy.
 */
typedef struct zrtpTimer {
    int32_t time,       ///< Current timeout value
    start,              ///< Start value for timeout
    increment,          ///< increment timeout after each timeout event (not used anymore)
    capping,            ///< Maximum timeout value
    counter,            ///< Current number of timeouts
    maxResend;          ///< Maximum number of timeout resends
} zrtpTimer_t;


class ZRtp;

/**
 * This class is the ZRTP protocol state engine.
 *
 * This class is responsible to handle the ZRTP protocol. It does not
 * handle the ZRTP HMAC, DH, and other data management. This is done in
 * class ZRtp, which is the parent of this class.
 *
 * The methods of this class implement the ZRTP state actions.
 *
 */


class __EXPORT ZrtpStateEngineImpl : public ZrtpStateEngine {

private:
    ZRtp * parent;                           ///< The ZRTP implementation
    ZrtpStates * engine = nullptr;           ///< The state switching engine
    Event * event = nullptr;                 ///< Current event to process

    static state_t states[numberOfStates];
    /**
     * The last packet that was sent.
     *
     * If we are <code>Initiator</code> then resend this packet in case of
     * timeout.
     */
    ZrtpPacketBase* sentPacket = nullptr;

    /**
     * Points to prepared Commit packet after receiving a Hello packet
     */
    ZrtpPacketCommit* commitPkt;

    zrtpTimer_t T1 = {};         ///< The Hello message timeout timer
    zrtpTimer_t T2 = {};         ///< Timeout timer for other messages

    int32_t t1Resend;       ///< configurable resend counter for T1 (Hello packets)
    int32_t t1ResendExtend; ///< configurable extended resend counter for T1 (Hello packets)
    int32_t t2Resend;       ///< configurable resend counter for T2 (other packets)

    std::string msgType;

    /*
     * If this is set to true the protocol engine handle the multi-stream
     * variant of ZRTP. Refer to chapter 5.4.2 in the ZRTP specification.
     */
    bool multiStream;

    // Secure sub-state to handle SAS relay packets
    SecureSubStates secSubState;

    /**
     * Secure Sub state WaitSasRelayAck.
     *
     * This state belongs to the secure substates and handles
     * SAS Relay Ack. 
     *
     * When entering this transition function
     * - sentPacket contains Error packet, Error timer active
     *
     * Possible events in this state are:
     * - timeout for sent SAS Relay packet: causes a resend check and repeat sending
     *   of packet
     * - SASRelayAck: Stop timer and switch to secure substate Normal.
     */
    bool subEvWaitRelayAck();

    /**
     * Hello packet version sent to other partner
     */
    int32_t sentVersion;
    
    int32_t retryCounters[ErrorRetry+1] = {0};  // TODO adjust

    int32_t transportOverhead = RTP_HEADER_LENGTH;

    bool isZrtp2022Supported = false;

public:
    // region ZrtpStateEngine functions

    explicit ZrtpStateEngineImpl(ZRtp *p);

    ~ZrtpStateEngineImpl() override;

    [[nodiscard]] bool inState(const int32_t state) const override { return engine->inState(state); };

    void processEvent(Event * ev) override;

    void sendErrorPacket(uint32_t errorCode) override;

    void setT1Resend(int32_t counter) override {T1.maxResend = counter;}

    void setT1Capping(int32_t capping) override {T1.capping = capping;}

    void setT1ResendExtend(int32_t counter) override {t1ResendExtend = counter;}

    void setT2Resend(int32_t counter) override {T2.maxResend = counter;}

    void setT2Capping(int32_t capping) override {T2.capping = capping;}

    int getNumberOfRetryCounters() override;

    int getRetryCounters(int32_t* counters) override;

    void setTransportOverhead(int32_t overhead) override { transportOverhead = overhead; }

    void setMultiStream(bool multi) override { multiStream = multi; }

    void setZrtp2022(bool supported) override { isZrtp2022Supported = supported; };
    // endregion
private:
    /// Switch to the specified state
    void nextState(int32_t state)        { engine->nextState(state); };

    /**
     * The state event handling methods.
     *
     * Refer to the protocol state diagram for further documentation.
     */
    /// Initial event state
    void evInitial();

    /// Detect state
    void evDetect();

    /// HelloAck detected state
    void evAckDetected();

    /// HelloAck sent state
    void evAckSent();

    /// Wait for Commit message
    void evWaitCommit();

    /// Commit sent state
    void evWaitDHPart1();

    /// Wait for DHPart2 message
    void evWaitDHPart2();

    /// Wait for Confirm2 message
    void evWaitConfirm1();

    /// Wait for Confirm2 message
    void evWaitConfirm2();

    /// Wait for ConfAck message
    void evWaitConfAck();

    /// Wait for ClearAck message (not used)
    void evWaitClearAck();

    /// Secure reached state
    void evSecureState();

    /// Wait for ErrorAck message
    void evWaitErrorAck();

    /**
     * Initialize and activate a timer.
     *
     * @param t
     *    The ZRTP timer structure to use for the timer.
     * @return
     *    1 timer was activated
     *    0 activation failed
     */
    int32_t startTimer(zrtpTimer_t *t);

    /**
     * Compute and set the next timeout value.
     *
     * @param t
     *    The ZRTP timer structure to use for the timer.
     * @return
     *    1 timer was activated
     *    0 activation failed
     *   -1 resend counter exceeded
     */
    int32_t nextTimer(zrtpTimer_t *t);

    /**
     * Cancel the active timer.
     *
     * @return
     *    1 timer was canceled
     *    0 timer cancel failed
     */
    int32_t cancelTimer() {return parent->cancelTimer(); };

    void adjustT2Sidh(int32_t adjustedStart) { T2.start = adjustedStart; }

    /**
     * Set status if an error occurred while sending a ZRTP packet.
     *
     * This functions clears data and set the state to Initial after the engine
     * detected a problem while sending a ZRTP packet.
     *
     * @return
     *    Fail code
     */
    void sendFailed();

    /**
     * Set status if a timer problems occurs.
     *
     * This functions clears data and set state to Initial after a timer
     * error occurred. Either no timer available or resend counter excesded.
     *
     * @return
     *    Fail code
     */
    void timerFailed(int32_t subCode);

    /**
     * Status of multi-stream mode flag.
     *
     * This functions returns the value of the multi-stream mode flag.
     *
     * @return
     *    Value of the multi-stream mode flag.
     */
    [[maybe_unused]] bool isMultiStream() { return multiStream; };

    /**
     * Send a SAS relay packet.
     *
     * the functions stores sends the SAS relay packet and stores the pointer in
     * the sentPacket variable to enable resending.
     *
     * The method switches to secure substate WaitSasRelayAck.
     * 
     * @param relay
     *    Pointer to the SAS relay packet.
     */
    void sendSASRelay(ZrtpPacketSASrelay* relay);

};

/**
 * @}
 */
#endif // _ZRTPSTATECLASS_H_

