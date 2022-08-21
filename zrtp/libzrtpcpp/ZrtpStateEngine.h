//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Created by werner on 19.08.22.
// Copyright (c) 2022 Werner Dittmann. All rights reserved.
//

#ifndef LIBZRTPCPP_ZRTPSTATECLASSX_H
#define LIBZRTPCPP_ZRTPSTATECLASSX_H

struct Event;

class ZrtpStateEngine {

public:

    virtual ~ZrtpStateEngine() = default;

    /// Check if in a specified state
    [[nodiscard]] virtual bool inState(int32_t state) const = 0;

    /// Process an event, the main entry point into the state engine
    virtual void processEvent(Event * ev) = 0;

    /**
     * Prepare and send an Error packet.
     *
     * Preparse an Error packet and sends it. It stores the Error
     * packet in the sentPacket variable to enable resending. The
     * method switches to protocol state Initial.
     */
    virtual void sendErrorPacket(uint32_t errorCode) = 0;

    /**
     * Set the resend counter of timer T1 - T1 controls the Hello packets.
     */
    virtual void setT1Resend(int32_t counter) = 0;

    /**
     * Set the time capping of timer T1 - T1 controls the Hello packets.
     */
    virtual void setT1Capping(int32_t capping) = 0;

    /**
     * Set the extended resend counter of timer T1 - T1 controls the Hello packets.
     *
     * More retries to extend time, see chap. 6
     */
    virtual void setT1ResendExtend(int32_t counter) = 0;

    /**
     * Set the resend counter of timer T2 - T2 controls other (post-Hello) packets.
     */
    virtual void setT2Resend(int32_t counter) = 0;

    /**
     * Set the time capping of timer T2 - T2 controls other (post-Hello) packets.
     */
    virtual void setT2Capping(int32_t capping) = 0;

    /**
     * @brief Get required buffer size to get all 32-bit retry counters
     *
     * @return number of 32 bit integer elements required or < 0 on error
     */
    virtual int getNumberOfRetryCounters() = 0;

    /**
     * @brief Read retry counters
     *
     * @param counters Pointer to buffer of 32-bit integers. The buffer must be able to
     *         hold at least getNumberOfRetryCounters() 32-bit integers
     *
     * @return number of 32-bit counters returned in buffer or < 0 on error
     */
    virtual int getRetryCounters(int32_t* counters) = 0;

    /**
     * Set length in bytes of transport over head, default is @c RTP_HEADER_LENGTH
     *
     * State engine uses this overhead length to validate the packet length of a ZRTP
     * packet including the transport header/footer. For example overhead of RTP is
     * 12 bytes (RTP header) and this is also the default value that the ZRTP state
     * engine uses.
     *
     * @param overhead
     */
    virtual void setTransportOverhead(int32_t overhead) = 0;

    /**
     * Set multi-stream mode flag.
     *
     * This functions set the multi-stream mode. The protocol
     * engine will run the multi-stream mode variant of the ZRTP
     * protocol if this flag is set to true.
     *
     * @param multi
     *    Set the multi-stream mode flag to true or false.
     */
    virtual void setMultiStream(bool multi) = 0;

};

#endif //LIBZRTPCPP_ZRTPSTATECLASSX_H
