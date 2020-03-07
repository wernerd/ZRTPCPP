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
// Created by werner on 06.03.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#ifndef LIBZRTPCPP_GENERICPACKETFILTER_H
#define LIBZRTPCPP_GENERICPACKETFILTER_H

/**
 * @file
 * @brief Generic packet filter
 * @defgroup GNU_ZRTP The ZRTP C++ implementation
 * @{
 */

#include <cstdint>
#include <cstddef>
#include <functional>

#include "config.h"

/**
 * @brief Packet filter and implementation of ZRTP callback functions.
 */
class GenericPacketFilter {

public:
    /**
     * @brief Result of packet filter function.
     */
    enum FilterResult {
        Processed,              //!< ZRTP processed the data, no further processing
        Discarded,              //!< Filter discarded the data due to some error, no further processing
        NotProcessed            //!< Not a ZRTP packet, caller should process data,
    };

    /**
     * @brief Result of packet data check function.
     */
    enum DataCheckResult {
        Process,              //!< This is valid ZRTP data, process it
        Discard,              //!< Discard the data: no valid transport protocol packet, but also not a ZRTP packet: no further processing
        DontProcess           //!< Not a ZRTP packet, caller should process data,
    };

    /**
     * @brief Signature of ZRTP packet check function.
     *
     * This functions checks if `packetData` contains valid ZRTP data and returns the
     * offset to the first byte of the ZRTP packet if it's valid ZRTP data. If this is
     * not a valid ZRTP packet the function must return either `DontProcess` or `Discard`
     * and must not change the `offset` parameter.
     *
     * For an RTP packet this is the first byte after the fixed length RTP
     * header (12 bytes). Other transport protocols may have other offsets into
     * the data.
     *
     * This class provides a ready-to-use check function for RTP packet data.
     *
     * @sa checkRtpData(uint8_t const * packetData, size_t packetLength, size_t & offset);
     */
    using CheckFunction = std::function<DataCheckResult(uint8_t const * packetData, size_t packetLength, size_t & offset)>;

    /**
     * @brief Check for ZRTP packet and process it.
     *
     * @param packetData Pointer to the packet data
     * @param packetLength Length of the packet data in bytes
     * @param checkFunction `filterPacket` calls this function to check for ZRTP data.
     * @return FilterResult
     */
    FilterResult filterPacket(uint8_t const * packetData, size_t packetLength, CheckFunction const & checkFunction);

    /**
     * @brief Check if an RTP packet contains valid ZRTP data.
     *
     * This functions checks if `packetData` contains valid ZRTP data and returns a
     * pointer to the first byte of the ZRTP packet. If this is no a valid ZRTP packet
     * the function returns `NotProcessed`.
     *
     * @param packetData Pointer to the packet data
     * @param packetLength Length of the packet data in bytes
     * @param offset Contains offset to first ZRTP byte in packet data if return value is `Process`
     * @return DataCheckResult.
     */
    static DataCheckResult checkRtpData(uint8_t const * packetData, size_t packetLength, size_t & offset);
};

/**
 * @}
 */

#endif //LIBZRTPCPP_GENERICPACKETFILTER_H
