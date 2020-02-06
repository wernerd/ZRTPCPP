//
// Created by werner on 07.06.16.
//

#ifndef LIBZINALOTL_UTILITIES_H
#define LIBZINALOTL_UTILITIES_H

/**
 * @file
 * @brief Some utility and helper functions
 * @ingroup Zina
 * @{
 */


#include <sys/types.h>
#include <string>
#include <vector>
#include <memory>
#include <cstring>

#include "typedefs.h"
#include "osSpecifics.h"

namespace zrtp {
    /**
     * @brief Class with static helper functions only.
     */
    class __EXPORT Utilities {

    public:

        constexpr static uint64_t MINUTE_AS_USEC = 60 * 1000000ULL;

        /**
         * @brief Splits a string around matches of the given delimiter character.
         *
         * Trailing empty strings are not included in the resulting array.
         * This function works similar to the Java string split function, however it does
         * not support regular expressions, only a simple delimiter character.
         *
         * @param data The std::string to split
         * @param delimiter The delimiter character
         * @return A vector of strings
         */
        static std::unique_ptr<std::vector<std::string> > splitString(const std::string& data, const std::string& delimiter);
        
        /**
         * @brief get the current time in milliseconds.
         *
         * @return The time in milliseconds
         */
        static int64_t currentTimeMillis();

        /**
         * @brief Wipe a string.
         *
         * Fills the internal buffer of a string with zeros.
         *
         * @param toWipe The string to wipe.
         */
        static void wipeString(std::string &toWipe);

        /**
         * @brief Wipe memory.
         *
         * Fills a data buffer with zeros.
         *
         * @param data pointer to the data buffer.
         * @param length length of the data buffer in bytes
         */
        static inline void wipeMemory(void* data, size_t length) {
            static void * (*volatile memset_volatile)(void *, int, size_t) = std::memset;
            memset_volatile(data, 0, length);
        }

        /**
         * Functions to load in network (big) endian format
         *
         * @param ptr Array that contains the data in network order
         * @return Value
         */
        static uint64_t load64(const uint8_t* ptr);

        static uint32_t load32(const uint8_t* ptr);

        static uint16_t load16(const uint8_t* ptr);


        /**
         * Functions to store in network (big) endian format
         *
         * @param ptr Array to store the data in network order
         * @param val data to store in array
         */
        static void store64(uint64_t val, uint8_t *ptr);

        static void store32(uint32_t val, uint8_t *ptr);

        static void store16(uint16_t val, uint8_t *ptr);

        /**
         * @brief Returns a string with current date and Time, formatted according to ISO8601.
         *
         * The function uses Zulu (GMT) time, not the local time, as input to generate the string.
         * Example of a formatted string: 2016-08-30T13:09:17Z
         *
         * @return A formatted string with current Zulu time.
         */
        static std::string getIsoTimeUtc() { return getIsoTimeUtc(time(nullptr)); }

        /**
         * @brief Returns a string with date and Time, formatted according to ISO8601.
         *
         * The function uses Zulu (GMT) time, not the local time, as input to generate the string.
         * Example of a formatted string: 2016-08-30T13:09:17Z
         *
         * @param theTime the time in seconds
         * @return A formatted string with current Zulu time.
         */
        static std::string getIsoTimeUtc(time_t theTime);

        /**
         * @brief Returns a string with current date and time with milliseconds, formatted according to ISO8601.
         *
         * The function uses Zulu (GMT) time, not the local time, as input to generate the string.
         * Example of a formatted string: 2016-08-30T13:09:17.122Z
         *
         * @return A formatted string with current Zulu time.
         */
        static std::string getIsoTimeUtcMs() { return getIsoTimeUtcMs(currentTimeMillis()); }

        /**
         * @brief Returns a string with date and Time with milliseconds, formatted according to ISO8601.
         *
         * The function uses Zulu (GMT) time, not the local time, as input to generate the string.
         * Example of a formatted string: 2016-08-30T13:09:17.122Z
         *
         * @param theTime the time in milliseconds
         * @return A formatted string with current Zulu time.
         */
        static std::string getIsoTimeUtcMs(int64_t theTime);

        /**
         * @brief Computes the difference of two unsigned integers and returns a signed integer.
         *
         * If the differnce exceeds the `limit` value, then the function returns the limit. The limit
         * value is an absolute value (unsigned), the returned value is signed. The limit value must
         * be less or equal to system defined INT64_MAX
         *
         * @param first first unsigned value
         * @param second second unsinged value
         * @param limit limit of difference
         * @return difference as signed integer
         */
        static int64_t getDifference(uint64_t first, uint64_t second, uint64_t limit);

        // Small functions to dump binary data as readable hex values, debugging for hases, encrypted data, etc
        static StringUnique hexdump(const char *title, const unsigned char *s, size_t l);

        static StringUnique hexdump(const std::string &title, const std::string &in) {
                return hexdump(title.c_str(), (uint8_t*)in.data(), in.size());
        }

        static bool isUuid(const std::string& mayBeUuid) {
            return Utilities::splitString(mayBeUuid, "-")->size() == 5;
        }

        static std::string uriDecode(std::string const & sSrc);

        static std::string uriEncode(std::string const & sSrc);
    };
}

/**
 * @}
 */
#endif //LIBZINALOTL_UTILITIES_H
