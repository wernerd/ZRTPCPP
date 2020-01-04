/*
Copyright 2016 Silent Circle, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//
// Created by werner on 07.06.16.
//

#include <cstring>
#include <ctime>
#include <cassert>
#include <chrono>
#include "Utilities.h"

using namespace std;
using namespace zrtp;


unique_ptr<vector<string> >
Utilities::splitString(const string& data, const string& delimiter)
{
    auto result = make_unique<vector<string> >();

    if (data.empty() || (delimiter.empty() || delimiter.size() > 1)) {
        return result;
    }
    string copy(data);

    size_t pos = 0;
    while ((pos = copy.find(delimiter)) != string::npos) {
        string token = copy.substr(0, pos);
        copy.erase(0, pos + 1);
        result->push_back(token);
    }
    if (!copy.empty()) {
        result->push_back(copy);
    }

    size_t idx = result->empty() ? 0: result->size() - 1;
    while (idx != 0) {
        if (result->at(idx).empty()) {
            result->pop_back();
            idx--;
        }
        else
            break;
    }
    return result;
}

int64_t
Utilities::currentTimeMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void
Utilities::wipeString(string &toWipe)
{
    // This append is necessary: the GCC C++ string implementation uses shared strings, reference counted. Thus
    // if we set the data buffer to 0 then all other references are also cleared. Appending a blank forces the string
    // implementation to really copy the string and we can set the contents to 0. string.clear() does not clear the
    // contents, just sets the length to 0 which is not good enough.
    toWipe.append(" ");
    wipeMemory((void*)toWipe.data(), toWipe.size());
    toWipe.clear();
}

uint64_t Utilities::load64(const uint8_t* const ptr)
{
    uint64_t retval =   ((uint64_t) ptr[0]<<56U)
                      | ((uint64_t) ptr[1]<<48U)
                      | ((uint64_t) ptr[2]<<40U)
                      | ((uint64_t) ptr[3]<<32U)
                      | ((uint64_t) ptr[4]<<24U)
                      | ((uint64_t) ptr[5]<<16U)
                      | ((uint64_t) ptr[6]<< 8U)
                      | ((uint64_t) ptr[7]);
    return retval;
}

uint32_t Utilities::load32(const uint8_t* const ptr)
{
    uint32_t retval = ((uint32_t)ptr[0]<<24U) | ((uint32_t)ptr[1]<<16U) | ((uint32_t)ptr[2]<<8U) | ptr[3];
    return retval;
}

uint16_t Utilities::load16(const uint8_t* const ptr)
{
    uint16_t retval = ((uint32_t)ptr[0]<<8U) | ptr[1];
    return retval;
}

void Utilities::store64(uint64_t val, uint8_t *ptr)
{
    *ptr++ = (uint8_t)(val>>56U);
    *ptr++ = (uint8_t)(val>>48U);
    *ptr++ = (uint8_t)(val>>40U);
    *ptr++ = (uint8_t)(val>>32U);
    *ptr++ = (uint8_t)(val>>24U);
    *ptr++ = (uint8_t)(val>>16U);
    *ptr++ = (uint8_t)(val>> 8U);
    *ptr = (uint8_t)val;
}

void Utilities::store32(uint32_t val, uint8_t *ptr)
{
    *ptr++ = (uint8_t)(val>>24U);
    *ptr++ = (uint8_t)(val>>16U);
    *ptr++ = (uint8_t)(val>> 8U);
    *ptr = (uint8_t)val;
}

void Utilities::store16(uint16_t val, uint8_t *ptr)
{
    *ptr++ = (uint8_t)(val>> 8U);
    *ptr = (uint8_t)val;
}

string
Utilities::getIsoTimeUtc(time_t theTime)
{
    static char dateFormat[] = "%FT%TZ";
    struct tm timeInfo = {0};
    char dateBuffer[200];

    strftime(dateBuffer, sizeof(dateBuffer), dateFormat, gmtime_r(&theTime, &timeInfo));
    return string(dateBuffer);
}

string
Utilities::getIsoTimeUtcMs(int64_t theTime)
{
    const char dateFormat[] = "%FT%T";
    struct tm timeInfo = {0};
    char dateBuffer[200];
    char outBuffer[200];

    int32_t ms = theTime % 1000;
    time_t seconds = theTime / 1000;

    strftime(dateBuffer, sizeof(dateBuffer), dateFormat, gmtime_r(&seconds, &timeInfo));
    snprintf(outBuffer, sizeof(outBuffer), "%s.%03dZ", dateBuffer, ms);

    return string(outBuffer);
}

StringUnique
Utilities::hexdump(const char* title, const unsigned char *s, size_t l) {
    char hexBuffer[2000] = {0};

    if (s == nullptr) return make_unique<string>();     // return an empty string

    auto len = sprintf(hexBuffer, "%s",title);
    for (size_t n = 0; n < l; ++n) {
        if ((n%16) == 0) len += sprintf(hexBuffer+len, "\n%04x",static_cast<int>(n));

        len += sprintf(hexBuffer+len, " %02x",s[n]);
        if (len > 1953) break;
    }
    len += sprintf(hexBuffer+len, "\n");
    return make_unique<string>(hexBuffer, len);
}

int64_t
Utilities::getDifference(uint64_t first, uint64_t second, uint64_t limit) {
    assert(limit <= INT64_MAX);
    uint64_t absDiff = (first > second) ? (first - second): (second - first);
    absDiff = (absDiff > limit) ? limit : absDiff;
    return (first > second) ? (int64_t)absDiff : -(int64_t)absDiff;
}

// Uri encode and decode.
// RFC1630, RFC1738, RFC2396

static constexpr char HEX2DEC[256] = {
                /*       0  1  2  3   4  5  6  7   8  9  A  B   C  D  E  F */
                /* 0 */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127,
                /* 1 */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127,
                /* 2 */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127,
                /* 3 */  0,  1,  2,  3,   4,  5,  6,  7,   8,  9, 127,127, 127,127,127,127,

                /* 4 */ 127, 10, 11, 12,  13, 14, 15,127, 127,127,127,127, 127,127,127,127,
                /* 5 */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127,
                /* 6 */ 127, 10, 11, 12,  13, 14, 15,127, 127,127,127,127, 127,127,127,127,
                /* 7 */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127,

                /* 8 */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127,
                /* 9 */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127,
                /* A */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127,
                /* B */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127,

                /* C */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127,
                /* D */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127,
                /* E */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127,
                /* F */ 127,127,127,127, 127,127,127,127, 127,127,127,127, 127,127,127,127
        };

std::string
Utilities::uriDecode(std::string const & sSrc)
{
    // Note from RFC1630:  "Sequences which start with a percent sign
    // but are not followed by two hexadecimal characters (0-9, A-F) are reserved
    // for future extension"

    auto * pSrc = (const unsigned char *)sSrc.c_str();
    const int SRC_LEN = sSrc.length();
    const unsigned char * const SRC_END = pSrc + SRC_LEN;
    const unsigned char * const SRC_LAST_DEC = SRC_END - 2;   // last decodable '%'

    vector<char> decoded;
    decoded.reserve(SRC_LEN);

    while (pSrc < SRC_LAST_DEC)
    {
        if (*pSrc == '%')
        {
            char dec1, dec2;
            if ((dec1 = HEX2DEC[*(pSrc + 1)]) != 127 && (dec2 = HEX2DEC[*(pSrc + 2)]) != 127) {
                decoded.push_back((dec1 << 4) + dec2);
                pSrc += 3;
                continue;
            }
        }

        decoded.push_back(*pSrc++);
    }
    // the last 2- chars
    while (pSrc < SRC_END) {
        decoded.push_back(*pSrc++);
    }

    std::string sResult(decoded.begin(), decoded.end());
    return sResult;
}

// Only alphanum is safe.
static constexpr char SAFE[256] = {
                /*      0 1 2 3  4 5 6 7  8 9 A B  C D E F */
                /* 0 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                /* 1 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                /* 2 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                /* 3 */ 1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0,

                /* 4 */ 0,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
                /* 5 */ 1,1,1,1, 1,1,1,1, 1,1,1,0, 0,0,0,0,
                /* 6 */ 0,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
                /* 7 */ 1,1,1,1, 1,1,1,1, 1,1,1,0, 0,0,0,0,

                /* 8 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                /* 9 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                /* A */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                /* B */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,

                /* C */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                /* D */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                /* E */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                /* F */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
        };

std::string
Utilities::uriEncode(std::string const & sSrc)
{
    const char DEC2HEX[16 + 1] = "0123456789ABCDEF";
    auto * pSrc = (const unsigned char *)sSrc.c_str();
    const int SRC_LEN = sSrc.length();
    const unsigned char * const SRC_END = pSrc + SRC_LEN;

    vector<char> encoded;
    encoded.reserve(SRC_LEN*3);

    for (; pSrc < SRC_END; ++pSrc)
    {
        if (SAFE[*pSrc]) {
            encoded.push_back(*pSrc);
        }
        else {
            // escape this char
            encoded.push_back('%');
            encoded.push_back(DEC2HEX[*pSrc >> 4]);
            encoded.push_back(DEC2HEX[*pSrc & 0x0F]);
        }
    }
    std::string sResult(encoded.begin(), encoded.end());
    return sResult;
}
