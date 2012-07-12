/*
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
*/
#include <stdint.h>

class CryptoContext;
class CryptoContextCtrl;

/**
 * SRTP and SRTCP protect and unprotect functions.
 *
 * The functions of this take a uint8_t buffer that must contain an RTP packet. The
 * functions also assume that the buffer contains all protocol relevant fields
 * (SSRC, sequence number etc.) in network order.
 *
 * When encrypting the buffer must big enough to store additional data, usually
 * 10 bytes if the application set the full authentication length (80 bit).
 *
 * All public functions expect the length of the input buffer in the @c length
 * parameter and the functions return the new length in parameter @c newLength.
 * 
 */
class SrtpHandler
{
public:
    static bool protect(CryptoContext* pcc, uint8_t* buffer, size_t length, size_t* newLength);

    static int32_t unprotect(CryptoContext* pcc, uint8_t* buffer, size_t length, size_t* newLength);

    static bool protectCtrl(CryptoContextCtrl* pcc, uint8_t* buffer, size_t length, size_t* newLength, uint32_t *srtcpIndex);

    static int32_t unprotectCtrl(CryptoContextCtrl* pcc, uint8_t* buffer, size_t length, size_t* newLength);

//private:
    static bool decodeRtp(uint8_t* buffer, int32_t length, uint32_t *ssrc, uint16_t *seq, uint8_t** payload, int32_t *payloadlen);

};