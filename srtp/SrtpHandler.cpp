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
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <cstdio>               // Keep it -> compiling with mingw (Windows) complains if not included here
#include <cstring>
#include <cstdint>

#include <common/osSpecifics.h>

#include "srtp/SrtpHandler.h"
#include "srtp/CryptoContext.h"
#include "srtp/CryptoContextCtrl.h"

bool SrtpHandler::decodeRtp(uint8_t* buffer, size_t length, uint32_t *ssrc, uint16_t *seq, uint8_t** payload, int32_t *payloadlen)
{
    volatile size_t offset;
    uint16_t *pus;
    uint32_t *pui;

    /* Assume RTP header at the start of buffer. */

    if ((*buffer & 0xC0U) != 0x80) {         // check version bits
        return false;
    }
    if (length < RTP_HEADER_LENGTH)
        return false;

    /* Get some handy pointers */
    pus = (uint16_t*)buffer;
    pui = (uint32_t*)buffer;

    *seq = zrtpNtohs(pus[1]);                        // and return in host oder
    *ssrc = zrtpNtohl(pui[2]);                       // and return in host order

    /* Payload is located right after header plus CSRC */
    int32_t numCC = buffer[0] & 0x0fU;           // lower 4 bits in first byte is num of contrib SSRC
    offset = RTP_HEADER_LENGTH + (numCC * sizeof(uint32_t));

    // Sanity check
    if (offset > length)
        return false;

    /* Adjust payload offset if RTP extension is used. */
    if ((*buffer & 0x10U) == 0x10) {             // packet contains RTP extension
        pus = (uint16_t*)(buffer + offset);     // pus points to extension as 16bit pointer
        offset += (zrtpNtohs(pus[1]) + 1) * sizeof(uint32_t);
    }
    /* Sanity check */
    if (offset > length)
        return false;

    /* Set payload and payload length. */
    *payload = buffer + offset;
    *payloadlen = length - offset;

    return true;
}

static void fillErrorData(SrtpErrorData* data, SrtpErrorType type, uint8_t* buffer, size_t length, uint64_t guessedIndex)
{
    data->errorType = type;
    memcpy((void*)data->rtpHeader, (void*)buffer, RTP_HEADER_LENGTH);
    data->length = length;
    data->guessedIndex = guessedIndex;
}

bool SrtpHandler::protect(CryptoContext* pcc, uint8_t* buffer, size_t length, size_t* newLength)
{
    uint8_t* payload = nullptr;
    int32_t payloadlen = 0;
    uint16_t seqnum;
    uint32_t ssrc;


    if (pcc == nullptr) {
        return false;
    }
    if (!decodeRtp(buffer, length, &ssrc, &seqnum, &payload, &payloadlen))
        return false;

    /* Encrypt the packet */
    uint64_t index = ((uint64_t)pcc->getRoc() << 16U) | (uint64_t)seqnum;

    pcc->srtpEncrypt(buffer, payload, payloadlen, index, ssrc);

    // NO MKI support yet - here we assume MKI is zero. To build in MKI
    // take MKI length into account when storing the authentication tag.

    /* Compute MAC and store at end of RTP packet data */
    if (pcc->getTagLength() > 0) {
        pcc->srtpAuthenticate(buffer, length, pcc->getRoc(), buffer+length);
    }
    *newLength = length + pcc->getTagLength();

    /* Update the ROC if necessary */
    if (seqnum == 0xFFFF ) {
        pcc->setRoc(pcc->getRoc() + 1);
    }
    return true;
}

int32_t SrtpHandler::unprotect(CryptoContext* pcc, uint8_t* buffer, size_t length, size_t* newLength, SrtpErrorData* errorData)
{
    uint8_t* payload = nullptr;
    int32_t payloadlen = 0;
    uint16_t seqnum;
    uint32_t ssrc;

    if (pcc == nullptr) {
        return 0;
    }

    if (!decodeRtp(buffer, length, &ssrc, &seqnum, &payload, &payloadlen)) {
        if (errorData != nullptr)
            fillErrorData(errorData, DecodeError, buffer, length, 0);
        return 0;
    }
    /*
     * This is the setting of the packet data when we come to this point:
     *
     * length:      complete length of received data
     * buffer:      points to data as received from network
     * payloadlen:  length of data excluding hdrSize and padding
     *
     * Because this is an SRTP packet we need to adjust some values here.
     * The SRTP MKI and authentication data is always at the end of a
     * packet. Thus compute the positions of this data.
     */
    uint32_t srtpDataIndex = length - (pcc->getTagLength() + pcc->getMkiLength());

    // Compute new length
    length -= pcc->getTagLength() + pcc->getMkiLength();
    *newLength = length;

    // recompute payload length by subtracting SRTP data
    payloadlen -= pcc->getTagLength() + pcc->getMkiLength();

    // MKI is unused, so just skip it
    // const uint8* mki = buffer + srtpDataIndex;
    uint8_t* tag = buffer + srtpDataIndex + pcc->getMkiLength();

    /* Guess the index */
    uint64_t guessedIndex = pcc->guessIndex(seqnum);

    /* Replay control */
    if (!pcc->checkReplay(seqnum)) {
        if (errorData != nullptr)
            fillErrorData(errorData, ReplayError, buffer, length, guessedIndex);
        return -2;
    }

    if (pcc->getTagLength() > 0) {
        uint32_t guessedRoc = guessedIndex >> 16U;
        uint8_t mac[20];

        pcc->srtpAuthenticate(buffer, (uint32_t)length, guessedRoc, mac);
        if (memcmp(tag, mac, pcc->getTagLength()) != 0) {
            if (errorData != nullptr)
                fillErrorData(errorData, AuthError, buffer, length, guessedIndex);
            return -1;
        }
    }
    /* Decrypt the content */
    pcc->srtpEncrypt(buffer, payload, payloadlen, guessedIndex, ssrc);

    /* Update the Crypto-context */
    pcc->update(seqnum);

    return 1;
}


bool SrtpHandler::protectCtrl(CryptoContextCtrl* pcc, uint8_t* buffer, size_t length, size_t* newLength)
{

    if (pcc == nullptr) {
        return false;
    }
    /* Encrypt the packet */
    uint32_t ssrc = *(reinterpret_cast<uint32_t*>(buffer + 4)); // always SSRC of sender
    ssrc = zrtpNtohl(ssrc);

    uint32_t encIndex = pcc->getSrtcpIndex();
    pcc->srtcpEncrypt(buffer + 8, length - 8, encIndex, ssrc);

    encIndex |= 0x80000000;                                     // set the E flag

    // Fill SRTCP index as last word
    auto* ip = reinterpret_cast<uint32_t*>(buffer+length);
    *ip = zrtpHtonl(encIndex);

    // NO MKI support yet - here we assume MKI is zero. To build in MKI
    // take MKI length into account when storing the authentication tag.

    // Compute MAC and store in packet after the SRTCP index field
    pcc->srtcpAuthenticate(buffer, length, encIndex, buffer + length + sizeof(uint32_t));

    encIndex++;
    encIndex &= ~0x80000000;                                // clear the E-flag and modulo 2^31
    pcc->setSrtcpIndex(encIndex);
    *newLength = length + pcc->getTagLength() + sizeof(uint32_t);

    return true;
}

int32_t SrtpHandler::unprotectCtrl(CryptoContextCtrl* pcc, uint8_t* buffer, size_t length, size_t* newLength)
{

    if (pcc == nullptr) {
        return 0;
    }

    // Compute the total length of the payload
    int32_t payloadLen = length - (pcc->getTagLength() + pcc->getMkiLength() + 4);
    *newLength = payloadLen;

    // point to the SRTCP index field just after the real payload
    const uint32_t* index = reinterpret_cast<uint32_t*>(buffer + payloadLen);

    uint32_t encIndex = zrtpNtohl(*index);
    uint32_t remoteIndex = encIndex & ~0x80000000;    // get index without Encryption flag

    if (!pcc->checkReplay(remoteIndex)) {
       return -2;
    }

    uint8_t mac[20];

    // Now get a pointer to the authentication tag field
    const uint8_t* tag = buffer + (length - pcc->getTagLength());

    // Authenticate includes the index, but not MKI and not (obviously) the tag itself
    pcc->srtcpAuthenticate(buffer, payloadLen, encIndex, mac);
    if (memcmp(tag, mac, pcc->getTagLength()) != 0) {
        return -1;
    }

    uint32_t ssrc = *(reinterpret_cast<uint32_t*>(buffer + 4)); // always SSRC of sender
    ssrc = zrtpNtohl(ssrc);

    // Decrypt the content, exclude the very first SRTCP header (fixed, 8 bytes)
    if (encIndex & 0x80000000)
        pcc->srtcpEncrypt(buffer + 8, payloadLen - 8, remoteIndex, ssrc);

    // Update the Crypto-context
    pcc->update(remoteIndex);

    return 1;
}

