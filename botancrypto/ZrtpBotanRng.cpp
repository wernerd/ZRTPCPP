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
// Created by werner on 17.04.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//


#include <fcntl.h>
#include <mutex>
#include <cstring>
#include <array>

#if !(defined(_WIN32) || defined(_WIN64))
#include <unistd.h>
#endif

#if defined(_WINDOWS)
#include <windows.h>
#include <ntsecapi.h>
#endif

#include <common/Utilities.h>
#include <common/osSpecifics.h>
#include "ZrtpBotanRng.h"

#if defined(EMSCRIPTEN)
#include <emscripten.h>
#endif

static std::mutex lockRandom;

static bool initialized = false;

static std::unique_ptr<Botan::HashFunction> hashMain;

ZrtpBotanRng::ZrtpBotanRng()
{
    // just to call add entropy, buffer may contain some data, whatever is currently on the stack.
    // ZrtpRandom::addEntropy initializes the RNG, adds first set of seed etc.
    // ZrtpRandom is thread safe.
    uint8_t someBuffer[128];
    addEntropy(someBuffer, 128);
}

void ZrtpBotanRng::randomize(uint8_t output[], size_t length)
{
    getRandomData(output, static_cast<uint32_t>(length));
}

void ZrtpBotanRng::add_entropy(const uint8_t input[], size_t length)
{
    addEntropy(input, static_cast<uint32_t>(length));
}

void ZrtpBotanRng::randomize_with_input(uint8_t output[], size_t output_len,
                                        const uint8_t input[], size_t input_len)
{
    addEntropy(input, static_cast<uint32_t>(input_len));
    getRandomData(output, static_cast<uint32_t>(output_len));
}

void ZrtpBotanRng::randomize_with_ts_input(uint8_t output[], size_t output_len)
{
    auto timeStamp = zrtp::Utilities::currentTimeMillis();
    add_entropy_T(timeStamp);
    getRandomData(output, static_cast<uint32_t>(output_len));
}


/*
 * memset_volatile is a volatile pointer to the memset function.
 * You can call (*memset_volatile)(buf, val, len) or even
 * memset_volatile(buf, val, len) just as you would call
 * memset(buf, val, len), but the use of a volatile pointer
 * guarantees that the compiler will not optimise the call away.
 */
static void * (*volatile memset_volatile)(void *, int, size_t) = memset;

/*
 * Random bits are produced as follows.
 * First stir new entropy into the random state (zrtp->rand_ctx).
 * Then make a copy of the random context and finalize it.
 * Use the digest to seed an AES-256 context and, if space remains, to
 * initialize a counter.
 * Then encrypt the counter with the AES-256 context, incrementing it
 * per block, until we have produced the desired quantity of data.
 */
/*----------------------------------------------------------------------------*/
uint32_t ZrtpBotanRng::getRandomData(uint8_t* buffer, uint32_t length) {

    auto aes = Botan::BlockCipher::create_or_throw("AES-256");
    std::unique_ptr<Botan::HashFunction> hashInternal;

    uint8_t    md[SHA512_DIGEST_LENGTH];
    uint8_t    ctr[Botan::AES_256::BLOCK_SIZE];
    uint8_t    rdata[Botan::AES_256::BLOCK_SIZE];
    uint32_t   generated = length;

    /*
     * Add entropy from system state
     * We will include whatever happens to be in the buffer, it can't hurt
     */
    lockRandom.lock();
    ZrtpBotanRng::addEntropy(buffer, length, true);

    /* Copy the mainCtx and finalize it into the md buffer */
    hashInternal = hashMain->copy_state();
    hashInternal->final(md);

    lockRandom.unlock();

    /* Key an AES crypto from hash output buffer */
    aes->set_key(md, 32);

    /* Initialize counter, using excess from md if available */
    memset (ctr, 0, sizeof(ctr));
    uint32_t ctrbytes = SHA512_DIGEST_LENGTH - (256 / 8);
    if (ctrbytes > Botan::AES_256::BLOCK_SIZE)
        ctrbytes = Botan::AES_256::BLOCK_SIZE;
    memcpy(ctr + sizeof(ctr) - ctrbytes, md + (256 / 8), ctrbytes);

    /* Encrypt counter, copy to destination buffer, increment counter */
    while (length) {
        uint8_t *ctrptr;
        uint32_t copied;
        aes->encrypt(ctr, rdata);
        copied = (sizeof(rdata) < length) ? sizeof(rdata) : length;
        memcpy (buffer, rdata, copied);
        buffer += copied;
        length -= copied;

        /* Increment counter */
        ctrptr = ctr + sizeof(ctr) - 1;
        while (ctrptr >= ctr) {
            if ((*ctrptr-- += 1) != 0) {
                break;
            }
        }
    }
    hashInternal->clear();
    aes->clear();
    memset_volatile(md, 0, sizeof(md));
    memset_volatile(ctr, 0, sizeof(ctr));
    memset_volatile(rdata, 0, sizeof(rdata));

    return generated;
}


uint32_t ZrtpBotanRng::addEntropy(const uint8_t *buffer, uint32_t length, bool isLocked)
{

    std::array<uint8_t, 64> newSeed {};
    size_t len = getSystemSeed(newSeed);

    if (!isLocked) lockRandom.lock();

    initialize();

    if (buffer && length) {
        hashMain->update(buffer, length);
    }
    if (len > 0) {
        hashMain->update(newSeed.data(), len);
        length += len;
    }
    if (!isLocked) lockRandom.unlock();

    return length;
}


void ZrtpBotanRng::initialize() {
    if (initialized)
        return;

    hashMain = Botan::HashFunction::create_or_throw("SHA-512");
    initialized = true;
}

/*
 * This works for Linux and similar systems. For other systems add
 * other functions (using #ifdef conditional compile) to get some
 * random data that we can use as seed for the internal PRNG below.
 */

size_t ZrtpBotanRng::getSystemSeed(std::array<uint8_t, 64>& seed)
{
    size_t num = 0;

#if !(defined(_WIN32) || defined(_WIN64) || defined(EMSCRIPTEN))
    int rnd = open("/dev/urandom", O_RDONLY);
    if (rnd >= 0) {
        num = read(rnd, seed.data(), seed.size());
        close(rnd);
    }
    // Code was copied from ZrtpRandom.cpp, commit 24f240931279501e71bf78b5033f23deecbc828f
#elif defined(EMSCRIPTEN)
    for (int i = 0; i < length; ++i) {
        seed[i] = EM_ASM_INT_V(
                  var bytes;
            if (typeof Module.browserifyCrypto !== 'undefined') {
                 var crypto = Module.browserifyCrypto;
                 var byte = crypto.randomByte();
                 return byte;
            }
            else if (typeof Module.browserCrypto !== 'undefined') {
                bytes = new Uint8Array(1);
                Module.browserCrypto.getRandomValues(bytes);
            }
            else if (ENVIRONMENT_IS_NODE) {
                 var crypto = require('crypto');
                 bytes = crypto.randomBytes(1);
            }
            return bytes[0];
        );
    }
    num = length;
#elif defined(_WIN32) || defined(_WIN64)
    //--------------------------------------------------------------------
    // Generate a random initialization vector.

    if (RtlGenRandom(seed, length)) {
        return static_cast<size_t >(length);
    }
    else {
        return 0;
    }
#else
#error Unknown system - getSystemSeed function not defined for this system
#endif
    return num;
}

uint32_t zrtp_AddEntropy(const uint8_t *buffer, uint32_t length, int isLocked) {
    return ZrtpBotanRng::addEntropy(buffer, length, isLocked != 0);
}

uint32_t zrtp_getRandomData(uint8_t *buffer, uint32_t length) {
    return ZrtpBotanRng::getRandomData(buffer, length);
}
