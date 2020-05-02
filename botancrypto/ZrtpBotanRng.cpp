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

#include <cryptcommon/ZrtpRandom.h>
#include <common/Utilities.h>
#include "ZrtpBotanRng.h"

ZrtpBotanRng::ZrtpBotanRng()
{
    // just to call add entropy, buffer may contain some data, whatever is currently on the stack.
    // ZrtpRandom::addEntropy initializes the RNG, adds first set of seed etc.
    // ZrtpRandom is thread safe.
    uint8_t someBuffer[128];
    ZrtpRandom::addEntropy(someBuffer, 128);
}

void ZrtpBotanRng::randomize(uint8_t output[], size_t length)
{
    ZrtpRandom::getRandomData(output, static_cast<uint32_t>(length));
}

void ZrtpBotanRng::add_entropy(const uint8_t input[], size_t length)
{
    ZrtpRandom::addEntropy(input, static_cast<uint32_t>(length));
}

void ZrtpBotanRng::randomize_with_input(uint8_t output[], size_t output_len,
                                        const uint8_t input[], size_t input_len)
{
    ZrtpRandom::addEntropy(input, static_cast<uint32_t>(input_len));
    ZrtpRandom::getRandomData(output, static_cast<uint32_t>(output_len));
}

void ZrtpBotanRng::randomize_with_ts_input(uint8_t output[], size_t output_len)
{
    auto timeStamp = zrtp::Utilities::currentTimeMillis();
    add_entropy_T(timeStamp);
    ZrtpRandom::getRandomData(output, static_cast<uint32_t>(output_len));
}
