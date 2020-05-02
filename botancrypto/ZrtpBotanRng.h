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

#ifndef LIBZRTPCPP_ZRTPBOTANRNG_H
#define LIBZRTPCPP_ZRTPBOTANRNG_H

#ifdef BOTAN_AMAL
#include "botan_all.h"
#else
#include <botan/rng.h>
#endif

class ZrtpBotanRng : public Botan::RandomNumberGenerator {

public:
    ZrtpBotanRng();

    ~ZrtpBotanRng() override = default;

    void randomize(uint8_t output[], size_t length) override;

    [[nodiscard]] bool accepts_input() const override { return true;}

    void add_entropy(const uint8_t input[], size_t length) override;

    void randomize_with_input(uint8_t output[], size_t output_len,
                                      const uint8_t input[], size_t input_len) override ;

    void randomize_with_ts_input(uint8_t output[], size_t output_len) override ;

    [[nodiscard]] std::string name() const override { return "ZRTP_RNG"; }

    void clear() override {}

    [[nodiscard]] bool is_seeded() const override { return true;}

    size_t reseed(Botan::Entropy_Sources& srcs,
                  size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS,
                  std::chrono::milliseconds poll_timeout = BOTAN_RNG_RESEED_DEFAULT_TIMEOUT) override { return 42; }

    void reseed_from_rng(RandomNumberGenerator& rng,
                         size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS) override {  }

};


#endif //LIBZRTPCPP_ZRTPBOTANRNG_H
