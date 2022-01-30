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

#include "botan_all.h"

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#endif

class ZrtpBotanRng : public Botan::RandomNumberGenerator {

public:
    ZrtpBotanRng();

    ~ZrtpBotanRng() override = default;

    // region implement Botan::RandomNumberGenerator functions
    void randomize(uint8_t output[], size_t length) override;

    [[nodiscard]] bool accepts_input() const override { return true;}

    void add_entropy(const uint8_t input[], size_t length) override;

    void randomize_with_input(uint8_t output[], size_t output_len,
                                      const uint8_t input[], size_t input_len) override ;

    void randomize_with_ts_input(uint8_t output[], size_t output_len) override ;

    [[nodiscard]] std::string name() const override { return "ZRTP_RNG"; }

    void clear() override {}

    [[nodiscard]] bool is_seeded() const override { return true;}

    // Don't use a polling function to do reseed - use `add_entropy` in this implementation
    size_t reseed(Botan::Entropy_Sources& srcs,
                  size_t poll_bit,
                  std::chrono::milliseconds poll_timeout) override { return 42; }

    void reseed_from_rng(RandomNumberGenerator& rng,
                         size_t poll_bits) override {  }

    // endregion

    /**
     * @brief This method adds entropy to the PRNG.
     *
     * An application may seed some entropy data to the PRNG. If the @c buffer is
     * @c NULL or the @c length is zero then the method adds at least some system
     * entropy.
     *
     * @param buffer some entropy data to add
     *
     * @param length length of entropy data in bytes
     *
     * @return on success: number of entropy bytes added, on failure: -1. Number of
     *         bytes added may be bigger then @c length because of added system
     *         entropy.
     */
    static int addEntropy(const uint8_t *buffer, uint32_t length, bool isLocked = false);

    /**
     * @brief Get some random data.
     *
     * @param buffer that will contain the random data
     *
     * @param length how many bytes of random data to generate
     *
     * @return the number of generated random data bytes
     */
    static int32_t getRandomData(uint8_t *buffer, uint32_t length);

private:
    static void initialize();
    static size_t getSystemSeed(uint8_t *seed, size_t length);

};

#ifdef __cplusplus
extern "C"
{
#endif

int zrtp_AddEntropy(const uint8_t *buffer, uint32_t length, int isLocked);

int zrtp_getRandomData(uint8_t *buffer, uint32_t length);

#ifdef __cplusplus
}
#endif


#endif //LIBZRTPCPP_ZRTPBOTANRNG_H
