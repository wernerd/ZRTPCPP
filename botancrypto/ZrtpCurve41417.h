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
// Created by werner on 19.04.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#ifndef LIBZRTPCPP_ZRTPCURVE41417_H
#define LIBZRTPCPP_ZRTPCURVE41417_H

#include "botan_all.h"
#include "botancrypto/ZrtpBotanRng.h"
#include "botancrypto/Ec41417Group.h"
#include "botancrypto/Point41417.h"

namespace Botan {

    class BOTAN_PUBLIC_API(2, 0) Curve41417_PublicKey : public virtual Public_Key {
    public:

        static constexpr size_t COORDINATE_BYTES = 52;

        explicit Curve41417_PublicKey(uint8_t *otherKey);

        ~Curve41417_PublicKey() override = default;

        std::string algo_name() const override { return "Curve41417"; }

        size_t estimated_strength() const override { return 256; }

        size_t key_length() const override { return COORDINATE_BYTES * 8; }

        AlgorithmIdentifier algorithm_identifier() const override { return {}; }

        bool check_key(RandomNumberGenerator &rng, bool strong) const override;

        std::vector<uint8_t> public_key_bits() const override;

        /**
         * @return public point value, uncompressed format
         */
        std::vector<uint8_t> public_value() const { return m_public.encode(Point41417p::UNCOMPRESSED); }

        /**
         * @return public point value encoded to `format`
         */
        std::vector<uint8_t> public_value(Point41417p::Compression_Type format) const {
            return m_public.encode(format);
        }

        /**
         * @brief Compute decompressed X/Y-coordinates.
         *
         * @param compressedData compressed Y-coordinate with leading format byte (2 or 3)
         * @param coordinates decompressed X/Y coordinates with leading format byte (4)
         * @return false if decompression failed
         */
        static bool decompress_y_coordinate(uint8_t const * compressedData, std::vector<uint8_t> & coordinates);

        /**
         * Get the domain parameters of this key.
         */
        const EC41417_Group& domain() const { return m_domain_params; }

    protected:
        Curve41417_PublicKey() = default;

        Point41417p m_public;
        EC41417_Group m_domain_params;

    };

    class BOTAN_PUBLIC_API(2, 0) Curve41417_PrivateKey final : public Curve41417_PublicKey,
                                                               public virtual Private_Key,
                                                               public virtual PK_Key_Agreement_Key {
    public:
        /**
         * Generate a private key.
         *
         * @param rng the RNG to use
         */
        explicit Curve41417_PrivateKey(RandomNumberGenerator &rng, const BigInt& x = 0);

        ~Curve41417_PrivateKey() override = default;

        std::vector<uint8_t> public_value() const override { return Curve41417_PublicKey::public_value(); }

        secure_vector<uint8_t> private_key_bits() const override;

        bool check_key(RandomNumberGenerator &rng, bool strong) const override;

        const BigInt& private_value() const
        {
            if(m_private_key == 0)
                throw Invalid_State("EC41417_PrivateKey::private_value - uninitialized");

            return m_private_key;
        }


        std::unique_ptr<PK_Ops::Key_Agreement>
        create_key_agreement_op(RandomNumberGenerator &rng,
                                const std::string &params,
                                const std::string &provider) const override;

    private:
        BigInt m_private_key;
    };

}
#endif //LIBZRTPCPP_ZRTPCURVE41417_H
