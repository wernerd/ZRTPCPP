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

#include "ZrtpCurve41417.h"
#include "Ec41417Group.h"

namespace Botan {

    namespace {

        /**
         * Curve41417 operation
         */
        class Curve41417_KA_Operation final : public PK_Ops::Key_Agreement {
        public:

            Curve41417_KA_Operation(const Curve41417_PrivateKey &key, const std::string &kdf) :
                    PK_Ops::Key_Agreement(),
                    m_key(key),
                    m_group(key.domain()) {}

            [[nodiscard]] size_t agreed_value_size() const override { return 52; }

            secure_vector<uint8_t> agree(size_t key_len,
                                         const uint8_t other_key[], size_t other_key_len,
                                         const uint8_t salt[], size_t salt_len) override
            {

                auto x = BigInt::decode(&other_key[1], 52);
                auto y = BigInt::decode(&other_key[52+1], 52);
                Point41417p pubPoint(x, y, 1);                  // The public point uses affine coordinates

                std::vector<BigInt> ws(Point41417p::WORKSPACE_SIZE);
                auto resultPoint = m_group.point_multiply(pubPoint, m_key.private_value(), ws);
                auto affineXY = resultPoint.getAffineXY();
                auto affinePntDouble = Botan::Point41417p(affineXY.first, affineXY.second, 1);

                if(!affinePntDouble.on_the_curve())
                    throw Illegal_Point("ECDH 41417 agreed point is not on the curve");

                auto secret = BigInt::encode_1363(affineXY.first, m_group.get_p_bytes());
                return secret;
            }

        private:
            const Curve41417_PrivateKey &m_key;
            EC41417_Group m_group;
        };

    }

    Curve41417_PrivateKey::Curve41417_PrivateKey(RandomNumberGenerator & rng, const BigInt& x)
    {
        if (x == 0) {
            m_private_key = m_domain_params.random_scalar(rng);
        }
        else {
            m_private_key = x;
        }
        std::vector<BigInt> ws;
        m_public = m_domain_params.base_point_multiply(m_private_key, ws);
    }

    std::unique_ptr<PK_Ops::Key_Agreement>
    Curve41417_PrivateKey::create_key_agreement_op(RandomNumberGenerator & /*rng*/,
                                                   const std::string &params,
                                                   const std::string &provider) const
    {
        if (provider == "base" || provider.empty())
            return std::unique_ptr<PK_Ops::Key_Agreement>(new Curve41417_KA_Operation(*this, params));
        throw Provider_Not_Found(algo_name(), provider);
    }

    secure_vector<uint8_t>
    Curve41417_PrivateKey::private_key_bits() const { return {}; }

    bool
    Curve41417_PrivateKey::check_key(RandomNumberGenerator &rng, bool strong) const { return false; }

    // Optimized for use in ZRTP: the protocol exchanges affine raw X/Y coordinates
    Curve41417_PublicKey::Curve41417_PublicKey(uint8_t *otherKey) {
        auto x = BigInt::decode(&otherKey[0], 52);
        auto y = BigInt::decode(&otherKey[52], 52);

        // Set other key's affine x/y coordinates
        m_public = Point41417p(x, y, 1);
    }

    bool
    Curve41417_PublicKey::check_key(RandomNumberGenerator &rng, bool strong) const {
        return domain().verify_public_element(m_public);
    }

    std::vector<uint8_t>
    Curve41417_PublicKey::public_key_bits() const { return {}; }

}
