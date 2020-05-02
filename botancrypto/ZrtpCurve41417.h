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

#ifdef BOTAN_AMAL
#include "botan_all.h"
#endif

#include "botancrypto/ZrtpBotanRng.h"
#include "botancrypto/Ec41417Group.h"
#include "botancrypto/Point41417.h"


namespace Botan {

    class BOTAN_PUBLIC_API(2, 0) Curve41417_PublicKey : public virtual Public_Key {
    public:
        std::string algo_name() const override { return "Curve41417"; }

        size_t estimated_strength() const override { return 256; }

        size_t key_length() const override { return 52 * 8; }

        AlgorithmIdentifier algorithm_identifier() const override { return AlgorithmIdentifier(); }

        bool check_key(RandomNumberGenerator &rng, bool strong) const override;

        std::vector<uint8_t> public_key_bits() const override;

        std::vector<uint8_t> public_value() const { return m_public.encode(Point41417p::UNCOMPRESSED); }

        /**
         * Get the domain parameters of this key.
         */
        const EC41417_Group& domain() const { return m_domain_params; }

    protected:
        Curve41417_PublicKey() = default;
        ~Curve41417_PublicKey() override = default;

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
        Curve41417_PrivateKey(RandomNumberGenerator &rng, const BigInt& x = 0);

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
