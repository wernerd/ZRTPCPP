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

#ifndef LIBZRTPCPP_EC41417GROUP_H
#define LIBZRTPCPP_EC41417GROUP_H

#include "botan_all.h"

#include "botancrypto/ZrtpBotanRng.h"

namespace Botan {

    class Point41417p;
    class EC41417_Group_Data;

    /**
     * Class representing an 41417 elliptic curve
     *
     * The internal representation is stored in a shared_ptr, so copying an
     * EC_Group is inexpensive.
     */
    class BOTAN_PUBLIC_API(2, 0) EC41417_Group final {
    public:
        /**
        * Create an EC41417_Group with 41417 domain data.
        */
        EC41417_Group();

        ~EC41417_Group() = default;

        EC41417_Group(const EC41417_Group &) = default;

        EC41417_Group(EC41417_Group &&) = default;

        EC41417_Group &operator=(const EC41417_Group &) = default;

        EC41417_Group &operator=(EC41417_Group &&) = default;

        /**
        * Create the DER encoding of this domain
        * @param form of encoding to use
        * @returns bytes encododed as DER
        */
//        std::vector<uint8_t> DER_encode(EC41417_Group_Encoding form) const;

        /**
        * Return the PEM encoding (always in explicit form)
        * @return string containing PEM data
        */
//        std::string PEM_encode() const;

        /**
        * Return if a == 0 mod p
        */
        bool a_is_zero() const;

        /**
        * Return the size of p in bits (same as get_p().bits())
        */
        size_t get_p_bits() const;

        /**
        * Return the size of p in bytes (same as get_p().bytes())
        */
        [[nodiscard]] size_t get_p_bytes() const;

        /**
        * Return the size of group order in bits (same as get_order().bits())
        */
        size_t get_order_bits() const;

        /**
        * Return the size of p in bytes (same as get_order().bytes())
        */
        size_t get_order_bytes() const;

        /**
        * Return the prime modulus of the field
        */
        [[nodiscard]] const BigInt &get_p() const;

        /**
        * Return the a parameter of the elliptic curve equation
        */
        [[nodiscard]] const BigInt &get_a() const;

        /**
        * Return the b parameter of the elliptic curve equation
        */
        const BigInt &get_b() const;

        /**
        * Return group base point
        * @result base point
        */
        [[nodiscard]] const Point41417p &get_base_point() const;

        /**
        * Return the x coordinate of the base point
        */
        [[nodiscard]] const BigInt &get_g_x() const;

        /**
        * Return the y coordinate of the base point
        */
        [[nodiscard]] const BigInt &get_g_y() const;

        /**
        * Return the order of the base point
        * @result order of the base point
        */
        [[nodiscard]] const BigInt &get_order() const;

        /*
        * Reduce x modulo the prime
        */
        [[nodiscard]] BigInt mod_prime(const BigInt &x) const;

        /*
        * Return inverse of x modulo the prime
        */
        [[nodiscard]] BigInt inverse_mod_prime(const BigInt &x) const;

        /*
        * Reduce (x*x) modulo the prime
        */
        [[nodiscard]] BigInt square_mod_prime(const BigInt &x) const;

        /*
        * Reduce (x*y) modulo the prime
        */
        [[nodiscard]] BigInt multiply_mod_prime(const BigInt &x, const BigInt &y) const;

        /*
        * Reduce (x*y*z) modulo the prime
        */
        [[nodiscard]] BigInt multiply_mod_prime(const BigInt &x, const BigInt &y, const BigInt &z) const;

        /**
        * Return the cofactor
        * @result the cofactor
        */
        [[nodiscard]] const BigInt &get_cofactor() const;

        /**
        * Check if y is a plausible point on the curve
        *
        * In particular, checks that it is a point on the curve, not infinity,
        * and that it has order matching the group.
        */
        [[nodiscard]] bool verify_public_element(const Point41417p &y) const ;

        /**
        * Return a point on this curve with the affine values x, y
        */
        [[nodiscard]] Point41417p point(const BigInt &x, const BigInt &y) const;

        /**
        * Base point multiplication
        * @param k the scalar
        * @param ws a temp workspace
        * @return base_point*k
        */
        Point41417p base_point_multiply(const BigInt &k, std::vector<BigInt> &ws) const;

        /**
        * Point multiplication
        * @param point input point
        * @param k the scalar
        * @param ws a temp workspace
        * @return point*k
        */
        Point41417p point_multiply(const Point41417p &point, const BigInt &k, std::vector<BigInt> &ws) const;

        /**
        * Return a random scalar suitable as private key for curve 41417.
        */
        BigInt random_scalar(RandomNumberGenerator &rng) const;

        /**
        * Return the zero (or infinite) point on this curve
        */
        [[nodiscard]] Point41417p zero_point() const;

        [[nodiscard]] bool initialized() const { return (m_data != nullptr); }

        /**
         * Verify EC41417_Group domain
         * @returns Always returns true - group is fixed
         */
        static bool verify_group(RandomNumberGenerator &rng,
                          bool strong = false) { return true; }

        bool operator==(const EC41417_Group &other) const = delete;

        /**
        * Return PEM representation of named EC group
        * Deprecated: Use EC41417_Group(name).PEM_encode() if this is needed
        */
        static std::string BOTAN_DEPRECATED("See header comment")
        PEM_for_named_group(const std::string &name) { return {}; }

        /**
        * Return a set of known named EC groups
        */
        static const std::set<std::string> &known_named_groups();

    private:

        static std::shared_ptr<EC41417_Group_Data>
        load_EC41417_group_info(const char *p,
                                const char *a,
                                const char *g_x,
                                const char *g_y,
                                const char *order);

        // Member data
        [[nodiscard]] const EC41417_Group_Data &data() const;

        std::shared_ptr<EC41417_Group_Data> m_data;
    };

}
#endif //LIBZRTPCPP_EC41417GROUP_H
