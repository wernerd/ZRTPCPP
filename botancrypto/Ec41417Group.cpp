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

#include <iostream>

#include "Ec41417Group.h"
#include "Point41417.h"

/*
 * The data for Curve41417 copied from:
 * http://safecurves.cr.yp.to/field.html
 * http://safecurves.cr.yp.to/base.html
 *
 * The following parameters are given:
 * - The prime modulus p
 * - The order n
 * - The base point x coordinate Gx
 * - The base point y coordinate Gy
 * - The factor d (3617) -> mapped onto the 'a' curve member of
 *
 * This curve does no require or use the usual a and b parameters as found in the NIST curves
 */
static char const *curve41417[] = {
        "0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffef",  // Prime
        "0x07ffffffffffffffffffffffffffffffffffffffffffffffffffeb3cc92414cf706022b36f1c0338ad63cf181b0e71a5e106af79",  // order
        // 17319886477121189177719202498822615443556957307604340815256226171904769976866975908866528699294134494857887698432266169206165,
        "0x1a334905141443300218c0631c326e5fcd46369f44c03ec7f57ff35498a4ab4d6d6ba111301a73faa8537c64c4fd3812f3cbc595",  // Gx
        "0x22",                                                                                                        // Gy (radix 16)
        "3617",                                                                                                        // a  (radix 10)
};


namespace Botan {

    /**
     * This implementation does not use any optimized code but uses standard algorithms
     * for Edward curves to add or double points. For the purpose of ZRTP the speed is OK
     * because ZRTP performs ECDH computations only once per negotiation/call.
     */
    class EC41417_Group_Data final {
    public:

        EC41417_Group_Data(const BigInt &p,
                           const BigInt &a,
                           const BigInt &g_x,
                           const BigInt &g_y,
                           const BigInt &order,
                           const BigInt &cofactor) :
                m_base_point(g_x, g_y, 1),
                m_p(p),
                m_a(a),
                m_g_x(g_x),
                m_g_y(g_y),
                m_order(order),
                m_cofactor(cofactor),
                m_mod_prime(p),
//                m_base_mult(m_base_point, m_mod_prime),
                m_p_bits(p.bits()),
                m_order_bits(order.bits()) {

//            m_base_point.setPrime(p);
        }

        bool match(const BigInt &p, const BigInt &a, const BigInt &b,
                   const BigInt &g_x, const BigInt &g_y,
                   const BigInt &order, const BigInt &cofactor) const {
            return (this->p() == p &&
                    this->order() == order &&
                    this->cofactor() == cofactor &&
                    this->g_x() == g_x &&
                    this->g_y() == g_y);
        }

        const BigInt &p() const { return m_p; }

        const BigInt &a() const { return m_a; }

        const BigInt &order() const { return m_order; }

        const BigInt &cofactor() const { return m_cofactor; }

        const BigInt &g_x() const { return m_g_x; }

        const BigInt &g_y() const { return m_g_y; }

        size_t p_bits() const { return m_p_bits; }

        size_t p_bytes() const { return (m_p_bits + 7) / 8; }

        size_t order_bits() const { return m_order_bits; }

        size_t order_bytes() const { return (m_order_bits + 7) / 8; }

        const Point41417p &base_point() const { return m_base_point; }

        BigInt mod_prime(const BigInt &x) const { return m_mod_prime.reduce(x); }

        BigInt square_mod_prime(const BigInt &x) const {
            return m_mod_prime.square(x);
        }

        BigInt multiply_mod_prime(const BigInt &x, const BigInt &y) const {
            return m_mod_prime.multiply(x, y);
        }

        BigInt multiply_mod_prime(const BigInt &x, const BigInt &y, const BigInt &z) const {
            return m_mod_prime.multiply(m_mod_prime.multiply(x, y), z);
        }

        BigInt inverse_mod_prime(const BigInt &x) const {
            return inverse_mod(x, m_p);
        }

//        PointGFp blinded_base_point_multiply(const BigInt& k,
//                                             RandomNumberGenerator& rng,
//                                             std::vector<BigInt>& ws) const
//        {
//            return m_base_mult.mul(k, rng, m_order, ws);
//        }

    private:
        Point41417p m_base_point;
        BigInt m_p;
        BigInt m_a;
        BigInt m_g_x;
        BigInt m_g_y;
        BigInt m_order;
        BigInt m_cofactor;
        Modular_Reducer m_mod_prime;
//        PointGFp_Base_Point_Precompute m_base_mult;
        size_t m_p_bits;
        size_t m_order_bits;
    };


    EC41417_Group::EC41417_Group() {
        m_data = load_EC41417_group_info(curve41417[0], curve41417[4], curve41417[2], curve41417[3], curve41417[1]);
    }

    std::shared_ptr<EC41417_Group_Data>
    EC41417_Group::load_EC41417_group_info(const char *p_str,
                                           const char *a_str,
                                           const char *g_x_str,
                                           const char *g_y_str,
                                           const char *order_str) {
        const BigInt p(p_str);
        const BigInt a(a_str);
        const BigInt g_x(g_x_str);
        const BigInt g_y(g_y_str);
        const BigInt order(order_str);
        const BigInt cofactor(1); // implicit

        return std::make_shared<EC41417_Group_Data>(p, a, g_x, g_y, order, cofactor);
    }

    BigInt EC41417_Group::random_scalar(RandomNumberGenerator &rng) const
    {
        auto random = rng.random_vec(52);
        /* prepare the secret random data: clear bottom 3 bits. Clearing top 2 bits
         * makes is a 414 bit value
         */
        random[51] &= ~0x7;
        random[0] &= 0x3f;

        // convert the random data into big numbers
        return BigInt(random);
    }

    Point41417p EC41417_Group::point(const BigInt &x, const BigInt &y) const
    {
        return {x, y};
    }

    Point41417p EC41417_Group::zero_point() const {
        return {0, 0};
    }

    const EC41417_Group_Data & EC41417_Group::data() const {
            if(m_data == nullptr)
                throw Invalid_State("EC41417_Group uninitialized");
            return *m_data;
    }

    const BigInt& EC41417_Group::get_p() const
    {
        return data().p();
    }

    const BigInt& EC41417_Group::get_a() const
    {
        return data().a();
    }

    const Point41417p& EC41417_Group::get_base_point() const
    {
        return data().base_point();
    }

    const BigInt& EC41417_Group::get_order() const
    {
        return data().order();
    }

    const BigInt& EC41417_Group::get_g_x() const
    {
        return data().g_x();
    }

    const BigInt& EC41417_Group::get_g_y() const
    {
        return data().g_y();
    }

    const BigInt& EC41417_Group::get_cofactor() const
    {
        return data().cofactor();
    }

    size_t EC41417_Group::get_p_bytes() const {
        return data().p_bytes();
    }

    BigInt EC41417_Group::mod_prime(const BigInt& k) const
    {
        return data().mod_prime(k);
    }

    BigInt EC41417_Group::square_mod_prime(const BigInt& x) const
    {
        return data().square_mod_prime(x);
    }

    BigInt EC41417_Group::multiply_mod_prime(const BigInt& x, const BigInt& y) const
    {
        return data().multiply_mod_prime(x, y);
    }

    BigInt EC41417_Group::multiply_mod_prime(const BigInt& x, const BigInt& y, const BigInt& z) const
    {
        return data().multiply_mod_prime(x, y, z);
    }

    BigInt EC41417_Group::inverse_mod_prime(const BigInt& x) const
    {
        return data().inverse_mod_prime(x);
    }

    Point41417p EC41417_Group::base_point_multiply(const BigInt &k, std::vector<BigInt> &ws) const
    {
        return k * get_base_point();
    }

    Point41417p EC41417_Group::point_multiply(const Point41417p &point, const BigInt &k, std::vector<BigInt> &ws) const {
        return k * point;
    }

    bool EC41417_Group::verify_public_element(const Point41417p& point) const
    {
        //check that public point is not at infinity
        if(point.is_zero())
            return false;

        //check that public point is on the curve
        if(!point.on_the_curve())
            return false;

        return true;
    }
}