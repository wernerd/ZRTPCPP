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
#include "Point41417.h"

namespace Botan {
    std::vector<uint8_t> Point41417p::encode(Point41417p::Compression_Type format) const {
        std::vector<uint8_t> result;

        EC41417_Group m_group;

        const size_t p_bytes = m_group.get_p().bytes(); // Check: this should be 52

        std::pair<BigInt, BigInt> xy = getAffineXY();
        if (format == Point41417p::UNCOMPRESSED) {
            result.resize(1 + 2 * p_bytes);
            result[0] = 0x04;
            BigInt::encode_1363(&result[1], p_bytes, xy.first);
            BigInt::encode_1363(&result[1 + p_bytes], p_bytes, xy.second);
        }
        else if(format == Point41417p::COMPRESSED)
        {
            result.resize(1 + p_bytes);
            result[0] = 0x02 | static_cast<uint8_t>(xy.second.get_bit(0));
            BigInt::encode_1363(&result[1], p_bytes, xy.first);
        }
        else {
            throw Invalid_Argument("EC41417 illegal point encoding");
        }
        return result;
    }

    void Point41417p::swap(Point41417p& other)
    {
        m_coord_x.swap(other.m_coord_x);
        m_coord_y.swap(other.m_coord_y);
        m_coord_z.swap(other.m_coord_z);
    }

    // Decode an Edwards curve point into the given x,y coordinates.
    // Returns an error if the input does not denote a valid curve point.
    // Note that this does NOT check if the point is in the prime-order subgroup:
    // an adversary could create an encoding denoting a point
    // on the twist of the curve, or in a larger subgroup.
    // However, the "safecurves" criteria (http://safecurves.cr.yp.to)
    // ensure that none of these other subgroups are small
    // other than the tiny ones represented by the cofactor;
    // hence Diffie-Hellman exchange can be done without subgroup checking
    // without exposing more than the least-significant bits of the scalar.

    // Edwards curves are symmetric. Thus, this functions can decompress the x or y
    // coordinate if the other one is given (and the odd-indicator).

    // Curve41417 equation: ax²+y² = 1+3617x²y²
    //
    // rewritten equation to solve for y:
    // a = 1
    // d = 3617
    // y² = 1 - x² / 1 - 3617 * x²
    // y = sqrt(y²)
    //
    // all computations must use modulo algorithms

    BigInt Point41417p::decompress_point(bool isOdd,
                                         const BigInt& xOrY,
                                         const BigInt& d,
                                         std::vector<BigInt> &workspace)
    {
        auto& xOrY2 = workspace[0];
        auto& dxOrY2 = workspace[1];
        auto& result2 = workspace[2];
        auto &invers = workspace[3];
        auto result = workspace[4];

        EC41417_Group m_group;

        // compute a*xOrY² and d*xOrY² where a = 1, d = 3617
        xOrY2 = m_group.square_mod_prime(xOrY);
        dxOrY2 = m_group.multiply_mod_prime(d, xOrY2);

        BigInt bigInternal;
        secure_vector<word>& ws = bigInternal.get_word_vector();

        // compute 1-xOrY² and 1-(d*xOrY²)
        xOrY2 = BigInt(1).mod_sub(xOrY2, m_group.get_p(), ws);
        dxOrY2 = BigInt(1).mod_sub(dxOrY2, m_group.get_p(), ws);

        // Invert 1-(d*xOrY²) and use it to divide 1-xOrY²
        invers = Botan::inverse_mod(dxOrY2, m_group.get_p());

        // result2 is result of the division: either x² or y² depending on
        // input parameter (decompress the X or the Y coordinate)
        result2 = m_group.multiply_mod_prime(xOrY2, invers);

        // get the square root of result2 into result. This function uses
        // the Tonelli-Shanks algorithm to compute sqrt modulo
        result = Botan::ressol(result2, m_group.get_p());
        if (result == -1) {
            throw Illegal_Point("ECDH 41417 cannot decompress point");
        }

        // Need to use the other sqrt result: negate the result modulo (p - result)
        if (isOdd != result.is_odd()) {
            result = BigInt(m_group.get_p()).mod_sub(result, m_group.get_p(), ws);
        }
        return result;
    }
    /*
     * Refer to the document: Faster addition and doubling on elliptic curves; Daniel J. Bernstein and Tanja Lange
     * section 4.
     *
     */

    void Point41417p::add(const Point41417p &Q, std::vector<BigInt> &workspace)
    {
        // Other point Q is zero -> leave this point untouched
        if (Q.is_zero()) {
            return;
        }
        // this point is zero -> copy values from Q into this point, done.
        if (is_zero()) {
            m_coord_x = Q.m_coord_x;
            m_coord_y = Q.m_coord_y;
            m_coord_z = Q.m_coord_z;
            return;
        }

        BigInt& Rx = workspace[0];
        BigInt& Ry = workspace[1];
        BigInt& Rz = workspace[2];
        BigInt& t0 = workspace[3];
        BigInt& t1 = workspace[4];
        BigInt& t2 = workspace[5];
        BigInt& t3 = workspace[6];

        BigInt bigInternal;
        secure_vector<word>& ws = bigInternal.get_word_vector();

        EC41417_Group m_group;

        /* Compute A, C, D first */
        Rz = m_group.multiply_mod_prime(m_coord_z, Q.m_coord_z);            /* Rz -> A; (Z1 * Z2); Rz becomes R3 */
        Rx = m_group.multiply_mod_prime(m_coord_x, Q.m_coord_x);            /* Rx -> C; (X1 * X2); Rx becomes R1 */
        Ry = m_group.multiply_mod_prime(m_coord_y, Q.m_coord_y);            /* Ry -> D; (Y1 * Y2); Ry becomes R2 */


        /* Compute large parts of X3 equation, sub result in t0 */
        t0 = m_coord_x;
        t0.mod_add(m_coord_y, m_group.get_p(), ws);                 /* t0 -> X1 + Y1 mod p */

        t1 = Q.m_coord_x;
        t1.mod_add(Q.m_coord_y, m_group.get_p(), ws);               /* t1 -> X2 + Y2 mod p*/


        t2 = m_group.multiply_mod_prime(t0, t1);                            /* t2 = t0 * t1 */
        t2.mod_sub(Rx, m_group.get_p(), ws);                        /* t2 - C */
        t2.mod_sub(Ry, m_group.get_p(), ws);                        /* t2 - D */
        t0 = m_group.multiply_mod_prime(t2, Rz);                           /* t0 -> R7; (t2 * A); sub result */

        /* Compute E */
        t2 = m_group.multiply_mod_prime(Rx, Ry);                           /* t2 = C * D */
        t1 = m_group.multiply_mod_prime(t2, m_group.get_a());           /* t1 -> E; t1 new R8 */

        /* Compute part of Y3 equation, sub result in t2 */
        Ry.mod_sub(Rx, m_group.get_p(), ws);                       /* Ry = D - C; sub result */
        t2 = m_group.multiply_mod_prime(Ry, Rz);                           /* t2 = Ry * A; sub result */

        /* Compute B */
        Rz = m_group.square_mod_prime(Rz);                                /* Rz -> B; (A^2) */

        /* Compute F */
        t3 = Rz;
        t3.mod_sub(t1, m_group.get_p(), ws);                   /* t3 -> F; (B - E) */

        /* Compute G */
        Rz.mod_add(t1, m_group.get_p(), ws);                   /* Rz -> G; (B + E) */

        /* Compute, X, Y, Z results */
        m_coord_x = m_group.multiply_mod_prime(t3, t0);           /* result x = F * t0 */
        m_coord_y = m_group.multiply_mod_prime(t2, Rz);           /* result y = t2 * G */
        m_coord_z = m_group.multiply_mod_prime(t3, Rz);           /* result z = F * G */
    }

    bool Point41417p::on_the_curve() const
    {
        EC41417_Group m_group;

        /* Represent point at infinity by (0, 0), make sure it's not that */
        if (m_coord_x.is_zero() && m_coord_y.is_zero()) {
            return false;
        }
        /* Check that coordinates are within range */
        if (m_coord_x < 0 || m_coord_x >= m_group.get_p()) {
            return false;
        }
        if (m_coord_y < 0 || m_coord_y >= m_group.get_p()) {
            return false;
        }

        std::vector<BigInt> workspace(Point41417p::WORKSPACE_SIZE);

        BigInt& t0 = workspace[0];
        BigInt& t1 = workspace[1];
        BigInt& t2 = workspace[2];
        BigInt& t3 = workspace[3];

        secure_vector<word>& ws = workspace[4].get_word_vector();

        /* Check that point satisfies EC equation x^2+y^2 = 1+3617x^2y^2, mod P */
        t1 = m_group.square_mod_prime(m_coord_y);
        t2 = m_group.square_mod_prime(m_coord_x);

        t3 = t1;                                                     /* Load t3 */
        t3.mod_add(t2, m_group.get_p(), ws);                   /* t3 = t1 + t2, (x^2+y^2)*/

        t0 = m_group.multiply_mod_prime(t1, m_group.get_a());     /* t0 = a * t1,  (3617 * y^2) */
        t0 = m_group.multiply_mod_prime(t0, t2);                     /* t0 = t0 * t2, (3617 * x^2 * y^2) */
        t0.mod_add(1, m_group.get_p(), ws);               /* t0 = t0 + 1,  (3617 * x^2 * y^2 + 1) */

        return !(t0 != t3);
    }

    std::pair<BigInt, BigInt>
    Point41417p::getAffineXY() const
    {
        std::vector<BigInt> workspace(Point41417p::WORKSPACE_SIZE);

        BigInt& z1 = workspace[0];
        BigInt Rx;
        BigInt Ry;

        EC41417_Group m_group;

        /* affine x = X / Z */
        z1 = m_group.inverse_mod_prime(m_coord_z);                 /* z_1 = Z^(-1) */
        Rx = m_group.multiply_mod_prime(m_coord_x, z1);

        /* affine y = Y / Z */
        Ry = m_group.multiply_mod_prime(m_coord_y, z1);

        return {Rx, Ry};
    }

    void
    Point41417p::mult2(std::vector<BigInt> &workspace)
    {
        EC41417_Group group;

        BigInt& Rx = workspace[0];
        BigInt& Ry = workspace[1];
        BigInt& Rz = workspace[2];
        BigInt& t0 = workspace[3];
        BigInt& t1 = workspace[4];
        BigInt& t2 = workspace[5];
        secure_vector<word>& ws = workspace[6].get_word_vector();

        /* Compute B, C, D, H, E */
        t0 = m_coord_x;
        t0.mod_add(m_coord_y, group.get_p(), ws);
        t0 = group.square_mod_prime(t0);                            /* t0 -> B */

        Rx = group.square_mod_prime(m_coord_x);                     /* Rx -> C */

        Ry = group.square_mod_prime(m_coord_y);                     /* Ry -> D */

        Rz = group.square_mod_prime(m_coord_z);                     /* Rz -> H */
        Rz.mod_add(Rz, group.get_p(), ws);                       /* Rz -> 2H */

        t1 = Rx;
        t1.mod_add(Ry, group.get_p(), ws);                       /* t1 -> E */

        /* Compute y coordinate */
        t2 = Rx;
        t2.mod_sub(Ry, group.get_p(), ws);                       /* C - D */
        m_coord_y = group.multiply_mod_prime(t1, t2);               /* E * t2; Ry */

        /* Compute x coordinate */
        t0.mod_sub(t1, group.get_p(), ws);                       /* B - E; sub result */
        t2 = t1;
        t2.mod_sub(Rz, group.get_p(), ws);                       /* t2 -> J; (E - 2H) */
        m_coord_x = group.multiply_mod_prime(t2, t0);               /* J * t0 */

        /* Compute z coordinate */
        m_coord_z = group.multiply_mod_prime(t2, t1);               /* J * E */
    }

    BOTAN_PUBLIC_API(2,0) Point41417p operator*(const BigInt& scalar, const Point41417p& point)
    {
        const size_t bits = scalar.bits();
        Point41417p n(point);
        Point41417p R = point.zero();

        std::vector<BigInt> workspace(Point41417p::WORKSPACE_SIZE);

        for (uint32_t i = 0; i < bits; i++) {
            const size_t b = scalar.get_bit(i);
            if (b)
                R.add(n, workspace);

            n.mult2(workspace);
        }
        return R;
    }
}