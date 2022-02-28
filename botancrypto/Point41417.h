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

#ifndef LIBZRTPCPP_POINT41417_H
#define LIBZRTPCPP_POINT41417_H

#include "botan_all.h"
#include "botancrypto/ZrtpBotanRng.h"
#include "botancrypto/Ec41417Group.h"

namespace Botan {
    /**
     * This class represents one point on a curve of 41417
     */
    class BOTAN_PUBLIC_API(2, 0) Point41417p {
    public:
        enum Compression_Type {
            UNCOMPRESSED = 0,
            COMPRESSED = 1,
            HYBRID = 2
        };

        enum {
            WORKSPACE_SIZE = 8
        };

        /**
        * Construct an uninitialized PointGFp
        */
        Point41417p() = default;

        /**
        * Copy constructor
        */
        Point41417p(const Point41417p &) = default;

        /**
        * Move Constructor
        */
        Point41417p(Point41417p &&other)  noexcept {
            this->swap(other);
        }

        /**
        * Standard Assignment
        */
        Point41417p &operator=(const Point41417p &) = default;

        /**
        * Move Assignment
        */
        Point41417p &operator=(Point41417p &&other) {
            if (this != &other)
                this->swap(other);
            return (*this);
        }

        /**
         * Construct a point from its affine coordinates
         * Prefer EC_Group::point(x,y) for this operation.
         * @param x affine x coordinate
         * @param y affine y coordinate
         */
        Point41417p(const BigInt &x, const BigInt &y, const BigInt &z = 0) :
                m_coord_x(x), m_coord_y(y), m_coord_z(z) {}

        /**
        * EC2OSP - elliptic curve to octet string primitive
        * @param format which format to encode using
        */
        std::vector<uint8_t> encode(Point41417p::Compression_Type format) const;

        std::pair<BigInt, BigInt> getAffineXY() const;

        const BigInt &get_x() const { return m_coord_x; }

        const BigInt &get_y() const { return m_coord_y; }

        const BigInt &get_z() const { return m_coord_z; }

        void swap_coords(BigInt &new_x, BigInt &new_y, BigInt &new_z) {
            m_coord_x.swap(new_x);
            m_coord_y.swap(new_y);
            m_coord_z.swap(new_z);
        }

        bool is_affine() const { return m_coord_z == 1; }

        /**
        * Is this the point at infinity?
        * @result true, if this point is at infinity, false otherwise.
        */
        bool is_zero() const { return m_coord_z.is_zero(); }

        /**
        * Checks whether the point is to be found on the underlying
        * curve; used to prevent fault attacks.
        * @return if the point is on the curve
        */
        bool on_the_curve() const;

        /**
        * swaps the states of *this and other, does not throw!
        * @param other the object to swap values with
        */
        void swap(Point41417p &other);

        /**
        * Point addition
        * @param other the point to add to *this
        * @param workspace temp space, at least WORKSPACE_SIZE elements
        */
        void add(const Point41417p &other, std::vector<BigInt> &workspace);

        /**
        * Point doubling
        * @param workspace temp space, at least WORKSPACE_SIZE elements
        */
        void mult2(std::vector<BigInt> &workspace);

        /**
        * Point addition
        * @param other the point to add to *this
        * @param workspace temp space, at least WORKSPACE_SIZE elements
        * @return other plus *this
        */
        Point41417p plus(const Point41417p &other, std::vector<BigInt> &workspace) const {
            Point41417p x = (*this);
            x.add(other, workspace);
            return x;
        }

        /**
        * Point doubling
        * @param workspace temp space, at least WORKSPACE_SIZE elements
        * @return *this doubled
        */
        Point41417p double_of(std::vector<BigInt> &workspace) const {
            Point41417p x = (*this);
            x.mult2(workspace);
            return x;
        }

        /**
        * Return the zero (aka infinite) point associated with this group
        */
        static Point41417p zero() { return {0, 0}; }

        static BigInt decompress_point(bool isOdd, const BigInt& xOrY);

    private:
        BigInt m_coord_x, m_coord_y, m_coord_z;
    };

    /**
     * Point multiplication operator
     * @param scalar the scalar value
     * @param point the point value
     * @return scalar*point on the curve
     */
    BOTAN_PUBLIC_API(2,0) Point41417p operator*(const BigInt& scalar, const Point41417p& point);

}

#endif //LIBZRTPCPP_POINT41417_H
