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
// Created by werner on 28.01.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#include <zrtp/crypto/zrtpDH.h>
#include <zrtp/libzrtpcpp/ZrtpTextData.h>

#include <botancrypto/Point41417.h>
#include "../logging/ZrtpLogging.h"
#include "gtest/gtest.h"

using namespace std;

/*
 * Result if base point (generator) multiplied with 31415:
 * X:
 * hex: 2E381D4526F05330CAEF549FD754A6CCE4E27136060111EF1EE9A88DDA7CC31FEAAD2B9C28D01E7B7C2AEEC23C1A67D218664F91
 * dec: 30553475802749957144362965037321709320356477475486539679158004672956949220949505188481387089370025578448230875777441695420305
 *
 * Y:
 * hex: 2C4853EEE25DB622DB04EF54C064E082278F2FBC8199DB01CE57D2B1F6E5328D5FD547F5D9041D5D8C320990C0F6A7B45005884B
 * dec: 29273231244339256955699668356694183924984615939477469174536339873148548197480670899551170046439682076270123478944260632709195
 *
 * DJB provided the following Sage script that computes the results above (dec):
 *
   n = 31415
   p = 2^414-17
   k = GF(p)
   d = k(3617)
   x = k(17319886477121189177719202498822615443556957307604340815256226171904769976866975908866528699294134494857887698432266169206165)
   y = k(34)
   # convert to Montgomery form:
   A = 2*(1+d)/(1-d)
   B = 4/(1-d)
   x,y = (1+y)/(1-y),((1+y)/(1-y))/x
   # convert to short Weierstrass form:
   a = (3-A^2)/(3*B^2)
   b = (2*A^3-9*A)/(27*B^3)
   x,y = (x+A/3)/B,y/B
   # Sage knows how to multiply in short Weierstrass form:
   E = EllipticCurve([a,b])
   P = n * E([x,y])
   if P == 0:
     print 0,1
   else:
     x,y = P[0],P[1]
     # back to Montgomery:
     x,y = B*x-A/3,B*y
     # back to Edwards:
     x,y = x/y,(x-1)/(x+1)
     print x,y

 */

static char resultX31415[] = "30553475802749957144362965037321709320356477475486539679158004672956949220949505188481387089370025578448230875777441695420305";
static char resultY31415[] = "29273231244339256955699668356694183924984615939477469174536339873148548197480670899551170046439682076270123478944260632709195";

static char random414117[] = "3BD8B33E37C66342ED1CCC0F9A09211B547E4FB68E926E784B5D15977E330587156379BBEB63B5E2F6616DFC8FE36CE0085809D8";

class BotanEc41417TestFixture: public ::testing::Test {
public:
    BotanEc41417TestFixture() = default;

    BotanEc41417TestFixture(const BotanEc41417TestFixture& other) = delete;
    BotanEc41417TestFixture(const BotanEc41417TestFixture&& other) = delete;
    BotanEc41417TestFixture& operator= (const BotanEc41417TestFixture& other) = delete;
    BotanEc41417TestFixture& operator= (const BotanEc41417TestFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(DEBUGGING);
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~BotanEc41417TestFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }
};

TEST_F(BotanEc41417TestFixture, SimpleChecks) {
    Botan::EC41417_Group ecGroup;

    auto const & basePnt = ecGroup.get_base_point();
    ASSERT_EQ(34, basePnt.get_y());

    // Base point must be on curve -> this checks the 'on_the_curve()' function
    auto onCurve = basePnt.on_the_curve();
    ASSERT_TRUE(onCurve);

    std::vector<Botan::BigInt> workspace(Botan::Point41417p::WORKSPACE_SIZE);

    // Add base point to zero point -> check if it's the base point
    auto RPnt = ecGroup.zero_point();
    RPnt.add(basePnt, workspace);
    ASSERT_TRUE(basePnt.get_x() == RPnt.get_x());
    ASSERT_TRUE(basePnt.get_y() == RPnt.get_y());
    ASSERT_TRUE(basePnt.get_z() == RPnt.get_z());

    // Also, affine point must be on curve
    auto affineXy = RPnt.getAffineXY();
    Botan::Point41417p affinePnt(affineXy.first, affineXy.second, 1);
    onCurve = affinePnt.on_the_curve();
    ASSERT_TRUE(onCurve);

    // basePnt -> base point, RPnt -> also base point, no change after adding 0,0,0
    // This adds the base point to another point (which happens to be the base point)
    // Result must be on curve
    RPnt.add(basePnt, workspace);
    affineXy = RPnt.getAffineXY();
    affinePnt = Botan::Point41417p(affineXy.first, affineXy.second, 1);
    onCurve = affinePnt.on_the_curve();
    ASSERT_TRUE(onCurve);

    // Get another base point, double it
    // Must be on curve, also the affine result of doubling should be the same as add base point to itself above
    Botan::Point41417p baseCopyDouble(basePnt);
    baseCopyDouble.mult2(workspace);
    affineXy = baseCopyDouble.getAffineXY();
    auto affinePntDouble = Botan::Point41417p(affineXy.first, affineXy.second, 1);
    onCurve = affinePntDouble.on_the_curve();
    ASSERT_TRUE(onCurve);

    ASSERT_TRUE(affinePnt.get_x() == affinePntDouble.get_x());
    ASSERT_TRUE(affinePnt.get_y() == affinePntDouble.get_y());
    ASSERT_TRUE(affinePnt.get_z() == affinePntDouble.get_z());
}

TEST_F(BotanEc41417TestFixture, TestVector) {
    Botan::EC41417_Group ecGroup;

    auto const & basePnt = ecGroup.get_base_point();
    const Botan::BigInt piMult("31415");
    auto piResult = piMult * basePnt;

    auto affineXy = piResult.getAffineXY();
    auto affinePnt = Botan::Point41417p(affineXy.first, affineXy.second, 1);
    auto onCurve = affinePnt.on_the_curve();

    ASSERT_TRUE(onCurve);
    ASSERT_TRUE(affinePnt.get_x().to_dec_string() == resultX31415);
    ASSERT_TRUE(affinePnt.get_y().to_dec_string() == resultY31415);
}

TEST_F(BotanEc41417TestFixture, DiffieHellman) {
    // Test simulates a Diffie-Hellman as used by ZRTP - test must run using the Botan based zrtpDH class

    // Setup with  DH code for Alice
    ZrtpDH aliceDh(e414, ZrtpDH::Commit);
    ASSERT_TRUE(aliceDh.version() == "Botan");

    zrtp::SecureArray1k alicePubKey;
    auto aliceKeyLen = aliceDh.fillInPubKeyBytes(alicePubKey);

    // Setup with  DH code for Bob
    ZrtpDH bobDh(e414, ZrtpDH::Commit);

    zrtp::SecureArray1k bobPubKey;
    bobDh.fillInPubKeyBytes(bobPubKey);

    // Agree on keys. Alice first
    zrtp::SecureArray1k aliceSharedData;
    aliceKeyLen = aliceDh.computeSecretKey(bobPubKey.data(), aliceSharedData);
    ASSERT_GT(aliceKeyLen, 0);
    ASSERT_EQ(aliceKeyLen, aliceSharedData.size());

    // Now Bob
    zrtp::SecureArray1k bobSharedData;
    auto bobKeyLen = bobDh.computeSecretKey(alicePubKey.data(), bobSharedData);
    ASSERT_GT(bobKeyLen, 0);
    ASSERT_EQ(bobKeyLen, bobSharedData.size());

    ASSERT_EQ(aliceKeyLen, bobKeyLen);
    ASSERT_TRUE(aliceSharedData.equals(bobSharedData, aliceKeyLen));
}

// Test compressed X-coordinate
TEST_F(BotanEc41417TestFixture, compressX) {
    Botan::EC41417_Group ecGroup;

    auto const & basePnt = ecGroup.get_base_point();

    // Use the Y-coordinate to re-compute the X-coordinate
    auto result = Botan::Point41417p::decompress_point(basePnt.get_x().is_odd(), basePnt.get_y());
    // Re-computed value must be equal to original value
    ASSERT_TRUE(result == basePnt.get_x());

    // Compute the well known point (see above)
    const Botan::BigInt piMult("31415");
    auto piResult = piMult * basePnt;

    auto affineXy = piResult.getAffineXY();
    auto affinePnt = Botan::Point41417p(affineXy.first, affineXy.second, 1);

    // Perform the same steps as above for the computed point 31415, check the result
    result = Botan::Point41417p::decompress_point(affineXy.first.is_odd(), affinePnt.get_y());
    ASSERT_TRUE(result == affinePnt.get_x());
}

// Test compressed Y-coordinate
TEST_F(BotanEc41417TestFixture, compressY) {
    Botan::EC41417_Group ecGroup;

    auto const & basePnt = ecGroup.get_base_point();

    // Use the X-coordinate to re-compute the Y-coordinate
    auto result = Botan::Point41417p::decompress_point(basePnt.get_y().is_odd(), basePnt.get_x());
    // Re-computed value must be equal to original value
    ASSERT_TRUE(result == basePnt.get_y());

    // Compute the well known point (see above)
    const Botan::BigInt piMult("31415");
    auto piResult = piMult * basePnt;

    auto affineXy = piResult.getAffineXY();
    auto affinePnt = Botan::Point41417p(affineXy.first, affineXy.second, 1);

    // Perform the same steps as above for the computed point 31415, check the result
    result = Botan::Point41417p::decompress_point(affineXy.second.is_odd(), affinePnt.get_x());
    ASSERT_TRUE(result == affinePnt.get_y());
}

#if 0
TEST_F(BotanEc41417TestFixture, benchmark) {
    Botan::EC41417_Group ecGroup;

    auto const & basePnt = ecGroup.get_base_point();
    // Compute the well known point (see above)
    const Botan::BigInt piMult("31415");
    auto piResult = piMult * basePnt;
    auto affineXy = piResult.getAffineXY();
    auto affinePnt = Botan::Point41417p(affineXy.first, affineXy.second, 1);

    auto start = zrtpGetTickCount();
    for (int i = 0; i < 10000; i++) {
        Botan::Point41417p::decompress_point(affineXy.second.is_odd(), affinePnt.get_x());
    }
    auto end = zrtpGetTickCount();
    auto diff = end - start;
    LOGGER(WARNING, "decompress time: ", diff)

    start = zrtpGetTickCount();
    for (int i = 0; i < 10000; i++) {
        piResult.on_the_curve();
    }
    end = zrtpGetTickCount();
    diff = end - start;
    LOGGER(WARNING, "on curve time: ", diff)

}
#endif