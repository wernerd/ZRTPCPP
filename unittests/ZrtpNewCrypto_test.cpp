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

#include <array>
#include "../logging/ZrtpLogging.h"
#include "../common/Utilities.h"

#include "zrtp/crypto/zrtpDH.h"
#include "zrtp/libzrtpcpp/ZrtpTextData.h"
#include "zrtp/crypto/sha256.h"
#include "zrtp/crypto/sha384.h"
#include "zrtp/crypto/skein256.h"
#include "zrtp/crypto/skein384.h"
#include "zrtp/crypto/hmac256.h"
#include "zrtp/crypto/hmac384.h"
#include "zrtp/crypto/skeinMac256.h"
#include "zrtp/crypto/skeinMac384.h"
#include "zrtp/crypto/aesCFB.h"
#include "zrtp/crypto/twoCFB.h"
#include "srtp/crypto/hmac.h"
#include "botancrypto/ZrtpCurve41417.h"
#include "botan_all.h"
#include "botancrypto/ZrtpBotanRng.h"
#include "gtest/gtest.h"

//
// These tests use the zrtpDH crypto functions and compare the results
// to plain Botan crypto functions. Make sure the crypto wrapper works.
using namespace std;

class ZrtpNewCryptoTestFixture: public ::testing::Test {
public:
    ZrtpNewCryptoTestFixture() = default;

    ZrtpNewCryptoTestFixture(const ZrtpNewCryptoTestFixture& other) = delete;
    ZrtpNewCryptoTestFixture(const ZrtpNewCryptoTestFixture&& other) = delete;
    ZrtpNewCryptoTestFixture& operator= (const ZrtpNewCryptoTestFixture& other) = delete;
    ZrtpNewCryptoTestFixture& operator= (const ZrtpNewCryptoTestFixture&& other) = delete;

    void SetUp() override {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(WARNING);
    }

    void TearDown( ) override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~ZrtpNewCryptoTestFixture( ) override {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }
};

TEST_F(ZrtpNewCryptoTestFixture, simpleAliceBob) {
    ZrtpDH aliceDh(dh3k, ZrtpDH::Commit);
    ZrtpDH bobDh(dh3k, ZrtpDH::Commit);

    zrtp::SecureArray1k alicePubKey;
    auto aliceKeyLen = aliceDh.fillInPubKeyBytes(alicePubKey);

    zrtp::SecureArray1k bobPubKey;
    auto bobKeyLen = bobDh.fillInPubKeyBytes(bobPubKey);

    ASSERT_EQ(aliceKeyLen, bobKeyLen);

    zrtp::SecureArray1k aliceSharedData;
    aliceKeyLen = aliceDh.computeSecretKey(bobPubKey.data(), aliceSharedData);
    ASSERT_GT(aliceKeyLen, 0);

    zrtp::SecureArray1k bobSharedData;
    bobKeyLen = bobDh.computeSecretKey(alicePubKey.data(), bobSharedData);
    ASSERT_GT(bobKeyLen, 0);

    ASSERT_EQ(aliceKeyLen, bobKeyLen);

    ASSERT_TRUE(aliceSharedData.equals(bobSharedData, aliceSharedData.size()));
}

// std::unique_ptr<Botan::RandomNumberGenerator> rng; rng.reset(new AutoSeeded_RNG);
//          std::unique_ptr<Botan::Private_Key> key(new Botan::DH_PrivateKey(Test::rng(), grp, x)); // x == 0 -> generate random
// DH_PublicKey pubKey = privateKey.public_value()

// DH_PublicKey(const DL_Group& grp, const BigInt& y);
//          kas.reset(new Botan::PK_Key_Agreement(*privkey, Test::rng(), kdf, provider));

TEST_F(ZrtpNewCryptoTestFixture, botanSimple) {
    ZrtpBotanRng rng;
    // ec domain and
    Botan::DL_Group group("modp/ietf/3072");
    std::string kdf = "Raw";
    // generate DH keys
    Botan::DH_PrivateKey keyAlice(rng, group);
    Botan::DH_PrivateKey keyBob(rng, group);

    // Construct key agreements
    Botan::PK_Key_Agreement dhAlice(keyAlice, rng, kdf);
    Botan::PK_Key_Agreement dhBob(keyBob,rng, kdf);

    // Agree on shared secret and derive symmetric key of 256 bit length
    Botan::secure_vector<uint8_t> sA = dhAlice.derive_key(384, keyBob.public_value()).bits_of();
    Botan::secure_vector<uint8_t> sB = dhBob.derive_key(384, keyAlice.public_value()).bits_of();

    ASSERT_EQ(384, sA.size());
    ASSERT_EQ(384, sB.size());
    ASSERT_TRUE(sA == sB);
}

TEST_F(ZrtpNewCryptoTestFixture, mixedLibs) {

    // Setup with existing DH code fpr Alice
    ZrtpDH aliceDh(dh3k, ZrtpDH::Commit);
    zrtp::SecureArray1k alicePubKey;
    aliceDh.fillInPubKeyBytes(alicePubKey);

    // Using Botan lib for Bob
    ZrtpBotanRng rng;
    // dh group
    Botan::DL_Group group("modp/ietf/3072");
    std::string kdf = "Raw";

    // generate DH keys - Bob
    Botan::DH_PrivateKey keyBob(rng, group);
    auto bobPubKey = keyBob.public_value();

    // Agree on keys. Alice first
    zrtp::SecureArray1k aliceSharedData;
    ASSERT_EQ(1, aliceDh.checkPubKey(bobPubKey.data()));  // check must return OK
    auto aliceKeyLen = aliceDh.computeSecretKey(bobPubKey.data(), aliceSharedData);
    ASSERT_GT(aliceKeyLen, 0);

    Botan::PK_Key_Agreement dhBob(keyBob,rng, kdf);
    Botan::secure_vector<uint8_t> sB = dhBob.derive_key(384, alicePubKey.data(), alicePubKey.size()).bits_of();

    ASSERT_EQ(aliceKeyLen, sB.size());

    ASSERT_TRUE(aliceSharedData.equals(sB.data(), aliceSharedData.size()));
}

TEST_F(ZrtpNewCryptoTestFixture, mixedEcDh256) {
    // Setup with existing DH code fpr Alice
    ZrtpDH aliceDh(ec25, ZrtpDH::Commit);

    zrtp::SecureArray1k alicePubTmp;
    auto aliceKeyLen = aliceDh.fillInPubKeyBytes(alicePubTmp);

    vector<uint8_t > alicePubKey(aliceKeyLen+1);
    alicePubKey.at(0) = 4;      // 4 -> magic number, shows x,y coordinates are in uncompressed format
    memcpy(alicePubKey.data()+1, alicePubTmp.data(), aliceKeyLen);

    // Using Botan lib for Bob, ec domain
    ZrtpBotanRng rng;
    Botan::EC_Group domain("secp256r1");
    std::string kdf = "Raw";

    // generate DH keys - Bob
    Botan::ECDH_PrivateKey keyBob(rng, domain);
    Botan::PK_Key_Agreement ecdhBob(keyBob, rng, kdf);
    auto bobPubKey = keyBob.public_value();

    // Agree on keys. Alice first
    zrtp::SecureArray1k aliceSharedData;
    ASSERT_EQ(0, aliceDh.checkPubKey(bobPubKey.data()));    // Force error
    ASSERT_EQ(1, aliceDh.checkPubKey(bobPubKey.data()+1));  // check must return OK

    aliceKeyLen = aliceDh.computeSecretKey(bobPubKey.data()+1, aliceSharedData);
    ASSERT_GT(aliceKeyLen, 0);

    Botan::secure_vector<uint8_t> sB = ecdhBob.derive_key(32, alicePubKey).bits_of();

    ASSERT_EQ(aliceKeyLen, sB.size());
    ASSERT_TRUE(aliceSharedData.equals(sB.data(), aliceSharedData.size()));
}

TEST_F(ZrtpNewCryptoTestFixture, mixedEcDh384) {
// Setup with existing DH code fpr Alice
    ZrtpDH aliceDh(ec38, ZrtpDH::Commit);

    zrtp::SecureArray1k alicePubTmp;
    auto aliceKeyLen = aliceDh.fillInPubKeyBytes(alicePubTmp);

    vector<uint8_t > alicePubKey(aliceKeyLen+1);
    alicePubKey.at(0) = 4;      // 4 -> magic number, shows x,y coordinates are in uncompressed format
    memcpy(alicePubKey.data()+1, alicePubTmp.data(), aliceKeyLen);

// Using Botan lib for Bob, ec domain
    ZrtpBotanRng rng;
    Botan::EC_Group domain("secp384r1");
    std::string kdf = "Raw";

// generate DH keys - Bob
    Botan::ECDH_PrivateKey keyBob(rng, domain);
    Botan::PK_Key_Agreement ecdhBob(keyBob, rng, kdf);
    auto bobPubKey = keyBob.public_value();

// Agree on keys. Alice first
    zrtp::SecureArray1k aliceSharedData;
    ASSERT_EQ(0, aliceDh.checkPubKey(bobPubKey.data()));    // Force error
    ASSERT_EQ(1, aliceDh.checkPubKey(bobPubKey.data()+1));  // check must return OK
    aliceKeyLen = aliceDh.computeSecretKey(bobPubKey.data()+1, aliceSharedData);
    ASSERT_GT(aliceKeyLen, 0);

    Botan::secure_vector<uint8_t> sB = ecdhBob.derive_key(48, alicePubKey).bits_of();

    ASSERT_EQ(aliceKeyLen, sB.size());
    ASSERT_TRUE(aliceSharedData.equals(sB.data(), aliceSharedData.size()));
}

TEST_F(ZrtpNewCryptoTestFixture, mixedEcDh25519) {
// Setup with existing DH code fpr Alice
    ZrtpDH aliceDh(e255, ZrtpDH::Commit);

    zrtp::SecureArray1k alicePubKey;
    aliceDh.fillInPubKeyBytes(alicePubKey);

// Using Botan lib for Bob, generate curve25519 keys
    ZrtpBotanRng rng;
    std::string kdf = "Raw";
    Botan::Curve25519_PrivateKey keyBob(rng);
    Botan::PK_Key_Agreement ecdhBob(keyBob, rng, kdf);
    auto bobPubKey = keyBob.public_value();

// Agree on keys. Alice first
    zrtp::SecureArray1k aliceSharedData;
    ASSERT_EQ(1, aliceDh.checkPubKey(bobPubKey.data()));  // check must return OK
    auto aliceKeyLen = aliceDh.computeSecretKey(bobPubKey.data(), aliceSharedData);
    ASSERT_GT(aliceKeyLen, 0);

    Botan::secure_vector<uint8_t> sB = ecdhBob.derive_key(32, alicePubKey.data(), alicePubKey.size()).bits_of();

    ASSERT_EQ(aliceKeyLen, sB.size());
    ASSERT_TRUE(aliceSharedData.equals(sB.data(), aliceSharedData.size()));
}

TEST_F(ZrtpNewCryptoTestFixture, mixedSha256) {

    string toHash("The quick brown fox jumps over the lazy dog's back");

    std::unique_ptr<Botan::HashFunction> hash1(Botan::HashFunction::create_or_throw("SHA-256"));
    hash1->update(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size());
    auto botanHash = hash1->final();

    ASSERT_EQ(SHA256_DIGEST_LENGTH, botanHash.size());

    secUtilities::SecureArray<SHA256_DIGEST_LENGTH> oldHash;
    sha256(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size(), oldHash.data());

    ASSERT_TRUE(oldHash.equals(botanHash.data(), botanHash.size()));

}

TEST_F(ZrtpNewCryptoTestFixture, mixedSha384) {

    string toHash("The quick brown fox jumps over the lazy dog's back");

    std::unique_ptr<Botan::HashFunction> hash1(Botan::HashFunction::create_or_throw("SHA-384"));
    hash1->update(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size());
    auto botanHash = hash1->final();

    ASSERT_EQ(SHA384_DIGEST_LENGTH, botanHash.size());

    secUtilities::SecureArray<SHA384_DIGEST_LENGTH> oldHash;
    sha384(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size(), oldHash.data());

    ASSERT_TRUE(oldHash.equals(botanHash.data(), botanHash.size()));
}

TEST_F(ZrtpNewCryptoTestFixture, mixedSkein256) {

    string toHash("The quick brown fox jumps over the lazy dog's back");

    std::unique_ptr<Botan::HashFunction> hash1(Botan::HashFunction::create_or_throw("Skein-512(256)"));
    hash1->update(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size());
    auto botanHash = hash1->final();
    ASSERT_EQ(SHA256_DIGEST_LENGTH, botanHash.size());

    secUtilities::SecureArray<SHA256_DIGEST_LENGTH> oldHash;
    skein256(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size(), oldHash.data());
    ASSERT_TRUE(oldHash.equals(botanHash.data(), botanHash.size()));
}

TEST_F(ZrtpNewCryptoTestFixture, mixedSkein384) {

    string toHash("The quick brown fox jumps over the lazy dog's back");

    std::unique_ptr<Botan::HashFunction> hash1(Botan::HashFunction::create_or_throw("Skein-512(384)"));
    hash1->update(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size());
    auto botanHash = hash1->final();

    ASSERT_EQ(SHA384_DIGEST_LENGTH, botanHash.size());

    secUtilities::SecureArray<SHA384_DIGEST_LENGTH> oldHash;
    skein384(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size(), oldHash.data());

    ASSERT_TRUE(oldHash.equals(botanHash.data(), botanHash.size()));
}

TEST_F(ZrtpNewCryptoTestFixture, mixedHmacSha1) {

    string toHash("The quick brown fox jumps over the lazy dog's back");
    ZrtpBotanRng rng;

    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-1)");
    const auto key = rng.random_vec(32); // 256 bit random key
    hmac->set_key(key);
    hmac->update(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size());
    auto botanMac = hmac->final();

    ASSERT_EQ(SHA1_DIGEST_LENGTH, botanMac.size());

    zrtp::RetainedSecArray oldMac;
    int32_t macLen = 0;

    hmac_sha1(key.data(), key.size(),
            reinterpret_cast<const uint8_t *>(toHash.data()), static_cast<uint32_t>(toHash.size()), oldMac.data(), &macLen);

    ASSERT_TRUE(oldMac.equals(botanMac.data(), botanMac.size()));
}

TEST_F(ZrtpNewCryptoTestFixture, hmacSha1Multiple) {

    string toHash("The quick brown fox jumps over the lazy dog's back");
    ZrtpBotanRng rng;

    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-1)");
    const auto key = rng.random_vec(32); // 256 bit random key
    hmac->set_key(key);
    hmac->update(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size());
    auto botanMac = hmac->final();

    ASSERT_EQ(SHA1_DIGEST_LENGTH, botanMac.size());

    hmac->update(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size());
    auto botanMac1 = hmac->final();
    ASSERT_EQ(botanMac.size(), botanMac1.size());
    ASSERT_TRUE(memcmp(botanMac.data(), botanMac1.data(), botanMac.size()) == 0);
}

TEST_F(ZrtpNewCryptoTestFixture, mixedHmacSha256) {

    string toHash("The quick brown fox jumps over the lazy dog's back");
    ZrtpBotanRng rng;

    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
    const auto key = rng.random_vec(32); // 256 bit random key
    hmac->set_key(key);
    hmac->update(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size());
    auto botanMac = hmac->final();

    ASSERT_EQ(SHA256_DIGEST_LENGTH, botanMac.size());

    zrtp::RetainedSecArray oldMac;
    hmac_sha256(key.data(), key.size(), reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size(), oldMac);

    ASSERT_TRUE(oldMac.equals(botanMac.data(), botanMac.size()));
}

TEST_F(ZrtpNewCryptoTestFixture, mixedHmacSha384) {

    string toHash("The quick brown fox jumps over the lazy dog's back");
    ZrtpBotanRng rng;

    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-384)");
    const auto key = rng.random_vec(32); // 256 bit random key
    hmac->set_key(key);
    hmac->update(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size());
    auto botanMac = hmac->final();

    ASSERT_EQ(SHA384_DIGEST_LENGTH, botanMac.size());

    zrtp::RetainedSecArray oldMac;
    hmac_sha384(key.data(), key.size(), reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size(), oldMac);

    ASSERT_TRUE(oldMac.equals(botanMac.data(), botanMac.size()));
}

static std::array<unsigned char, 32> key_s = {  0x23, 0x48, 0x29, 0x00, 0x84, 0x67, 0xbe, 0x18,
                                                0x6c, 0x3d, 0xe1, 0x4a, 0xae, 0x72, 0xd6, 0x2c,
                                                0x23, 0x48, 0x29, 0x00, 0x84, 0x67, 0xbe, 0x18,
                                                0x6c, 0x3d, 0xe1, 0x4a, 0xae, 0x72, 0xd6, 0x2c};

static std::array<unsigned char, 16> iv_s = {  0x23, 0x48, 0x29, 0x00, 0x84, 0x67, 0xbe, 0x18,
                                                0x6c, 0x3d, 0xe1, 0x4a, 0xae, 0x72, 0xd6, 0x2c};

TEST_F(ZrtpNewCryptoTestFixture, mixedHmacSkein256) {

    string toHash("The quick brown fox jumps over the lazy dog's back");

    auto hash1(new Botan::Skein_512(256, "" ));

    hash1->setMacKey(key_s.begin(), key_s.size());
    hash1->update(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size());
    auto botanMac = hash1->final();

    ASSERT_EQ(SKEIN256_DIGEST_LENGTH, botanMac.size());

    zrtp::RetainedSecArray oldMac;
    macSkein256(key_s.begin(), key_s.size(), reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size(), oldMac);

    ASSERT_EQ(oldMac.size(), botanMac.size());
    ASSERT_EQ(SKEIN256_DIGEST_LENGTH, oldMac.size());

    ASSERT_TRUE(oldMac.equals(botanMac.data(), botanMac.size()));
    delete hash1;
}

TEST_F(ZrtpNewCryptoTestFixture, mixedHmacSkein384) {

    string toHash("The quick brown fox jumps over the lazy dog's back");

    auto hash1(new Botan::Skein_512(384, "" ));

    hash1->setMacKey(key_s.begin(), key_s.size());
    hash1->update(reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size());
    auto botanMac = hash1->final();

    ASSERT_EQ(SKEIN384_DIGEST_LENGTH, botanMac.size());

    zrtp::RetainedSecArray oldMac;
    macSkein384(key_s.begin(), key_s.size(), reinterpret_cast<const uint8_t *>(toHash.data()), toHash.size(), oldMac);

    ASSERT_EQ(oldMac.size(), botanMac.size());
    ASSERT_EQ(SKEIN384_DIGEST_LENGTH, oldMac.size());

    ASSERT_TRUE(oldMac.equals(botanMac.data(), botanMac.size()));
    delete hash1;
}

TEST_F(ZrtpNewCryptoTestFixture, mixedAesCfb256) {

    string toEncrypt("The quick brown fox jumps over the lazy dog's back");

    auto enc = Botan::Cipher_Mode::create_or_throw("AES-256/CFB", Botan::ENCRYPTION);

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt(toEncrypt.data(), toEncrypt.data()+toEncrypt.length());

    enc->set_key(key_s.begin(), key_s.size());
    enc->start(iv_s.begin(), iv_s.size());
    enc->finish(pt);

    secUtilities::SecureArrayFlex pt_old(reinterpret_cast<uint8_t const *>(toEncrypt.data()), toEncrypt.size());

    aesCfbEncrypt(key_s.data(), 32, iv_s.begin(), pt_old.data(), (int32_t)pt_old.size());
    ASSERT_TRUE(pt_old.equals(pt.data(), pt.size()));

    // Decrypt and check result.
    auto dec = Botan::Cipher_Mode::create_or_throw("AES-256/CFB", Botan::DECRYPTION);
    dec->set_key(key_s.begin(), key_s.size());
    dec->start(iv_s.begin(), iv_s.size());
    dec->finish(pt);

    std::string x;
    x.assign(reinterpret_cast<char const *>(pt.data()), pt.size());
    ASSERT_TRUE(x == toEncrypt);

    aesCfbDecrypt(key_s.data(), 32, iv_s.begin(), pt_old.data(), (int32_t)pt_old.size());
    x.assign(reinterpret_cast<char const *>(pt_old.data()), pt_old.size());
    ASSERT_TRUE(x == toEncrypt);
}

TEST_F(ZrtpNewCryptoTestFixture, mixedTwofishCfb256) {

    string toEncrypt("The quick brown fox jumps over the lazy dog's back");

    auto enc = Botan::Cipher_Mode::create_or_throw("Twofish/CFB", Botan::ENCRYPTION);

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt(toEncrypt.data(), toEncrypt.data()+toEncrypt.size());

    enc->set_key(key_s.begin(), key_s.size());
    enc->start(iv_s.begin(), iv_s.size());
    enc->finish(pt);

    secUtilities::SecureArrayFlex pt_old(reinterpret_cast<uint8_t const *>(toEncrypt.data()), toEncrypt.size());

    twoCfbEncrypt(key_s.data(), 32, iv_s.begin(), pt_old.data(), (int32_t)pt_old.size());
    ASSERT_TRUE(pt_old.equals(pt.data(), pt.size()));

//    std::cout << "Encrypted: " << *zrtp::Utilities::hexdump("Encrypted", pt.data(), pt.size()) << '\n';

    // Decrypt and check result.
    auto dec = Botan::Cipher_Mode::create_or_throw("Twofish/CFB", Botan::DECRYPTION);
    dec->set_key(key_s.begin(), key_s.size());
    dec->start(iv_s.begin(), iv_s.size());
    dec->finish(pt);

    std::string x;
    x.assign(reinterpret_cast<char const *>(pt.data()), pt.size());
    ASSERT_TRUE(x == toEncrypt);

    twoCfbDecrypt(key_s.data(), 32, iv_s.begin(), pt_old.data(), (int32_t)pt_old.size());
    x.assign(reinterpret_cast<char const *>(pt_old.data()), pt_old.size());
    ASSERT_TRUE(x == toEncrypt);

//    std::cout << "Decrypted: " << x << '\n';
}

TEST_F(ZrtpNewCryptoTestFixture, mixedEcDh41417) {
// Setup with existing DH code fpr Alice
    ZrtpDH aliceDh(e414, ZrtpDH::Commit);

    zrtp::SecureArray1k alicePubTmp;
    auto aliceKeyLen = aliceDh.fillInPubKeyBytes(alicePubTmp);

    vector<uint8_t > alicePubKey(aliceKeyLen+1);
    alicePubKey.at(0) = 4;      // 4 -> magic number, shows x,y coordinates are in uncompressed format
    memcpy(alicePubKey.data()+1, alicePubTmp.data(), aliceKeyLen);

// Using Botan lib for Bob, generate curve41417 keys
    ZrtpBotanRng rng;
    std::string kdf = "Raw";
    Botan::Curve41417_PrivateKey keyBob(rng);
    Botan::PK_Key_Agreement ecdhBob(keyBob, rng, kdf);
    auto bobPubKey = keyBob.public_value();

// Agree on keys. Alice first
    zrtp::SecureArray1k aliceSharedData;
    ASSERT_EQ(0, aliceDh.checkPubKey(bobPubKey.data()));    // Force error
    ASSERT_EQ(1, aliceDh.checkPubKey(bobPubKey.data()+1));  // check must return OK, secret pre-computed now
    aliceKeyLen = aliceDh.computeSecretKey(bobPubKey.data()+1, aliceSharedData);
    ASSERT_GT(aliceKeyLen, 0);

    Botan::secure_vector<uint8_t> sB = ecdhBob.derive_key(52, alicePubKey.data(), alicePubKey.size()).bits_of();

    ASSERT_EQ(aliceKeyLen, sB.size());
    ASSERT_TRUE(aliceSharedData.equals(sB.data(), aliceSharedData.size()));
}

TEST_F(ZrtpNewCryptoTestFixture, ecbModeAes256) {
    string toEncrypt("0123456789ABCDEF");       // 16 bytes, blocksize of twofish and AES

    auto enc = Botan::BlockCipher::create_or_throw("AES-256");

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt(toEncrypt.data(), toEncrypt.data()+toEncrypt.size());

    enc->set_key(key_s.data(), 32);
    enc->encrypt(pt);

    auto out = zrtp::Utilities::hexdump("Encrypted block AES-256", pt.data(), 16);
    LOGGER(DEBUGGING, "encrypted block: ", *out)

    // Decrypt and check result.
    auto dec = Botan::BlockCipher::create_or_throw("AES-256");
    dec->set_key(key_s.data(), 32);
    dec->decrypt(pt);

    std::string x;
    x.assign(reinterpret_cast<char const *>(pt.data()), pt.size());
    ASSERT_TRUE(x == toEncrypt);
}

TEST_F(ZrtpNewCryptoTestFixture, ecbModeAes128) {
    string toEncrypt("0123456789ABCDEF");       // 16 bytes, blocksize of twofish and AES

    auto enc = Botan::BlockCipher::create_or_throw("AES-128");

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt(toEncrypt.data(), toEncrypt.data()+toEncrypt.size());

    enc->set_key(key_s.data(), 16);
    enc->encrypt(pt);

    auto out = zrtp::Utilities::hexdump("Encrypted block AES-128", pt.data(), 16);
    LOGGER(DEBUGGING, "encrypted block: ", *out)

    // Decrypt and check result.
    auto dec = Botan::BlockCipher::create_or_throw("AES-128");
    dec->set_key(key_s.data(), 16);
    dec->decrypt(pt);

    std::string x;
    x.assign(reinterpret_cast<char const *>(pt.data()), pt.size());
    ASSERT_TRUE(x == toEncrypt);
}

TEST_F(ZrtpNewCryptoTestFixture, ecbModeTwofish256) {
    string toEncrypt("0123456789ABCDEF");       // 16 bytes, blocksize of twofish and AES

    auto enc = Botan::BlockCipher::create_or_throw("Twofish");

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt(toEncrypt.data(), toEncrypt.data()+toEncrypt.size());

    enc->set_key(key_s.data(), 32);
    enc->encrypt(pt);

    auto out = zrtp::Utilities::hexdump("Encrypted block Twofish", pt.data(), 16);
    LOGGER(DEBUGGING, "encrypted block: ", *out)

    // Decrypt and check result.
    auto dec = Botan::BlockCipher::create_or_throw("Twofish");
    dec->set_key(key_s.data(), 32);
    dec->decrypt(pt);

    std::string x;
    x.assign(reinterpret_cast<char const *>(pt.data()), pt.size());
    ASSERT_TRUE(x == toEncrypt);
}

TEST_F(ZrtpNewCryptoTestFixture, ecbModeTwofish128) {
    string toEncrypt("0123456789ABCDEF");       // 16 bytes, blocksize of twofish and AES

    auto enc = Botan::BlockCipher::create_or_throw("Twofish");

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt(toEncrypt.data(), toEncrypt.data()+toEncrypt.size());

    enc->set_key(key_s.data(), 16);
    enc->encrypt(pt);

    auto out = zrtp::Utilities::hexdump("Encrypted block Twofish 128", pt.data(), 16);
    LOGGER(DEBUGGING, "encrypted block: ", *out)

    // Decrypt and check result.
    auto dec = Botan::BlockCipher::create_or_throw("Twofish");
    dec->set_key(key_s.data(), 16);
    dec->decrypt(pt);

    std::string x;
    x.assign(reinterpret_cast<char const *>(pt.data()), pt.size());
    ASSERT_TRUE(x == toEncrypt);
}
