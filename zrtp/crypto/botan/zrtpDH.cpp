/*
 * Copyright 2006 - 2018, Werner Dittmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** Copyright (C) 2006, 2009, 2017, 2020
 *
 * @author  Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <cstring>

#include "crypto/zrtpDH.h"
#include "libzrtpcpp/ZrtpTextData.h"
#include "botancrypto/ZrtpBotanRng.h"
#include "common/Utilities.h"
#include "botan_all.h"
#include "botancrypto/ZrtpCurve41417.h"

void randomZRTP(uint8_t *buf, int32_t length)
{
    ZrtpBotanRng::getRandomData(buf, length);
}

// ZRTP does not use any built-in KDF because it defines own KDFs
constexpr char kdfString[] ="Raw";

struct ZrtpDH::dhCtx {
    // PK_Key_Agreement_Key is a superclass of all DH private key classes
    // (multiple inheritance of the DH private keys)
    std::unique_ptr<Botan::PK_Key_Agreement_Key> eccPrivateKey;
    std::unique_ptr<secUtilities::SecureArrayFlex> sntrupSecretKey;
    std::unique_ptr<secUtilities::SecureArrayFlex> sntrupPublicKey;
    std::unique_ptr<secUtilities::SecureArrayFlex> sntrupCipherText;
};

std::string
ZrtpDH::version() {
    return "Botan";
}

ZrtpDH::ZrtpDH(const char* type) : ctx(std::make_unique<ZrtpDH::dhCtx>()) {

    // Well - the algo type is only 4 char thus cast to int32 and compare
    if (*(int32_t*)type == *(int32_t*)dh2k) {
        pkType = DH2K;
    }
    else if (*(int32_t*)type == *(int32_t*)dh3k) {
        pkType = DH3K;
    }
    else if (*(int32_t*)type == *(int32_t*)ec25) {
        pkType = EC25;
    }
    else if (*(int32_t*)type == *(int32_t*)ec38) {
        pkType = EC38;
    }
    else if (*(int32_t*)type == *(int32_t*)e255) {
        pkType = E255;
    }
    else if (*(int32_t*)type == *(int32_t*)e414) {
        pkType = E414;
    }
    else if (*(int32_t*)type == *(int32_t*)np06) {
        pkType = NP06;
    }
    else if (*(int32_t*)type == *(int32_t*)np09) {
        pkType = NP09;
    }
    else if (*(int32_t*)type == *(int32_t*)np12) {
        pkType = NP12;
    }
    else {
        errorCode = UNKNOWN_ALGORITHM;
        return;
    }

    errorCode = SUCCESS;
    ZrtpBotanRng rng;

    switch (pkType) {
        case DH2K:
            ctx->eccPrivateKey = std::make_unique<Botan::DH_PrivateKey>(rng, Botan::DL_Group("modp/ietf/2048"));
            break;

        case DH3K:
            ctx->eccPrivateKey = std::make_unique<Botan::DH_PrivateKey>(rng, Botan::DL_Group("modp/ietf/3072"));
            break;

        case EC25:
            ctx->eccPrivateKey = std::make_unique<Botan::ECDH_PrivateKey>(rng, Botan::EC_Group("secp256r1"));
            break;

        case EC38:
            ctx->eccPrivateKey = std::make_unique<Botan::ECDH_PrivateKey>(rng, Botan::EC_Group("secp384r1"));
            break;

        case E255:
            ctx->eccPrivateKey = std::make_unique<Botan::Curve25519_PrivateKey>(rng);
            break;

        case E414:
        case NP06:
        case NP09:
        case NP12:
            ctx->eccPrivateKey = std::make_unique<Botan::Curve41417_PrivateKey>(rng);
            break;
    }
}

ZrtpDH::~ZrtpDH() {
    if (ctx == nullptr)
        return;

    ctx->eccPrivateKey.reset();
}

void ZrtpDH::generateSntrupKeyPair() const {
    switch (pkType) {
        case NP06:
            ctx->sntrupSecretKey = std::make_unique<secUtilities::SecureArrayFlex>(SNTRUP_CRYPTO_SECRETKEYBYTES_653);
            ctx->sntrupPublicKey = std::make_unique<secUtilities::SecureArrayFlex>(SNTRUP_CRYPTO_PUBLICKEYBYTES_653);
            crypto_kem_sntrup653_keypair(ctx->sntrupPublicKey->data(), ctx->sntrupSecretKey->data());
            ctx->sntrupSecretKey->size(SNTRUP_CRYPTO_SECRETKEYBYTES_653);
            ctx->sntrupPublicKey->size(SNTRUP_CRYPTO_PUBLICKEYBYTES_653);
            break;

        case NP09:
            ctx->sntrupSecretKey = std::make_unique<secUtilities::SecureArrayFlex>(SNTRUP_CRYPTO_SECRETKEYBYTES_953);
            ctx->sntrupPublicKey = std::make_unique<secUtilities::SecureArrayFlex>(SNTRUP_CRYPTO_PUBLICKEYBYTES_953);
            crypto_kem_sntrup953_keypair(ctx->sntrupPublicKey->data(), ctx->sntrupSecretKey->data());
            ctx->sntrupSecretKey->size(SNTRUP_CRYPTO_SECRETKEYBYTES_953);
            ctx->sntrupPublicKey->size(SNTRUP_CRYPTO_PUBLICKEYBYTES_953);
            break;

        case NP12:
            ctx->sntrupSecretKey = std::make_unique<secUtilities::SecureArrayFlex>(SNTRUP_CRYPTO_SECRETKEYBYTES_1277);
            ctx->sntrupPublicKey = std::make_unique<secUtilities::SecureArrayFlex>(SNTRUP_CRYPTO_PUBLICKEYBYTES_1277);
            crypto_kem_sntrup1277_keypair(ctx->sntrupPublicKey->data(), ctx->sntrupSecretKey->data());
            ctx->sntrupSecretKey->size(SNTRUP_CRYPTO_SECRETKEYBYTES_1277);
            ctx->sntrupPublicKey->size(SNTRUP_CRYPTO_PUBLICKEYBYTES_1277);
            break;

        default:
            break;
    }
}

size_t ZrtpDH::computeSecretKey(uint8_t * pubKeyBytes, zrtp::SecureArray1k& secret, MessageType msgType) {

    auto const length = getSharedSecretSize();
    ZrtpBotanRng rng;
    Botan::secure_vector<uint8_t> sharedSecret;

    try {
        switch(pkType) {
            case DH2K:
            case DH3K: {
                Botan::PK_Key_Agreement dhBob(*ctx->eccPrivateKey, rng, kdfString);
                sharedSecret = dhBob.derive_key(length, pubKeyBytes, length).bits_of();
                secret.assign(sharedSecret.data(), sharedSecret.size());
                zap(sharedSecret);
                return secret.size();
            }

            // Note: the `length` argument in derive_key() functions below is ignored
            // because the key agreement uses `raw`.Thus, no KDF is in use. The length
            // of the shared secret ist the length of the X-coordinate of the point on
            // the curve.
            case EC25:
            case EC38:
            case E414: {
                std::vector<uint8_t> pubKey(getPubKeySize() + 1);
                pubKey.at(0) = 4;               // 4 -> magic number: x, y coordinates are in uncompressed format
                memcpy(pubKey.data() + 1, pubKeyBytes, getPubKeySize());

                Botan::PK_Key_Agreement ecdhBob(*ctx->eccPrivateKey, rng, kdfString);
                sharedSecret = ecdhBob.derive_key(length, pubKey).bits_of();

                secret.assign(sharedSecret.data(), sharedSecret.size());
                Botan::zap(sharedSecret);
                return secret.size();
            }

            case E255: {
                Botan::PK_Key_Agreement ecdhBob(*ctx->eccPrivateKey, rng, kdfString);
                sharedSecret = ecdhBob.derive_key(length, pubKeyBytes, getPubKeySize()).bits_of();

                secret.assign(sharedSecret.data(), sharedSecret.size());
                Botan::zap(sharedSecret);
                return secret.size();
            }

            // Get SIDH shared secret data first, copy into return array, then
            // get E414 shared secret in an own array and append it to the SIDHp503 shared secret
            case NP06:
            case NP09:
            case NP12: {
                auto offset = computeSntrupSharedSecret(pubKeyBytes, secret, msgType);
                zrtp::SecureArray1k e414secret;

                std::vector<uint8_t > coordinates;
                auto isDecompressed = Botan::Curve41417_PrivateKey::decompress_y_coordinate(
                        pubKeyBytes + offset, coordinates);

                if (!isDecompressed) {
                    return -1;
                }
                // Copied from case E414 to avoid too much data copying
                // decompress already returns a correct format.
                Botan::PK_Key_Agreement ecdhBob(*ctx->eccPrivateKey, rng, kdfString);
                sharedSecret = ecdhBob.derive_key(length, coordinates).bits_of();
                secret.append(sharedSecret.data(), sharedSecret.size());
                Botan::zap(sharedSecret);
                return secret.size();
            }

            default:
                break;

        }
    } catch(Botan::Exception& e) {
        zap(sharedSecret);
    }
    return -1;
}

size_t ZrtpDH::computeSntrupSharedSecret(uint8_t *pubKeyBytes, zrtp::SecureArray1k& secret, MessageType msgType) {
    int offsetNextKeyData = -1;
    switch (pkType) {
        case NP06:
            if (msgType == Commit) {
                // commit packet contains SNTRUP public key, generate/encrypt shared key
                offsetNextKeyData = SNTRUP_CRYPTO_PUBLICKEYBYTES_653;
                ctx->sntrupCipherText = std::make_unique<secUtilities::SecureArrayFlex>(SNTRUP_CRYPTO_CIPHERTEXTBYTES_653);
                crypto_kem_sntrup653_enc(ctx->sntrupCipherText->data(), secret.data(), pubKeyBytes);
                ctx->sntrupCipherText->size(SNTRUP_CRYPTO_CIPHERTEXTBYTES_653);
            } else {
                // DHPart1 packet contains SNTRUP cipher text, decrypt it to get shared key
                offsetNextKeyData = SNTRUP_CRYPTO_CIPHERTEXTBYTES_653;
                crypto_kem_sntrup653_dec(secret.data(), pubKeyBytes, ctx->sntrupSecretKey->data() );
            }
            break;

        case NP09:
            if (msgType == Commit) {
                // commit packet contains SNTRUP public key, generate/encrypt shared key
                offsetNextKeyData = SNTRUP_CRYPTO_PUBLICKEYBYTES_953;
                ctx->sntrupCipherText = std::make_unique<secUtilities::SecureArrayFlex>(SNTRUP_CRYPTO_CIPHERTEXTBYTES_953);
                crypto_kem_sntrup953_enc(ctx->sntrupCipherText->data(), secret.data(), pubKeyBytes);
                ctx->sntrupCipherText->size(SNTRUP_CRYPTO_CIPHERTEXTBYTES_953);
            } else {
                // DHPart1 packet contains SNTRUP cipher text, decrypt it to get shared key
                offsetNextKeyData = SNTRUP_CRYPTO_CIPHERTEXTBYTES_953;
                crypto_kem_sntrup953_dec(secret.data(), pubKeyBytes, ctx->sntrupSecretKey->data());
            }
            break;

        case NP12:
            if (msgType == Commit) {
                // commit packet contains SNTRUP public key, generate/encrypt shared key
                offsetNextKeyData = SNTRUP_CRYPTO_PUBLICKEYBYTES_1277;
                ctx->sntrupCipherText = std::make_unique<secUtilities::SecureArrayFlex>(SNTRUP_CRYPTO_CIPHERTEXTBYTES_1277);
                crypto_kem_sntrup1277_enc(ctx->sntrupCipherText->data(), secret.data(), pubKeyBytes);
                ctx->sntrupCipherText->size(SNTRUP_CRYPTO_CIPHERTEXTBYTES_1277);
            } else {
                // DHPart1 packet contains SNTRUP cipher text, decrypt it to get shared key
                offsetNextKeyData = SNTRUP_CRYPTO_CIPHERTEXTBYTES_1277;
                crypto_kem_sntrup1277_dec(secret.data(), pubKeyBytes, ctx->sntrupSecretKey->data());
            }
            break;

        default:
            break;
    }
    secret.size(SNTRUP_CRYPTO_BYTES);
    return offsetNextKeyData;
}

size_t ZrtpDH::getSharedSecretSize() const
{
    switch (pkType) {
        case DH2K:
            return 2048/8;

        case DH3K:
            return 3072/8;

        case EC25:
            return 32;

        case EC38:
            return 48;

        case E255:
            return 32;

        case E414:
            return 52;

        case NP06:
        case NP09:
        case NP12:
            return SNTRUP_CRYPTO_BYTES + 52;    // combination of SNTRUP and curve 414

        default:
            return 0;
    }
}

size_t ZrtpDH::getPubKeySize() const
{
    switch (pkType) {
        case DH2K:
        case DH3K:
            return (ctx->eccPrivateKey->key_length() / 8);

        case EC25:
        case EC38:
        case E414:
            return ctx->eccPrivateKey->key_length() / 8 * 2;          // times 2 -> x and y coordinate

        case E255:
            return ((ctx->eccPrivateKey->key_length() + 7) / 8);

        case NP06:
        case NP09:
        case NP12:
            return -1;

        default:
            return 0;
    }
}

size_t ZrtpDH::getPubKeyBytes(zrtp::SecureArray4k& pubKey, MessageType msgType) const
{
    switch (pkType) {
        case DH2K:
            case DH3K: {
                // get len of pub_key, prepend with zeros to DH size
                auto size = getPubKeySize();
                size_t prepend = getSharedSecretSize() - size;
                if (prepend > 0) {
                    memset(pubKey.data(), 0, prepend);
                }
                memcpy(pubKey.data() + prepend, ctx->eccPrivateKey->public_value().data(), ctx->eccPrivateKey->public_value().size());
                pubKey.size(prepend + size);
                return prepend + size;
            }

        case EC25:
        case EC38:
        case E414:
            pubKey.assign(ctx->eccPrivateKey->public_value().data() + 1, ctx->eccPrivateKey->public_value().size() - 1);
            return pubKey.size();

        case E255:
            pubKey.assign(ctx->eccPrivateKey->public_value().data(), ctx->eccPrivateKey->public_value().size());
            return pubKey.size();

            // Get SIDH public key data first, copy into return array, then
            // get E414 compressed public key in an own array and append it to the SIDHp503 public key
        case NP06:
        case NP09:
        case NP12: {
            if (msgType == DhPart1) {
                pubKey.assign(*ctx->sntrupCipherText);
            } else {
                generateSntrupKeyPair();
                pubKey.assign(*ctx->sntrupPublicKey);
            }

            auto dhPrivateKey = dynamic_cast<Botan::Curve41417_PrivateKey*>(ctx->eccPrivateKey.get());
            auto const & compressed =
                    dhPrivateKey->Botan::Curve41417_PublicKey::public_value(Botan::Point41417p::COMPRESSED);
            pubKey.append(compressed.data(), compressed.size());
            return pubKey.size();
        }
        default:
            break;

   }

//    LOGGER(DEBUGGING, __func__, " <-- Error return");
    return 0;
}

int32_t ZrtpDH::checkPubKey(uint8_t *pubKeyBytes)
{
    ZrtpBotanRng rng;

    switch (pkType) {
        case DH2K:
        case DH3K: {
            // In these cases ctx private key actually holds a DH private key which
            // is a subclass of Botan::PK_Key_Agreement_Key. This downcast is valid.
            auto dhPrivateKey = dynamic_cast<Botan::DH_PrivateKey*>(ctx->eccPrivateKey.get());
            const auto& dhGroup = dhPrivateKey->get_group();
            auto singleLen = getPubKeySize();
            auto pubKeyBigInt = Botan::BigInt(pubKeyBytes, singleLen);

            auto otherPublicKey = Botan::DH_PublicKey(dhGroup, pubKeyBigInt);
            return !otherPublicKey.check_key(rng, false) ? 0 : 1;
        }

        case E255: {
            auto singleLen = getPubKeySize();
            auto pubKeyVector = std::vector<uint8_t>(pubKeyBytes, pubKeyBytes + singleLen);
            auto otherPublicKey = Botan::Curve25519_PublicKey(pubKeyVector);
            return !otherPublicKey.check_key(rng, false) ? 0 : 1;
        }

        case EC25:
        case EC38: {
            // In these cases ctx private key actually holds a ECDH private key which
            // is a subclass of Botan::PK_Key_Agreement_Key. This downcast is valid.
            auto ecPrivateKey = dynamic_cast<Botan::ECDH_PrivateKey*>(ctx->eccPrivateKey.get());
            const auto& ecGroup = ecPrivateKey->domain();
            auto singleLen = getPubKeySize() / 2;     // function returns size of X + Y size

            auto xBig = Botan::BigInt(pubKeyBytes, singleLen);
            auto yBig = Botan::BigInt(pubKeyBytes+singleLen, singleLen);
            auto pubPoint = ecGroup.point(xBig, yBig);

            auto otherPublicKey = Botan::ECDH_PublicKey(ecGroup, pubPoint);
            return !otherPublicKey.check_key(rng, false) ? 0 : 1;
        }

        case E414: {
            auto otherPublicKey = Botan::Curve41417_PublicKey(pubKeyBytes);
            return !otherPublicKey.check_key(rng, false) ? 0 : 1;
        }

            // No check for SIDH algorithm yet, check E414 only.
        case NP06:
        case NP09:
        case NP12: {
            // Not needed in case of compressed keys, implicit when de-compressing
            return 1;
        }
        default: {
           return 0;
        }
    }
}

const char* ZrtpDH::getDHtype() const
{
    switch (pkType) {
        case DH2K:
            return dh2k;
        case DH3K:
            return dh3k;
        case EC25:
            return ec25;
        case EC38:
            return ec38;
        case E255:
            return e255;
        case E414:
            return e414;
        case NP06:
            return np06;
        case NP09:
            return np09;
        case NP12:
            return np12;
        default:
            return nullptr;
    }
}
