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

#include <zrtp/crypto/zrtpDH.h>
#include <zrtp/libzrtpcpp/ZrtpTextData.h>
#include <botancrypto/ZrtpBotanRng.h>
#include <common/Utilities.h>
#include "botan_all.h"
#include "botancrypto/ZrtpCurve41417.h"

#ifdef SIDH_SUPPORT
#include "cpp/SidhWrapper.h"
#endif

void randomZRTP(uint8_t *buf, int32_t length)
{
    ZrtpBotanRng::getRandomData(buf, length);
}

// ZRTP does not use any built-in KDF because it defines own KDFs
static char const kdfString[] ="Raw";

struct ZrtpDH::dhCtx {
    // PK_Key_Agreement_Key is a superclass of all DH private key classes
    // (multiple inheritance of the DH private keys)
    std::unique_ptr<Botan::PK_Key_Agreement_Key> privKey;
#ifdef SIDH_SUPPORT
    std::unique_ptr<secUtilities::SecureArrayFlex> sidhPrivKey;
    std::unique_ptr<secUtilities::SecureArrayFlex> sidhPubKey;
#endif
};

std::string
ZrtpDH::version() {
    return "Botan";
}

ZrtpDH::ZrtpDH(const char* type, ProtocolState state) : protocolState(state), ctx(std::make_unique<ZrtpDH::dhCtx>()) {

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
#ifdef SIDH_SUPPORT
    else if (*(int32_t*)type == *(int32_t*)sdh5) {
        pkType = SDH5;
    }
    else if (*(int32_t*)type == *(int32_t*)sdh7) {
        pkType = SDH7;
    }
    else if (*(int32_t*)type == *(int32_t*)pq54) {
        pkType = PQ54;
    }
    else if (*(int32_t*)type == *(int32_t*)pq64) {
        pkType = PQ64;
    }
    else if (*(int32_t*)type == *(int32_t*)pq74) {
        pkType = PQ74;
    }
#endif
    else {
        errorCode = UNKNOWN_ALGORITHM;
        return;
    }

    errorCode = SUCCESS;
    ZrtpBotanRng rng;

    switch (pkType) {
        case DH2K:
            ctx->privKey = std::make_unique<Botan::DH_PrivateKey>(rng, Botan::DL_Group("modp/ietf/2048"));
            break;

        case DH3K:
            ctx->privKey = std::make_unique<Botan::DH_PrivateKey>(rng, Botan::DL_Group("modp/ietf/3072"));
            break;

        case EC25:
            ctx->privKey = std::make_unique<Botan::ECDH_PrivateKey>(rng, Botan::EC_Group("secp256r1"));
            break;

        case EC38:
            ctx->privKey = std::make_unique<Botan::ECDH_PrivateKey>(rng, Botan::EC_Group("secp384r1"));
            break;

        case E255:
            ctx->privKey = std::make_unique<Botan::Curve25519_PrivateKey>(rng);
            break;

        case E414:
            ctx->privKey = std::make_unique<Botan::Curve41417_PrivateKey>(rng);
            break;

#ifdef SIDH_SUPPORT
        case SDH5:
        case SDH7:
            generateSidhKeyPair();
            break;

        case PQ54:
        case PQ64:
        case PQ74:
            generateSidhKeyPair();
            ctx->privKey = std::make_unique<Botan::Curve41417_PrivateKey>(rng);
            break;
#endif
    }
}

ZrtpDH::~ZrtpDH() {
    if (ctx == nullptr)
        return;

    ctx->privKey.reset();
}

#ifdef SIDH_SUPPORT
SidhWrapper::SidhType ZrtpDH::getSidhType() const
{
    switch (pkType) {
        case SDH5:
        case PQ54:
#ifndef SIDH_COMPRESSED_WDI
            return SidhWrapper::P503;
#else
            return SidhWrapper::P503Comp;
#endif

        case PQ64:
#ifndef SIDH_COMPRESSED_WDI
            return SidhWrapper::P610;
#else
            return SidhWrapper::P610Comp;
#endif

        case SDH7:
        case PQ74:
#ifndef SIDH_COMPRESSED_WDI
            return SidhWrapper::P751;
#else
            return SidhWrapper::P751Comp;
#endif

        default:
            return static_cast<SidhWrapper::SidhType>(0);
    }
}

void ZrtpDH::generateSidhKeyPair() {
    SidhWrapper::SidhType sidhType = getSidhType();

    auto lengths = SidhWrapper::getFieldLengths(sidhType);

    // Get a secure flex array with the exact required capacity - this is then
    // also the length of the SIDH public key
    ctx->sidhPubKey = std::make_unique<secUtilities::SecureArrayFlex>(lengths->publicKey);
    if (protocolState == Commit) {
        ctx->sidhPrivKey = std::make_unique<secUtilities::SecureArrayFlex>(lengths->privateKeyA);
        SidhWrapper::random_mod_order_A(sidhType, ctx->sidhPrivKey->data());
        SidhWrapper::EphemeralKeyGeneration_A(sidhType, ctx->sidhPrivKey->data(), ctx->sidhPubKey->data());
    }
    else if (protocolState == DhPart1){
        ctx->sidhPrivKey = std::make_unique<secUtilities::SecureArrayFlex>(lengths->privateKeyB);
        SidhWrapper::random_mod_order_B(sidhType, ctx->sidhPrivKey->data());
        SidhWrapper::EphemeralKeyGeneration_B(sidhType, ctx->sidhPrivKey->data(), ctx->sidhPubKey->data());
    }
}
#endif

size_t ZrtpDH::secretKeyComputation(uint8_t *pubKeyBytes, zrtp::SecureArray1k& secret, int algorithm) {

    auto const length = getSharedSecretSize();
    ZrtpBotanRng rng;
    Botan::secure_vector<uint8_t> sharedSecret;

    try {
        switch(algorithm) {
            case DH2K:
            case DH3K: {
                Botan::PK_Key_Agreement dhBob(*ctx->privKey, rng, kdfString);
                sharedSecret = dhBob.derive_key(length, pubKeyBytes, length).bits_of();
                secret.assign(sharedSecret.data(), sharedSecret.size());
                zap(sharedSecret);
                return secret.size();
            }

            // Note: the `length` argument in derive_key() functions below is ignoreed
            // because the key agreement uses `raw`.Thus, no KDF is in use. The length
            // of the shared secret ist the length of the X-coordinate of the point on
            // the curve.
            case EC25:
            case EC38:
            case E414: {
                std::vector<uint8_t> pubKey(getPubKeySize() + 1);
                pubKey.at(0) = 4;               // 4 -> magic number: x, y coordinates are in uncompressed format
                memcpy(pubKey.data() + 1, pubKeyBytes, getPubKeySize());

                Botan::PK_Key_Agreement ecdhBob(*ctx->privKey, rng, kdfString);
                sharedSecret = ecdhBob.derive_key(length, pubKey).bits_of();

                secret.assign(sharedSecret.data(), sharedSecret.size());
                Botan::zap(sharedSecret);
                return secret.size();
            }
            case E255: {
                Botan::PK_Key_Agreement ecdhBob(*ctx->privKey, rng, kdfString);
                sharedSecret = ecdhBob.derive_key(length, pubKeyBytes, getPubKeySize()).bits_of();

                secret.assign(sharedSecret.data(), sharedSecret.size());
                Botan::zap(sharedSecret);
                return secret.size();
            }
#ifdef SIDH_SUPPORT
            case SDH5:
            case SDH7: {
                computeSidhSharedSecret(pubKeyBytes, secret);
                return secret.size();
            }

            // Get SIDH shared secret data first, copy into return array, then
            // get E414 shared secret in an own array and append it to the SIDHp503 shared secret
            case PQ54:
            case PQ64:
            case PQ74:{
                computeSidhSharedSecret(pubKeyBytes, secret);
                auto offset = ctx->sidhPubKey->capacity();  // skip SIDH data, see comment in generateSidhKeyPair() above
                zrtp::SecureArray1k e414secret;
#ifndef SIDH_COMPRESSED_WDI
                secretKeyComputation(pubKeyBytes + offset, e414secret, E414);
                secret.append(e414secret);
                return secret.size();
#else
                std::vector<uint8_t > coordinates;
                auto isDecompressed = Botan::Curve41417_PrivateKey::decompress_y_coordinate(
                        pubKeyBytes + offset, coordinates);

                if (!isDecompressed) {
                    return -1;
                }
                // Copied from case E414 to avoid too much data copying
                // decompress already returns a correct format.
                Botan::PK_Key_Agreement ecdhBob(*ctx->privKey, rng, kdfString);
                sharedSecret = ecdhBob.derive_key(length, coordinates).bits_of();
                secret.append(sharedSecret.data(), sharedSecret.size());
                Botan::zap(sharedSecret);
                return secret.size();
#endif
            }

#endif
            default:
                break;

        }
    } catch(Botan::Exception& e) {
        zap(sharedSecret);
    }
    return -1;
}

size_t ZrtpDH::computeSecretKey(uint8_t *pubKeyBytes, zrtp::SecureArray1k& secret) {
    return secretKeyComputation(pubKeyBytes, secret, pkType);
}

#ifdef SIDH_SUPPORT
size_t ZrtpDH::computeSidhSharedSecret(uint8_t *pubKeyBytes, zrtp::SecureArray1k& secret)
{
    SidhWrapper::SidhType sidhType = getSidhType();

    auto lengths = SidhWrapper::getFieldLengths(sidhType);
    if (protocolState == Commit) {
        // Alice computes her shared secret using Bob's public key
        SidhWrapper::EphemeralSecretAgreement_A(sidhType, ctx->sidhPrivKey->data(), pubKeyBytes, secret.data());
    }
    else {
        // Bob computes his shared secret using Alice's public key
        SidhWrapper::EphemeralSecretAgreement_B(sidhType, ctx->sidhPrivKey->data(), pubKeyBytes, secret.data());
    }
    secret.size(lengths->sharedSecret);
    return lengths->sharedSecret;
}

size_t ZrtpDH::getSidhSharedSecretLength() const {
    SidhWrapper::SidhType sidhType = getSidhType();

    auto lengths = SidhWrapper::getFieldLengths(sidhType);
    return lengths->sharedSecret;
}
#endif

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

#ifdef SIDH_SUPPORT
        case SDH5:
        case SDH7:
            return getSidhSharedSecretLength();

        case PQ54:
        case PQ64:
        case PQ74:
            return getSidhSharedSecretLength() + 52;    // combination of SIDHp503 and curve 414
#endif
        default:
            return 0;
    }
}

size_t ZrtpDH::getPubKeySize() const
{
    switch (pkType) {
        case DH2K:
        case DH3K:
            return (ctx->privKey->key_length() / 8);

        case EC25:
        case EC38:
        case E414:
            return ctx->privKey->key_length() / 8 * 2;          // times 2 -> x and y coordinate

        case E255:
            return ((ctx->privKey->key_length() + 7) / 8);

#ifdef SIDH_SUPPORT
        case SDH5:
        case SDH7:
            return ctx->sidhPubKey->capacity();
        case PQ54:
        case PQ64:
        case PQ74:
#ifndef SIDH_COMPRESSED_WDI
            return ctx->sidhPubKey->capacity() + ctx->privKey->key_length() / 8 * 2;
#else
            return ctx->sidhPubKey->capacity() + ctx->privKey->key_length() / 8 + 1; // +1 -> format byte in this case
#endif  // SIDH_COMPRESSED_WDI
#endif  // SIDH_SUPPORT
    }
    return 0;
}

size_t ZrtpDH::getPubKeyBytes(zrtp::SecureArray1k& pubKey, int algorithm) const
{
    switch (algorithm) {
        case DH2K:
            case DH3K: {
                // get len of pub_key, prepend with zeros to DH size
                auto size = getPubKeySize();
                size_t prepend = getSharedSecretSize() - size;
                if (prepend > 0) {
                    memset(pubKey.data(), 0, prepend);
                }
                memcpy(pubKey.data() + prepend, ctx->privKey->public_value().data(), ctx->privKey->public_value().size());
                pubKey.size(prepend + size);
                return prepend + size;
            }

        case EC25:
        case EC38:
        case E414:
            pubKey.assign(ctx->privKey->public_value().data()+1, ctx->privKey->public_value().size() - 1);
            return pubKey.size();

        case E255:
            pubKey.assign(ctx->privKey->public_value().data(), ctx->privKey->public_value().size());
            return pubKey.size();

#ifdef SIDH_SUPPORT
        case SDH5:
        case SDH7: {
            auto len = getPubKeySize();
            pubKey.assign(ctx->sidhPubKey->data(), len);
            return pubKey.size();
        }

            // Get SIDH public key data first, copy into return array, then
            // get E414 compressed public key in an own array and append it to the SIDHp503 public key
        case PQ54:
        case PQ64:
        case PQ74: {
            auto len = ctx->sidhPubKey->capacity();
            pubKey.assign(ctx->sidhPubKey->data(), len);

#ifndef SIDH_COMPRESSED_WDI
            zrtp::SecureArray1k e414PubKey;
            getPubKeyBytes(e414PubKey, E414);
            pubKey.append(e414PubKey);
#else
            auto dhPrivateKey = dynamic_cast<Botan::Curve41417_PrivateKey*>(ctx->privKey.get());
            auto const & compressed =
                    dhPrivateKey->Botan::Curve41417_PublicKey::public_value(Botan::Point41417p::COMPRESSED);
            pubKey.append(compressed.data(), compressed.size());
#endif
            return pubKey.size();
        }
#endif
        default:
            break;

   }

//    LOGGER(DEBUGGING, __func__, " <-- Error return");
    return 0;
}

size_t ZrtpDH::fillInPubKeyBytes(zrtp::SecureArray1k& pubKey) const
{
    return getPubKeyBytes(pubKey, pkType);
}


int32_t ZrtpDH::checkPubKey(uint8_t *pubKeyBytes)
{
    ZrtpBotanRng rng;

    switch (pkType) {
        case DH2K:
        case DH3K: {
            // In these cases ctx private key actually holds a DH private key which
            // is a sub-class of Botan::PK_Key_Agreement_Key. This downcast is valid.
            auto dhPrivateKey = dynamic_cast<Botan::DH_PrivateKey*>(ctx->privKey.get());
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
            // is a sub-class of Botan::PK_Key_Agreement_Key. This downcast is valid.
            auto ecPrivateKey = dynamic_cast<Botan::ECDH_PrivateKey*>(ctx->privKey.get());
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

#ifdef SIDH_SUPPORT
            // No check for SIDH algorithm yet, check E414 only.
        case PQ54:
        case PQ64:
        case PQ74: {
#ifndef SIDH_COMPRESSED_WDI
            auto offset = ctx->sidhPubKey->capacity();  // skip SIDH data, see comment in generateSidhKeyPair() above
            auto otherPublicKey = Botan::Curve41417_PublicKey(pubKeyBytes+offset);
            return !otherPublicKey.check_key(rng, false) ? 0 : 1;
#else
            // Not needed in case of compressed keys, implicit when de-compressing
            return 1;
#endif
        }

            // No check for SIDH algorithm yet - return OK
        case SDH5:
        case SDH7:
            return 1;
#endif
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
        case SDH5:
            return sdh5;
        case SDH7:
            return sdh7;
        case PQ54:
            return pq54;
        case PQ64:
            return pq64;
        case PQ74:
            return pq74;
        default:
            return nullptr;
    }
}
