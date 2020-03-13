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
// Created by werner on 07.03.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#ifndef LIBZRTPCPP_ZRTPCONFIGUREBUILDER_H
#define LIBZRTPCPP_ZRTPCONFIGUREBUILDER_H

#include <memory>

#include <libzrtpcpp/ZrtpConfigure.h>
#include <libzrtpcpp/ZIDCache.h>
#include <common/osSpecifics.h>

/**
 * @brief Builder class to simplify setup of ZrtpConfigure.
 *
 * ZRTP negotiates key data using a configured set of algorithms. Each party can set its
 * own algorithms and the ZRTP implementation builds a common set and uses it to perform
 * key negotiation.
 *
 * ZRTP can offer up to seven algorithms per algorithm type, thus up to seven different
 * public key algorithms, up to seven symmetric cipher algorithms and so on. If an application
 * tries to set more than seven algorithms only the first seven are used, the others
 * are silently discarded.
 *
 * Each builder function returns a reference to the builder instance. The algorithm functions
 * add the algorithm names in the parameter order or call order. ZRTP tries to use algorithms
 * which are first in the list.
 *
 * Usage example:
 *
 * ~~~~~{.cpp}
    bool cacheIsOk = false;

    auto config = ZrtpConfigureBuilder::builder()
            .publicKeyAlgorithms(ec25, ec38)
            .cipherAlgorithms(aes3, two3)
            .initializeCache("file.data", ZrtpConfigureBuilder::FileCache, cacheIsOk)
            .build();

    // Check if cache was set-up.
    ASSERT_TRUE(cacheIsOk);

    // If application needs the cache instance
    auto zidCache = config->getZidCache();
 * ~~~~~
 *
 * The builder currently does not support mostly unused flags to enable PBX support, request SAS
 * signing or the 'paranoid' mode. Applications can set these flags directly using the returned
 * ZrtpConfigure instance.
 *
 */
class __EXPORT ZrtpConfigureBuilder {

public:

    /**
     * @brief Type of ZRTP's ZID cache.
     */
    enum ZidCacheType {
        NoCache,               //!< Don't use a ZID cache - refer to RFC6189, section 4.9.1 Cacheless Implementations about the implications
        FileCache,             //!< Use a simple, direct access file to store ZID cache data
#ifdef ZID_DATABASE
        DbCache                //!< Use Sqlite (or SqlCipher if configured) to store ZID cache data
#endif
    };

    /**
     * @brief Get a Builder for ZrtpConfigure.
     *
     * The ZRTP configuration is empty, no algorithms pre-selected. The application
     * may set some algorithms (or use the ZRTP default if not algorithms selected).
     *
     * Also the application should set the ZID cache instance.
     *
     * @return A new ZrtpConfigureBuilder
     */
    static ZrtpConfigureBuilder builder() {
        auto builder = ZrtpConfigureBuilder();
        builder.configuration->clear();
        return builder;
    }

    /**
     * @brief Configure public key algorithms.
     *
     * The application may set which public key algorithms to offer during ZRTP's key
     * negotiation. Depending on ZRTP build configuration some algorithms may not be
     * available.
     *
     * @param name Short name(s) of the public key algorithm
     * @return reference of the current instance.
     * @sa ZrtpTextData.h
     */
    ZrtpConfigureBuilder&  publicKeyAlgorithms(char const* name) { addAlgorithm(name, PubKeyAlgorithm);return *this; }

    template<typename Name, typename ...Names>
    ZrtpConfigureBuilder& publicKeyAlgorithms(Name name, Names... names) {
        addAlgorithm(name, PubKeyAlgorithm);
        publicKeyAlgorithms(names...);
        return *this;
    }

    /**
     * @brief Configure hash algorithms.
     *
     * The application may set which hash algorithms to offer during ZRTP's key
     * negotiation. Depending on ZRTP build configuration some algorithms may not be
     * available.
     *
     * @param name Short name(s) of the hash algorithm
     * @return reference of the current instance.
     * @sa ZrtpTextData.h
     */
    ZrtpConfigureBuilder&  hashAlgorithms(char const* name) { addAlgorithm(name, HashAlgorithm); return *this; }

    template<typename Name, typename ...Names>
    ZrtpConfigureBuilder& hashAlgorithms(Name name, Names... names) {
        addAlgorithm(name, HashAlgorithm);
        hashAlgorithms(names...);
        return *this;
    }

    /**
     * @brief Configure symmetric cipher algorithms.
     *
     * The application may set which symmetric cipher algorithms to offer during ZRTP's key
     * negotiation. Depending on ZRTP build configuration some algorithms may not be
     * available.
     *
     * @param name Short name(s) of the symmetric cipher algorithm
     * @return reference of the current instance.
     * @sa ZrtpTextData.h
     */
    ZrtpConfigureBuilder&  cipherAlgorithms(char const* name)  { addAlgorithm(name, CipherAlgorithm); return *this; }

    template<typename Name, typename ...Names>
    ZrtpConfigureBuilder& cipherAlgorithms(Name name, Names... names) {
        addAlgorithm(name, CipherAlgorithm);
        cipherAlgorithms(names...);
        return *this;
    }

    /**
     * @brief Configure Short Authentication String (SAS) types.
     *
     * The application may set which SAS types to offer during ZRTP's key
     * negotiation. Depending on ZRTP build configuration some algorithms may not be
     * available.
     *
     * @param name Short name(s) of the SAS types
     * @return reference of the current instance.
     * @sa ZrtpTextData.h
     */
    ZrtpConfigureBuilder&  sasTypes(char const* name) { addAlgorithm(name, SasType); return *this; }

    template<typename Name, typename ...Names>
    ZrtpConfigureBuilder& sasTypes(Name name, Names... names) {
        addAlgorithm(name, SasType);
        sasTypes(names...);
        return *this;
    }

    /**
     * @brief Configure SRTP authentication length.
     *
     * The application may set which SRTP authentication length to offer during ZRTP's key
     * negotiation. Depending on ZRTP build configuration some algorithms may not be
     * available.
     *
     * @param name Short name(s) of the SRTP authentication length
     * @return reference of the current instance.
     * @sa ZrtpTextData.h
     */
    ZrtpConfigureBuilder&  authLengths(char const* name) { addAlgorithm(name, AuthLength); return *this; }

    template<typename Name, typename ...Names>
    ZrtpConfigureBuilder& authLengths(char const* name, Names... names) {
        addAlgorithm(name, AuthLength);
        authLengths(names...);
        return *this;
    }

    /**
     * @brief Add a standard configuration using secure and fast algorithms.
     *
     * The function adds a defined set of algorithms to the configuration.
     *
     * @return reference of the current instance.
     * @sa ZrtpConfigure::addStandardConfig()
     */
    ZrtpConfigureBuilder& addStandardConfig() { configuration->addStandardConfig(); return *this; }

    /**
     * @brief Set the mandatory algorithms only.
     *
     * An application may use this to add the bare minimum of offered algorithms. This
     * is not recommended. Applications should use ZrtpConfigureBuilder::setStandardConfig,
     * some of the other pre-defined algorithm sets, or define their own configuration.
     *
     * The function adds a defined set of mandatory algorithms to the configuration.
     *
     * @return reference of the current instance.
     * @sa ZrtpConfigure::addMandatoryOnly()
     */
    ZrtpConfigureBuilder& addMandatoryOnly() { configuration->addMandatoryOnly(); return *this; }

    /**
     * @brief Initialize, open, and set the ZID cache.
     *
     * ZRTP uses a specific cache to provide key-continuity, enhanced MitM protection and a
     * simply way inform the user about encrypted sessions. For technical details refer to
     * RFC6189, section 4.9 ZID and Cache Operation.
     *
     * While it is possible to use ZRTP in a cachelss mode, it is not recommended. If an
     * application does not use a ZRTP cache it should implement additional logic to check
     * for MitM attacks, etc. In cacheless mode each ZID cache instance uses a new random ZID
     * because it has not file or DB to store a ZID.
     *
     * Using a database ZID cache is recommended because the Sqlite3 code (the database implementation)
     * already provide thread safe access to the cache. The file based cache is not thread safe.
     *
     * Multiple ZRTP sessions can use the same ZID cache file or database, thus an application usually
     * requires only one ZIDCache instance. The functions returns a shared pointer to the initialized
     * cache instance.
     *
     * @param zidFilename Qualified filename of the UID cache file or database file. Ignored if cache
     *      type is `NoCache`.
     * @param cacheType Store data in simple file, database or not at all.
     * @param isSet functions sets it to `true` if ZID cache open was OK, `false` in case of failure
     * @return reference of the current instance.
     */
    ZrtpConfigureBuilder&
    initializeCache(const std::string & zidFilename, ZidCacheType cacheType, bool & isSet);

    /**
     * @brief Set the algorithm selection policies.
     *
     * The algorithm selection policy controls which algorithm ZRTP prefers when selecting algorithms
     * to negotiate keys and to use for symmetrical encryption or HMAC etc.
     *
     * When setting `Standard` policy then ZRTP selects algorithms according to the ZRTP
     * RFC 6189 specification (section 4.1.2). This ZRTP implementation added more algorithms which
     * are not defined by NIST. When setting `PreferNonNist` policy then ZRTP prefers non-NIST
     * defined algorithms, e.g. Twofish instead of AES, Curve 414 instead of ECDH-384.
     *
     * @param pol The policy to use.
     * @return reference of the current instance.
     */
    ZrtpConfigureBuilder&
    setSelectionPolicy(ZrtpConfigure::Policy pol) { configuration->setSelectionPolicy(pol);return *this;}

    std::shared_ptr<ZrtpConfigure>
    build() { return configuration; }


private:
    ZrtpConfigureBuilder() = default;

    void addAlgorithm(char const * name, AlgoTypes type );

    std::shared_ptr<ZrtpConfigure> configuration = std::make_shared<ZrtpConfigure>();

};


#endif //LIBZRTPCPP_ZRTPCONFIGUREBUILDER_H
