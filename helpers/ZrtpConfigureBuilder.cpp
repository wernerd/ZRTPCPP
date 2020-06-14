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

#include <zrtp/libzrtpcpp/ZIDCacheFile.h>
#include <zrtp/libzrtpcpp/ZIDCacheEmpty.h>
#ifdef ZID_DATABASE
#include <zrtp/libzrtpcpp/ZIDCacheDb.h>
#endif

#include <botancrypto/ZrtpBotanRng.h>
#include "ZrtpConfigureBuilder.h"

void ZrtpConfigureBuilder::addAlgorithm(char const * name, AlgoTypes type ) {
    switch (type) {
        case HashAlgorithm:
            configuration->addAlgo(type, zrtpHashes.getByName(name));
            break;
        case CipherAlgorithm:
            configuration->addAlgo(type, zrtpSymCiphers.getByName(name));
            break;
        case PubKeyAlgorithm:
            configuration->addAlgo(type, zrtpPubKeys.getByName(name));
            break;
        case SasType:
            configuration->addAlgo(type, zrtpSasTypes.getByName(name));
            break;
        case AuthLength:
            configuration->addAlgo(type, zrtpAuthLengths.getByName(name));
            break;
        default:
            configuration->addAlgo(type, zrtpPubKeys.getByName("None"));
            break;
    }
}


ZrtpConfigureBuilder&
ZrtpConfigureBuilder::initializeCache(const std::string & zidFilename, ZidCacheType cacheType, bool & isSet) {

    std::shared_ptr<ZIDCache> zf;
    uint8_t newZid[IDENTIFIER_LEN] = {0};
    isSet = true;

    switch (cacheType) {
        case NoCache:
            zf = std::make_shared<ZIDCacheEmpty>();
            ZrtpBotanRng::getRandomData(newZid, IDENTIFIER_LEN);
            zf->setZid(newZid);
            configuration->setZidCache(zf);
            return *this;

#ifdef ZID_DATABASE
        case DbCache:
            zf = std::make_shared<ZIDCacheDb>();
            break;
#endif
        case FileCache:
            zf = std::make_shared<ZIDCacheFile>();
            break;

        default:
            isSet = false;
            return *this;
    }
    if (zidFilename.empty() || zf->open((char *)zidFilename.c_str()) < 0) {
        zf.reset();
        isSet = false;
    }
    else {
        configuration->setZidCache(zf);
    }
    return *this;
}
