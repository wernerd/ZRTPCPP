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

#include <stdio.h>

#include <libzrtpcpp/ZIDCache.h>
#include <libzrtpcpp/ZIDRecordEmpty.h>

#ifndef _ZIDCACHEEMPTY_H_
#define _ZIDCACHEEMPTY_H_


/**
 * @file ZIDCacheEmpty.h
 * @brief ZID cache management
 *
 * An empty ZID file, thus thus implements an empty or non-existent
 * ZRTP cache. This is a valid option for ZRTP because ZRTP does not
 * require a cache. However, applications using ZRTP without cache
 * should check SAS on every session.
 *
 * @ingroup GNU_ZRTP
 * @{
 */

/**
 * This class implements an empty ZID (ZRTP Identifiers) file.
 *
 * The interface definition @c ZIDCache.h contains the method documentation.
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZIDCacheEmpty: public ZIDCache {

public:

    ZIDCacheEmpty() = default;

    ~ZIDCacheEmpty() override = default;

    int open(char *name) override ;

    bool isOpen() override { return true; };

    void close() override ;

    ZIDRecord *getRecord(unsigned char *zid) override;

    unsigned int saveRecord(ZIDRecord *zidRecord) override;

    const unsigned char* getZid() override { return nullptr; };

    int32_t getPeerName(const uint8_t *peerZid, std::string *name) override ;

    void putPeerName(const uint8_t *peerZid, std::string name) override ;

    // Not implemented for file based cache
    void cleanup() override {};
    void *prepareReadAll() override { return nullptr; };
    void *readNextRecord(void *stmt, std::string *output) override { return nullptr; };
    void closeOpenStatment(void *stmt) override {}


};

/**
 * @}
 */
#endif
