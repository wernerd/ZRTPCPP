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
#include <libzrtpcpp/ZIDRecordDb.h>
#include <libzrtpcpp/zrtpCacheDbBackend.h>

#ifndef _ZIDCACHEDB_H_
#define _ZIDCACHEDB_H_


/**
 * @file ZIDCacheDb.h
 * @brief ZID cache management
 *
 * A ZID file stores (caches) some data that helps ZRTP to achives its
 * key continuity feature. See @c ZIDRecordDb for further info which data
 * the ZID file contains.
 *
 * @ingroup GNU_ZRTP
 * @{
 */

/**
 * This class implements a ZID (ZRTP Identifiers) file.
 *
 * The interface defintion @c ZIDCache.h contains the method documentation.
 * The ZID cache file holds information about peers.
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZIDCacheDb: public ZIDCache {

private:

    void *zidFile;
    unsigned char associatedZid[IDENTIFIER_LEN] = {0};

    dbCacheOps_t cacheOps = { nullptr };

    char errorBuffer[DB_CACHE_ERR_BUFF_SIZE] = {'\0'};

    void formatOutput(remoteZidRecord_t *remZid, const char *nameBuffer, std::string *output);

public:

    ZIDCacheDb(): zidFile(nullptr) {
        getDbCacheOps(&cacheOps);
    };

    ~ZIDCacheDb() override;

    int open(char *name) override;

    bool isOpen() override { return (zidFile != nullptr); };

    void close() override;

    std::unique_ptr<ZIDRecord> getRecord(unsigned char *zid) override;

    unsigned int saveRecord(ZIDRecord& zidRecord) override;

    const unsigned char* getZid() override { return associatedZid; };

    int32_t getPeerName(const uint8_t *peerZid, std::string *name) override;

    void putPeerName(const uint8_t *peerZid, const std::string& name) override;

    void cleanup() override;

    void *prepareReadAll() override;

    void *readNextRecord(void *stmt, std::string *name) override;

    void closeOpenStatement(void *stmt) override;
};

/**
 * @}
 */
#endif
