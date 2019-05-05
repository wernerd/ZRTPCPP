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

#include <cstdio>

#include <libzrtpcpp/ZIDCache.h>
#include <libzrtpcpp/ZIDRecordFile.h>

#ifndef _ZIDCACHEFILE_H_
#define _ZIDCACHEFILE_H_


/**
 * @file ZIDCacheFile.h
 * @brief ZID cache management
 *
 * A ZID file stores (caches) some data that helps ZRTP to achives its
 * key continuity feature. See @c ZIDRecord for further info which data
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

class __EXPORT ZIDCacheFile: public ZIDCache {

private:

    FILE* zidFile;
    unsigned char associatedZid[IDENTIFIER_LEN] = {0};

    void createZIDFile(char* name);
    void checkDoMigration(char* name);

public:

    ZIDCacheFile(): zidFile(nullptr) {};

    ~ZIDCacheFile() override;

    int open(char *name) override;

    bool isOpen() override { return (zidFile != nullptr); };

    void close() override;

    CacheTypes getCacheType() override { return ZIDCache::File; };

    std::unique_ptr<ZIDRecord> getRecord(unsigned char *zid) override;

    unsigned int saveRecord(ZIDRecord& zidRecord) override;

    const unsigned char* getZid() override { return associatedZid; };

    void setZid(const uint8_t *zid) override {};

    int32_t getPeerName(const uint8_t *peerZid, std::string *name) override;

    void putPeerName(const uint8_t *peerZid, const std::string& name) override;

    // Not implemented for file based cache
    void cleanup() override {};
    void *prepareReadAll() override { return nullptr; };
    void *readNextRecord(void *stmt, std::string *output) override { return nullptr; };
    void closeOpenStatement(void *stmt) override {}


};

/**
 * @}
 */
#endif
