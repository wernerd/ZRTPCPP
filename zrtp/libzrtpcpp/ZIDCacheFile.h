/*
  Copyright (C) 2006-2013 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>

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
    unsigned char associatedZid[IDENTIFIER_LEN];

    void createZIDFile(char* name);
    void checkDoMigration(char* name);

public:

    ZIDCacheFile(): zidFile(NULL) {};

    ~ZIDCacheFile() override;

    int open(char *name) override;

    bool isOpen() override;

    void close() override;

    ZIDRecord *getRecord(unsigned char *zid) override;

    unsigned int saveRecord(ZIDRecord *zidRecord) override;

    const unsigned char* getZid() override;

    int32_t getPeerName(const uint8_t *peerZid, std::string *name) override;

    void putPeerName(const uint8_t *peerZid, const std::string name) override;

    // Not implemented for file based cache
    void cleanup() override;
    void *prepareReadAll() override;
    void *readNextRecord(void *stmt, std::string *output) override;
    void closeOpenStatment(void *stmt) override;


};

/**
 * @}
 */
#endif
