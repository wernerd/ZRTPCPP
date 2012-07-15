/*
  Copyright (C) 2006-2008 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */
// #define UNIT_TEST

#include <string>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

#include <libzrtpcpp/ZIDCacheDb.h>


static ZIDCacheDb* instance;
static int errors = 0;  // maybe we will use as member of ZIDCache later...


/**
 * A poor man's factory.
 *
 * The build process must not allow to implementation classes linked
 * into the same library.
 */

ZIDCache* getZidCacheInstance() {

    if (instance == NULL) {
        instance = new ZIDCacheDb();
    }
    return instance;
}


ZIDCacheDb::~ZIDCacheDb() {
    close();
}

int ZIDCacheDb::open(char* name) {

    // check for an already active ZID file
    if (zidFile != NULL) {
        return 0;
    }
    if (cacheOps.openCache(name, &zidFile, errorBuffer) == 0)
        cacheOps.readLocalZid(zidFile, associatedZid, NULL, errorBuffer);
    else
        zidFile = NULL;

    return ((zidFile == NULL) ? -1 : 1);
}

void ZIDCacheDb::close() {

    if (zidFile != NULL) {
        cacheOps.closeCache(zidFile);
        zidFile = NULL;
    }
}

ZIDRecord *ZIDCacheDb::getRecord(unsigned char *zid) {
    ZIDRecordDb *zidRecord = new ZIDRecordDb();

    cacheOps.readRemoteZidRecord(zidFile, zid, associatedZid, zidRecord->getRecordData(), errorBuffer);

    zidRecord->setZid(zid);

    // We need to create a new ZID record.
    if (!zidRecord->isValid()) {
        zidRecord->setValid();
        zidRecord->getRecordData()->secureSince = (int64_t)time(NULL);
        cacheOps.insertRemoteZidRecord(zidFile, zid, associatedZid, zidRecord->getRecordData(), errorBuffer);
    }
    return zidRecord;
}

unsigned int ZIDCacheDb::saveRecord(ZIDRecord *zidRec) {
    ZIDRecordDb *zidRecord = reinterpret_cast<ZIDRecordDb *>(zidRec);

    cacheOps.updateRemoteZidRecord(zidFile, zidRecord->getIdentifier(), associatedZid, zidRecord->getRecordData(), errorBuffer);
    return 1;
}

const char* ZIDCacheDb::getPeerName(const uint8_t *peerZid) {
    zidNameRecord_t nameRec;

    cacheOps.readZidNameRecord(zidFile, peerZid, associatedZid, NULL, &nameRec, errorBuffer);
    if ((nameRec.flags & Valid) != Valid) {
        return NULL;
    }
    return nameRec.name;
}

void ZIDCacheDb::putPeerName(const uint8_t *peerZid, const std::string *name) {
    zidNameRecord_t nameRec;

    cacheOps.readZidNameRecord(zidFile, peerZid, associatedZid, NULL, &nameRec, errorBuffer);
    nameRec.name = (char*)name->c_str();
    if ((nameRec.flags & Valid) != Valid)
        cacheOps.insertZidNameRecord(zidFile, peerZid, associatedZid, NULL, &nameRec, errorBuffer);
    else
        cacheOps.updateZidNameRecord(zidFile, peerZid, associatedZid, NULL, &nameRec, errorBuffer);

    return;
}
