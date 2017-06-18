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

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <time.h>

#include <libzrtpcpp/ZIDRecordFile.h>

void ZIDRecordFile::setNewRs1(const unsigned char* data, int32_t expire) {

    // shift RS1 data into RS2 position
    memcpy(record.rs2Data, record.rs1Data, RS_LENGTH);
    memcpy(record.rs2Interval, record.rs1Interval, TIME_LENGTH);

    // set new RS1 data
    memcpy(record.rs1Data, data, RS_LENGTH);

    time_t validThru;
    if (expire == -1) {
        validThru = -1;
    }
    else if (expire <= 0) {
        validThru = 0;
    }
    else {
        validThru = time(NULL) + expire;
    }

    if (sizeof(time_t) == 4) {
        long long temp = validThru;
        memcpy(record.rs1Interval, (unsigned char*)&temp, TIME_LENGTH);
    }
    else {
        memcpy(record.rs1Interval, (unsigned char*)&validThru, TIME_LENGTH);
    }
    resetRs2Valid();
    setRs1Valid();
}


bool ZIDRecordFile::isRs1NotExpired() {
    time_t current = time(NULL);
    time_t validThru;

    if (sizeof(time_t) == 4) {
        long long temp;
        memcpy((unsigned char*)&temp, record.rs1Interval, TIME_LENGTH);
        validThru = temp;
    }
    else {
        memcpy((unsigned char*)&validThru, record.rs1Interval, TIME_LENGTH);
    }

    if (validThru == -1)
        return true;
    if (validThru == 0)
        return false;
    return (current <= validThru) ? true : false;
}

bool ZIDRecordFile::isRs2NotExpired() {
    time_t current = time(NULL);
    time_t validThru;

    if (sizeof(time_t) == 4) {
        long long temp;
        memcpy((unsigned char*)&temp, record.rs2Interval, TIME_LENGTH);
        validThru = temp;
    }
    else {
        memcpy((unsigned char*)&validThru, record.rs2Interval, TIME_LENGTH);
    }

    if (validThru == -1)
        return true;
    if (validThru == 0)
        return false;
    return (current <= validThru) ? true : false;
}

void ZIDRecordFile::setMiTMData(const unsigned char* data) {
    memcpy(record.mitmKey, data, RS_LENGTH);
    setMITMKeyAvailable();
}

void ZIDRecordFile::setZid(const unsigned char *zid) {
    memcpy(record.identifier, zid, IDENTIFIER_LEN);
}

void ZIDRecordFile::setRs1Valid()    { record.flags |= RS1Valid; }

void ZIDRecordFile::resetRs1Valid()  { record.flags &= ~RS1Valid; }

bool ZIDRecordFile::isRs1Valid()     { return ((record.flags & RS1Valid) == RS1Valid); }

void ZIDRecordFile::setRs2Valid()    { record.flags |= RS2Valid; }

void ZIDRecordFile::resetRs2Valid()  { record.flags &= ~RS2Valid; }

bool ZIDRecordFile::isRs2Valid()     { return ((record.flags & RS2Valid) == RS2Valid); }

void ZIDRecordFile::setMITMKeyAvailable()     { record.flags |= MITMKeyAvailable; }

void ZIDRecordFile::resetMITMKeyAvailable()   { record.flags &= ~MITMKeyAvailable; }

bool ZIDRecordFile::isMITMKeyAvailable()      { return ((record.flags & MITMKeyAvailable) == MITMKeyAvailable); }

void ZIDRecordFile::setOwnZIDRecord()   { record.flags = OwnZIDRecord; }

void ZIDRecordFile::resetOwnZIDRecord()  { record.flags = 0; }

bool ZIDRecordFile::isOwnZIDRecord()    { return (record.flags == OwnZIDRecord); }  // no other flag allowed if own ZID

void ZIDRecordFile::setSasVerified()    { record.flags |= SASVerified; }

void ZIDRecordFile::resetSasVerified()  { record.flags &= ~SASVerified; }

bool ZIDRecordFile::isSasVerified()     { return ((record.flags & SASVerified) == SASVerified); }

const uint8_t* ZIDRecordFile::getIdentifier()  {return record.identifier; }

const unsigned char* ZIDRecordFile::getRs1()   { return record.rs1Data; }

const unsigned char* ZIDRecordFile::getRs2()  { return record.rs2Data; }

const unsigned char* ZIDRecordFile::getMiTMData()  {return record.mitmKey; }

int ZIDRecordFile::getRecordType()  {return FILE_TYPE_RECORD; }

int64_t ZIDRecordFile::getSecureSince()  { return 0; }
