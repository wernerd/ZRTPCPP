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

#ifndef _ZIDRECORDEMPTY_H_
#define _ZIDRECORDEMPTY_H_


/**
 * @file ZIDRecordEmpty.h
 * @brief ZID cache record management
 *
 * This empty ZID record does not store any data, thus implements an empty or non-existent
 * ZRTP cache.
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <string.h>
#include <stdint.h>
#include <libzrtpcpp/ZIDRecord.h>

#define TIME_LENGTH      8      // 64 bit, can hold time on 64 bit systems

/**
 * This class implements an empty ZID record.
 *
 * The ZID record is empty. It's a placeholder for an empty ZRTP cache record and returns @c false for
 * checks if some data exists of is valid.
 *
 * Other functions are just no-ops
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class __EXPORT ZIDRecordEmpty: public ZIDRecord {
    friend class ZIDCacheEmpty;

public:
    /*
     * @brief The default constructor,
     */
    ZIDRecordEmpty() = default;

    /**
     * @brief Set the @c ZID in the record.
     *
     * Set the ZID in this record before calling read or save.
     */
    void setZid(const unsigned char *zid) override { (void) zid; }

    /**
     * @brief Set @c valid flag in RS1
     */
    void setRs1Valid() override  {  }

    /**
     * @brief Reset @c valid flag in RS1
     */
    void resetRs1Valid() override { }

    /**
     * @brief Check @c valid flag in RS1
     */
    bool isRs1Valid() override   { return false; }

    /**
     * @brief Set @c valid flag in RS2
     */
    void setRs2Valid() override  {  }

    /**
     * @brief Reset @c valid flag in RS2
     */
    void resetRs2Valid() override {  }

    /**
     * @brief Check @c valid flag in RS2
     */
    bool isRs2Valid()  override  { return false; }

    /**
     * @brief Set MITM key available
     */
    void setMITMKeyAvailable() override  {  }

    /**
     * @brief Reset MITM key available
     */
    void resetMITMKeyAvailable() override {  }

    /**
     * @brief Check MITM key available is set
     */
    bool isMITMKeyAvailable()   override  { return false; }

    /**
     * @brief Mark this as own ZID record
     */
    void setOwnZIDRecord() override { }
    /**
     * @brief Reset own ZID record marker
     */
    void resetOwnZIDRecord() override {  }

    /**
     * @brief Check own ZID record marker
     */
    bool isOwnZIDRecord() override  { return false; }  // no other flag allowed if own ZID

    /**
     * @brief Set SAS for this ZID as verified
     */
    void setSasVerified() override  {  }
    /**
     * @brief Reset SAS for this ZID as verified
     */
    void resetSasVerified() override {  }

    /**
     * @brief Check if SAS for this ZID was verified
     */
    bool isSasVerified()  override  { return false; }

    /**
     * @brief Return the ZID for this record
     */
    const uint8_t* getIdentifier() override {return nullptr; }

    /**
     * @brief Check if RS1 is still valid
     *
     * Returns true if RS1 is still valid, false otherwise.
     *
     * @return
     *    Returns true is RS1 is not expired (valid), false otherwise.
     */
    bool isRs1NotExpired() override;

    /**
     * @brief Returns pointer to RS1 data.
     */
    const unsigned char* getRs1() override { return nullptr; }

    /**
     * @brief Check if RS2 is still valid
     *
     * Returns true if RS2 is still valid, false otherwise.
     *
     * @return
     *    Returns true is RS2 is not expired (valid), false otherwise.
     */
    bool isRs2NotExpired() override;

    /**
     * @brief Returns pointer to RS1 data.
     */
    const unsigned char* getRs2() override { return nullptr; }

    /**
     * @brief Sets new RS1 data and associated expiration value.
     *
     * If the expiration value is >0 or -1 the method stores the new
     * RS1. Before it stores the new RS1 it shifts the exiting RS1
     * into RS2 (together with its expiration time). Then it computes
     * the expiration time of the and stores the result together with
     * the new RS1.
     *
     * If the expiration value is -1 then this RS will never expire.
     *
     * If the expiration value is 0 then the expiration value of a
     * stored RS1 is cleared and no new RS1 value is stored. Also RS2
     * is left unchanged.
     *
     * @param data
     *    Points to the new RS1 data.
     * @param expire
     *    The expiration interval in seconds.
     *
     */
    void setNewRs1(const unsigned char* data, int32_t expire) override;

    /**
     * @brief Set MiTM key data.
     *
     */
    void setMiTMData(const unsigned char* data) override;

    /**
     * @brief Get MiTM key data.
     *
     */
    const unsigned char* getMiTMData() override {return nullptr; }

    int getRecordType() override {return FILE_TYPE_RECORD; }
    
    /**
     * @brief Get Secure since date.
     * 
     * The file based cache implementation does not support this datum, thus return 0
     * 
     */
    int64_t getSecureSince() override { return 0; }
};

#endif // ZIDRECORDSMALL

