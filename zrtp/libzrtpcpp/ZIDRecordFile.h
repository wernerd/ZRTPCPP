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

#ifndef _ZIDRECORDFILE_H_
#define _ZIDRECORDFILE_H_


/**
 * @file ZIDRecordFile.h
 * @brief ZID cache record management
 *
 * A ZID record stores (caches) ZID (ZRTP ID) specific data that helps ZRTP
 * to achives its key continuity feature. Please refer to the ZRTP
 * specification to get detailed information about the ZID.
 *
 * @ingroup ZRTP
 * @{
 */

#include <cstring>
#include <cstdint>
#include <libzrtpcpp/ZIDRecord.h>

#define TIME_LENGTH      8      // 64 bit, can hold time on 64 bit systems

/**
 * This is the recod structure of version 1 ZID records.
 *
 * This is not longer in use - only during migration.
 */
typedef struct zidrecord1 {
    char recValid;  //!< if 1 record is valid, if 0: invalid
    char ownZid;    //!< if >1 record contains own ZID, usually 1st record
    char rs1Valid;  //!< if 1 RS1 contains valid data
    char rs2Valid;  //!< if 1 RS2 contains valid data
    unsigned char identifier[IDENTIFIER_LEN]; ///< the peer's ZID or own ZID
    unsigned char rs1Data[RS_LENGTH], rs2Data[RS_LENGTH]; ///< the peer's RS data
} zidrecord1_t;

/**
 * This is the recod structure of version 2 ZID records.
 */
typedef struct zidrecord2 {
    char version;   ///< version number of file format, this is #2
    char flags;     ///< bit field holding various flags, see below
    char filler1;   ///< round up to next 32 bit
    char filler2;   ///< round up to next 32 bit
    unsigned char identifier[IDENTIFIER_LEN]; ///< the peer's ZID or own ZID
    unsigned char rs1Interval[TIME_LENGTH];   ///< expiration time of RS1; -1 means indefinite
    unsigned char rs1Data[RS_LENGTH];         ///< the peer's RS2 data
    unsigned char rs2Interval[TIME_LENGTH];   ///< expiration time of RS2; -1 means indefinite
    unsigned char rs2Data[RS_LENGTH];         ///< the peer's RS2 data
    unsigned char mitmKey[RS_LENGTH];         ///< MiTM key if available
} zidrecord2_t;

/**
 * This class implements the ZID record.
 *
 * The ZID record holds data about a peer. According to ZRTP specification
 * we use a ZID to identify a peer. ZRTP uses the RS (Retained Secret) data
 * to construct shared secrets.
 * <p>
 * NOTE: ZIDRecord has ZIDFile as friend. ZIDFile knows about the private
 *   data of ZIDRecord - please keep both classes synchronized.
 *
 * @author: Werner Dittmann <Werner.Dittmann@t-online.de>
 */
class __EXPORT ZIDRecordFile: public ZIDRecord {
    friend class ZIDCacheFile;

private:
    zidrecord2_t record;
    unsigned long position;

    /**
     * Functions for I/O availabe for ZID file handling
     *
     * These functions are private, thus only friends may use it.
     */
    void setPosition(long pos) {position = pos;}
    long getPosition()         {return position; }

    zidrecord2_t* getRecordData() {return &record; }
    int getRecordLength()         {return sizeof(zidrecord2_t); }

    bool isValid()    { return ((record.flags & Valid) == Valid); }
    void setValid()   { record.flags |= Valid; }

public:
    /*
     * @brief The default constructor,
     */
    ZIDRecordFile() {
        memset(&record, 0, sizeof(zidrecord2_t));
        record.version = 2;
    }

    /**
     * @brief Set the @c ZID in the record.
     *
     * Set the ZID in this record before calling read or save.
     */
    void setZid(const unsigned char *zid) override;
    /**
     * @brief Set @c valid flag in RS1
     */
    void setRs1Valid() override;

    /**
     * @brief Reset @c valid flag in RS1
     */
    void resetRs1Valid() override;

    /**
     * @brief Check @c valid flag in RS1
     */
    bool isRs1Valid() override;

    /**
     * @brief Set @c valid flag in RS2
     */
    void setRs2Valid() override;

    /**
     * @brief Reset @c valid flag in RS2
     */
    void resetRs2Valid() override;

    /**
     * @brief Check @c valid flag in RS2
     */
    bool isRs2Valid() override;

    /**
     * @brief Set MITM key available
     */
    void setMITMKeyAvailable() override;

    /**
     * @brief Reset MITM key available
     */
    void resetMITMKeyAvailable() override;

    /**
     * @brief Check MITM key available is set
     */
    bool isMITMKeyAvailable() override;

    /**
     * @brief Mark this as own ZID record
     */
    void setOwnZIDRecord() override;
    /**
     * @brief Reset own ZID record marker
     */
    void resetOwnZIDRecord() override;

    /**
     * @brief Check own ZID record marker
     */
    bool isOwnZIDRecord() override;

    /**
     * @brief Set SAS for this ZID as verified
     */
    void setSasVerified() override;
    /**
     * @brief Reset SAS for this ZID as verified
     */
    void resetSasVerified() override;

    /**
     * @brief Check if SAS for this ZID was verified
     */
    bool isSasVerified() override;

    /**
     * @brief Return the ZID for this record
     */
    const uint8_t* getIdentifier() override;

    /**
     * @brief Check if RS1 is still valid
     *
     * Returns true if RS1 is still valid, false otherwise.
     *
     * @return
     *    Returns true is RS1 is not expired (valid), false otherwise.
     */
    bool isRs1NotExpired() override ;

    /**
     * @brief Returns pointer to RS1 data.
     */
    const unsigned char* getRs1() override;

    /**
     * @brief Check if RS2 is still valid
     *
     * Returns true if RS2 is still valid, false otherwise.
     *
     * @return
     *    Returns true is RS2 is not expired (valid), false otherwise.
     */
    bool isRs2NotExpired() override ;

    /**
     * @brief Returns pointer to RS1 data.
     */
    const unsigned char* getRs2() override;

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
     *    The expiration interval in seconds. Default is -1.
     *
     */
    void setNewRs1(const unsigned char* data, int32_t expire =-1) override ;

    /**
     * @brief Set MiTM key data.
     *
     */
    void setMiTMData(const unsigned char* data) override ;

    /**
     * @brief Get MiTM key data.
     *
     */
    const unsigned char* getMiTMData() override;

    int getRecordType() override;
    
    /**
     * @brief Get Secure since date.
     * 
     * The file based cache implementation does not support this datum, thus return 0
     * 
     */
    int64_t getSecureSince() override;
};

#endif // ZIDRECORDSMALL

