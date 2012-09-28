/*
 *
 */

#ifndef _ZRTP_CACHE_DB_BACKEND_H_
#define _ZRTP_CACHE_DB_BACKEND_H_

#include <libzrtpcpp/ZIDRecordDb.h>

#if defined(__cplusplus)
extern "C"
{
#endif

#define DB_CACHE_ERR_BUFF_SIZE  1000

/**
 * Set of accessible operations of database ZRTP cache implementaion.
 *
 * The only public method of the database ZRTP implementation is
 * getDbCacheOps(...)  that fills in this call structure. This mechanism
 * decouples the database implementations from libzrtp and possible other
 * clients.
 *
 * Some implementation notes:
 * <ul>
 * <li> All data storage methods return 0 (zero) if the call was successful.
 * </li>

 * <li> The @c errString parameter points to a buffer of at least @c
 *      DB_CACHE_ERR_BUFF_SIZE character. In case of an error methods shall
 *      store detailed, human readable information in this buffer. Use @c
 *      snprintf or similar functions to format the data.  If this parameter
 *      is @c NULL then methods must not return an error string.
 *</li>
 * <li> The methods cast the @c void to the type they need. Be aware that the
 *      open functions requires a pointer to a pointer.
 * </li>
 * </ul>
 *
 *
 * 
 */
typedef struct {
    /**
     * @brief Open the cache.
     *
     * @param name String that identifies the database or data storage.
     *
     * @param pdb Pointer to an internal structure that the database
     *            implementation requires.
     *
     * @param errString Pointer to a character buffer, see implementation
     *                  notes above.
     */
    int (*openCache)(const char* name, void **pdb, char *errString);

    /**
     * Close the cache.
     *
     * @param db Pointer to an internal structure that the database
     *           implementation requires.
     */
    int (*closeCache)(void *db);

    /**
     * @brief Read a local ZID from the database.
     *
     * The cache database may implement methods to generate and store local
     * ZRTP identifiers (ZID) and optionally link them with account
     * information. The account information data is the key to the request
     * local ZID. If the application does not provide account information data
     * the method implmentation shall use a standard predfined string that
     * does not collide with usual account information.
     *
     * The SQLite backend uses the string @c "_STANDARD_" in this case and
     * sets a specific type field.
     * 
     * The first call to this method with a specific account information
     * generates a ZID, stores it in the database usind the account
     * information as key, and returns the ZID to the application. Any
     * subsequent call with the same account information return the same local
     * ZID.
     *
     * @param db Pointer to an internal structure that the database
     *           implementation requires.
     *
     * @param localZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                 uint8_t bytes. The method stores the local ZID in this
     *                 buffer.
     *
     * @param accountInfo Pointer to an account information string or @c NULL
     *                    if explicit account information is not required.
     *
     * @param errString Pointer to a character buffer, see implementation
     *                  notes above.
     */
    int (*readLocalZid)(void *db, uint8_t *localZid, const char *accountInfo, char *errString);

    /**
     * @brief Read a remote ZID data structure.
     *
     * The method uses @c remoteZid and @c localZid as keys to read the remote
     * ZID record.  If a record does not exist in the database the method
     * clears the @c flags field in the @c remoteZidRecord_t structure and
     * returns without error. The application must check the flags if the
     * method found a valid record.
     *
     * @param db Pointer to an internal structure that the database
     *           implementation requires.
     *
     * @param localZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                 uint8_t bytes. The buffer must contain the local ZID.
     *
     * @param remoteZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                  uint8_t bytes. The buffer must contain the remote ZID.
     *
     * @param remZid Pointer to the @c remoteZidRecord_t structure. The method
     *               fills this structure with data it read from the database.
     *
     * @param errString Pointer to a character buffer, see implementation
     *                  notes above.
     */
    int (*readRemoteZidRecord)(void *db, const uint8_t *remoteZid, const uint8_t *localZid, 
                               remoteZidRecord_t *remZid, char* errString);
    /**
     * @brief Update an existing remote ZID data structure.
     *
     * The method uses @c remoteZid and @c localZid as keys to update an
     * existing remote ZID record.
     *
     * @b NOTE: application must use this methods only if
     *          @c readRemoteZidRecord (see above) returned a @b valid record. If
     *          @c readRemoteZidRecord returned an invalid record then no such
     *          record exists in the database and the application must use the
     *          @c insertRemoteZidRecord (see below).
     *
     * @param db Pointer to an internal structure that the database
     *           implementation requires.
     *
     * @param localZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                 uint8_t bytes. The buffer must contain the local ZID.
     *
     * @param remoteZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                  uint8_t bytes. The buffer must contain the remote ZID.
     *
     * @param remZid Pointer to the @c remoteZidRecord_t structure. The method
     *               gets data from this structure and stores it in the
     *               database.
     *
     * @param errString Pointer to a character buffer, see implementation
     *                  notes above.
     */
    int (*updateRemoteZidRecord)(void *db, const uint8_t *remoteZid, const uint8_t *localZid, 
                                 const remoteZidRecord_t *remZid, char* errString);
    /**
     * @brief Insert a new remote ZID data structure.
     *
     * The method uses @c remoteZid and @c localZid as keys to insert a new
     * remote ZID record.
     *
     * @b NOTE: application must use this methods only if @c
     *          readRemoteZidRecord (see above) returned an @b invalid
     *          record. Refer to note.
     *
     * @param db Pointer to an internal structure that the database
     *           implementation requires.
     *
     * @param localZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                 uint8_t bytes. The buffer must contain the local ZID.
     *
     * @param remoteZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                  uint8_t bytes. The buffer must contain the remote ZID.
     *
     * @param remZid Pointer to the @c remoteZidRecord_t structure. The method
     *               gets data from this structure and stores it in the
     *               database.
     *
     * @param errString Pointer to a character buffer, see implementation
     *                  notes above.
     */
    int (*insertRemoteZidRecord)(void *db, const uint8_t *remoteZid, const uint8_t *localZid, 
                                 const remoteZidRecord_t *remZid, char* errString);

    /**
     * @brief Read a remote ZID name.
     *
     * The method uses @c remoteZid, @c localZid, and @c accountInfo as keys
     * to read the remote ZID name.  If a record does not exist in the database
     * the method clears the @c flags field in the @c zidNameRecord_t structure and
     * returns without error. The application must check the flags if the
     * method found a valid record.
     * 
     * @param db Pointer to an internal structure that the database
     *           implementation requires.
     *
     * @param localZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                 uint8_t bytes. The buffer must contain the local ZID.
     *
     * @param remoteZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                  uint8_t bytes. The buffer must contain the remote ZID.
     *
     * @param accountInfo Pointer to an account information string or @c NULL
     *                    if explicit account information is not required.
     *
     * @param zidName Pointer to the @c zidNameRecord_t structure. The method
     *                returns the data in this structure.
     *
     * @param errString Pointer to a character buffer, see implementation
     *                  notes above.
     */
    int (*readZidNameRecord)(void *vdb, const uint8_t *remoteZid, const uint8_t *localZid,
                             const char *accountInfo, zidNameRecord_t *zidName, char* errString);

    /**
     * @brief Update an existing remote ZID data structure.
     *
     * The method uses @c remoteZid and @c localZid as keys to update an
     * existing remote ZID record.
     *
     * @b NOTE: application must use this methods only if
     *          @c readZidName (see above) returned a @b valid record. If
     *          @c readZidName returned an invalid record then no such
     *          record exists in the database and the application must use the
     *          @c insertZidNameRecord (see below).
     *
     * @param db Pointer to an internal structure that the database
     *           implementation requires.
     *
     * @param localZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                 uint8_t bytes. The buffer must contain the local ZID.
     *
     * @param remoteZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                  uint8_t bytes. The buffer must contain the remote ZID.
     *
     * @param accountInfo Pointer to an account information string or @c NULL
     *                    if explicit account information is not required.
     *
     * @param zidName Pointer to the @c zidNameRecord_t structure. The method
     *               gets data from this structure and stores it in the
     *               database.
     *
     * @param errString Pointer to a character buffer, see implementation
     *                  notes above.
     */
    int (*updateZidNameRecord)(void *vdb, const uint8_t *remoteZid, const uint8_t *localZid,
                               const char *accountInfo, zidNameRecord_t *zidName, char* errString);

    /**
     * @brief Insert a new ZID name record.
     *
     * The method uses @c remoteZid, @c localZid, and @c accountInfo as keys to
     * insert a new ZID name record.
     *
     * @b NOTE: application must use this methods only if @c readZidName
     *         (see above) returned an @b invalid record.
     *
     * @param db Pointer to an internal structure that the database
     *           implementation requires.
     *
     * @param localZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                 uint8_t bytes. The buffer must contain the local ZID.
     *
     * @param remoteZid Pointer to a buffer of at least @c IDENTIFIER_LEN @c
     *                  uint8_t bytes. The buffer must contain the remote ZID.
     *
     * @param accountInfo Pointer to an account information string or @c NULL
     *                    if explicit account information is not required.
     *
     * @param zidName Pointer to the @c zidNameRecord_t structure. The method
     *               gets data from this structure and stores it in the
     *               database.
     *
     * @param errString Pointer to a character buffer, see implementation
     *                  notes above.
     */
    int (*insertZidNameRecord)(void *vdb, const uint8_t *remoteZid, const uint8_t *localZid,
                               const char *accountInfo, zidNameRecord_t *zidName, char* errString);


    /**
     * Clean the cache.
     *
     * This method cleans the cache and discards all information about remote peers.
     * The method does not delete the local (own) ZID. To delete local ZID information
     * the user must delete the database base.
     *
     * @param db Pointer to an internal structure that the database
     *           implementation requires.
     *
     * @param errString Pointer to a character buffer, see implementation
     *                  notes above.
     */
    int (*cleanCache)(void *db, char* errString);
} dbCacheOps_t;

void getDbCacheOps(dbCacheOps_t *ops);


#if defined(__cplusplus)
}
#endif

#endif /* _ZRTP_CACHE_DB_BACKEND_H_*/
