/*
 *
 */

#ifndef _ZRTP_CACHE_DB_H_
#define _ZRTP_CACHE_DB_H_

#if defined(__cplusplus)
extern "C"
{
#endif

 /**
  * Definitions and structures for ZRTP database cache implementations.
  *
  * The figure below depicts the overall structure of the ZRTP DB cache implmentation.
  * 
  *
  *@verbatim
  * +--------------------------------+
  * | zrtp_cache.h (zrtp_cache_op_t) |
  * | zrtp_cache.c                   |
  * +-+------------------------------+
  *   |
  *   |
  *   |
  *   |Include
  *   |
  *   |    Defines config for      Defines interface to access
  *   |    DB caches               DB caches (dbCacheOps_t)
  *   |   +-----------------+      +-------------------------+
  *   |   | zrtp_cache_db.h |      | zrtp_cache_db_backend.h |
  *   |   +------+----------+      +-----+---+----+----------+
  *   |          |                       |   |    |
  *   |          |                       |   |    |
  *   |          |Include and use        |   |    |
  *   |          |      +----------------+   |    |
  *   |          |      |                    |    |
  *   |   +------+------+---+                |    | Include and
  *   +---+ zrtp_cache_db.c |                |    | implement
  *       +-----+-----+-----+                |    |
  *             |     |            +---------+-------------------+
  *             |     +------------+ zrtp_cache_sqlite_backend.c |
  *             |        Call      +-----------------------------+
  *             |                                 |
  *             |                                 |
  *             |                  +--------------+--------------+
  *             +------------------+ zrtp_cache_others_backend.c |
  *                      Call      +-----------------------------+
  *                                 DB specific backends implement
  *                                 the acccess interface
  *@endverbatim
  *
  * The @c zrtp_cache_db module implments the standard @c libzrtp cache plugin
  * interface which is defined in @c zrtp_cache.h. The @c zrtp_cache_db.c file
  * includes the @c zrtp_cache_backend.h that defines a record structure to
  * manage cache data for the remote ZRTP identifiers (ZID).
  *
  * The database specific backend implementations take this ZID record to store
  * or retrieve data to/from the database. The database backend implementation
  * is independent of the @c zrtp_cache_db module.
  *
  */


/* The following lines are a slightly modified copy of @c zrtp_cache_file.h and
 * define the structure, public functions, and names for ZRTP database cache
 * implementations.
 *
 */
#undef ZRTP_DEF_CACHE_VERSION_STR
#define ZRTP_DEF_CACHE_VERSION_STR      "libZRTP db cache version="

#undef ZRTP_DEF_CACHE_VERSION_VAL
#define ZRTP_DEF_CACHE_VERSION_VAL      "1.0"

#define ZRTP_CACHE_DB_DEF_PATH        "./zrtp_def_cache_db.dat"

#define ZRTP_CACHE_STRLEN                       256

/* Forward declaration - the structure is local to zrtp_cache_db.c */
typedef struct zrtp_cache_db_t zrtp_cache_db_t;

typedef struct {
        /**
         * Path to ZRTP cache file. If file doesn't exist it will be created.
         * Default is ZRTP_CACHE_FILE_DEF_PATH.
         */
        char    cache_path[ZRTP_CACHE_STRLEN];

        /**
         * @brief Flush the cache automatically
         * Set to 1 if you want libzrtp to flush the cache to the persistent storage
         * right after it was modified. If cache_auto_store is 0, libzrtp will flush
         * the cache on going down only and the app is responsible for storing the
         * cache in unexpected situations. Enabled by default.
         *
         * @sa zrtp_def_cache_store()
         */
        unsigned                                cache_auto_store;
} zrtp_cache_db_config_t;

zrtp_status_t zrtp_cache_db_create(zrtp_stringn_t *local_zid,
                                   zrtp_cache_db_config_t *config,
                                   zrtp_cache_db_t **cache);

zrtp_status_t zrtp_cache_db_destroy(zrtp_cache_t *cache);


#if defined(__cplusplus)
}
#endif
#endif /* _ZRTP_CACHE_DB_H_ */
