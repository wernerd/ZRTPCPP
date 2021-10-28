//
// Created by wdi on 07.02.18.
//

#ifndef LIBCHAT_TYPEDEFS_H
#define LIBCHAT_TYPEDEFS_H

#include <list>
#include <string>
#include <memory>

#include "ZrtpConstants.h"
#include "SecureArray.h"

/**
 * @file
 * @ingroup ZRTP
 * @{
 *
 * This file contains constants some commonly used typedefs to simplify use of complex types.
 *
 */

namespace zrtp {

    /** Unique pointer to a string */
    using StringUnique = std::unique_ptr<std::string> ;

    /** Unique pointer to a list of strings */
    using StringListUnique = std::unique_ptr<std::list<std::string>>;

    using RetainedSecArray = secUtilities::SecureArray<MAX_DIGEST_LENGTH>;
    using ImplicitDigest = secUtilities::SecureArray<IMPL_MAX_DIGEST_LENGTH>;
    using NegotiatedArray = secUtilities::SecureArray<MAX_DIGEST_LENGTH>;
    using MaxDigestArray = secUtilities::SecureArray<MAX_DIGEST_LENGTH>;
}

#ifdef _WIN64
typedef __int64 ssize_t;
#elif defined _WIN32
typedef int     ssize_t;
#endif

/**
 * @}
 */

#endif //LIBCHAT_TYPEDEFS_H
