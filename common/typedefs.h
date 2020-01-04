//
// Created by wdi on 07.02.18.
//

#ifndef LIBCHAT_TYPEDEFS_H
#define LIBCHAT_TYPEDEFS_H

#include <list>
#include <string>

/**
 * @file
 * @ingroup Zina
 * @{
 *
 * This file contains constants some commonly used typedefs to simplify use of complex types.
 *
 */

namespace zrtp {

    /** Unique pointer to a string */
    typedef std::unique_ptr<std::string> StringUnique;

    /** Unique pointer to a list of strings */
    typedef std::unique_ptr<std::list<std::string>> StringListUnique;
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
