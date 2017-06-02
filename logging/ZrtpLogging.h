/*
  Copyright (C) 2017 Werner Dittmann

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

#ifndef LIBZRTP_ZRTPLOGGING_H
#define LIBZRTP_ZRTPLOGGING_H

/**
 * @file ZinaLogging.h
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 * @version 1.0
 *
 * @brief C++ logging functions for the ZINA library
 * @ingroup Logging
 * @{
 *
 * Set the project's maximum compiler log level if not otherwise specified during
 * compilation. See main CMakeLists.txt file, setting CMAKE_CXX_FLAGS_DEBUG for
 * DEBUG builds.
 *
 * The standard compile setting is logging level 'WARNING'
 */

#ifndef LOG_MAX_LEVEL
#define LOG_MAX_LEVEL WARNING
#endif

#define LOGGER_INSTANCE _globalZrtpLogger->
#include "Logger.h"

#ifdef ANDROID_LOGGER
extern std::shared_ptr<logging::Logger<logging::AndroidLogPolicy> > _globalZrtpLogger;

#elif defined(LINUX_LOGGER)
extern std::shared_ptr<logging::Logger<logging::CerrLogPolicy> > _globalZrtpLogger;
#elif defined(APPLE_LOGGER)
extern std::shared_ptr<logging::Logger<logging::IosLogPolicy> > _globalZrtpLogger;
#else
#error "Define Logger instance according to the system in use."
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

__EXPORT extern void setZrtpLogLevel(int32_t level);

#if defined(__cplusplus)
}
#endif
/**
 * @}
 */

#endif //LIBZRTP_ZRTPLOGGING_H
