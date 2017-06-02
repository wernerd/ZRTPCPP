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

#include "ZrtpLogging.h"


#ifdef ANDROID_LOGGER
std::shared_ptr<logging::Logger<logging::AndroidLogPolicy> >
        _globalZrtpLogger = std::make_shared<logging::Logger<logging::AndroidLogPolicy> >(std::string(""), std::string("libzrtp"));

#elif defined(LINUX_LOGGER)

std::shared_ptr<logging::Logger<logging::CerrLogPolicy> >
        _globalZrtpLogger = std::make_shared<logging::Logger<logging::CerrLogPolicy> >(std::string(""), std::string("libzrtp"));

#elif defined(APPLE_LOGGER)

/**
 * The following code is for internal iOS (APPLE) logging only
 *
 */
static void (*_zrtp_log_cb)(void *ret, const char *tag, const char *buf) = nullptr;
static void *pLogRet = nullptr;

// this function must be public. Tivi C++ code set its internal log function
void set_zrtp_log_cb(void *pRet, void (*cb)(void *ret, const char *tag, const char *buf)){
    _zina_log_cb = cb;
    pLogRet = pRet;
}

void logging::zrtp_log(const char *tag, const char *buf) {
    if(_zrtp_log_cb){
        _zrtp_log_cb(pLogRet, tag, buf);
    }
}

std::shared_ptr<logging::Logger<logging::IosLogPolicy> >
        _globalZrtpLogger = std::make_shared<logging::Logger<logging::IosLogPolicy> >(std::string(""), std::string("libzrt"));

#else
#error "Define Logger instance according to the system in use."
#endif

void setZrtpLogLevel(int32_t level)
{
    _globalZrtpLogger->setLogLevel(static_cast<LoggingLogLevel>(level));
}
