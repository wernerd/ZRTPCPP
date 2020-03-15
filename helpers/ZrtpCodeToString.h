//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Created by werner on 15.03.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#ifndef LIBZRTPCPP_ZRTPCODETOSTRING_H
#define LIBZRTPCPP_ZRTPCODETOSTRING_H

#include <string>
#include <map>
#include <libzrtpcpp/ZrtpCodes.h>
#include <common/osSpecifics.h>

/**
 * @file
 * @brief Define string for ZRTP codes, function to map code to string,
 *
 * @ingroup ZRTP
 * @{
 */

class __EXPORT ZrtpCodeToString {
public:
    ZrtpCodeToString() {
        initialize();
    }

    std::string const &
    getStringForCode(GnuZrtpCodes::MessageSeverity sev, int32_t subCode);

private:
    void initialize();

    std::map<int32_t, std::string> infoMap;
    std::map<int32_t, std::string> warningMap;
    std::map<int32_t, std::string> severeMap;
    std::map<int32_t, std::string> zrtpMapR;
    std::map<int32_t, std::string> zrtpMapS;
};

/**
 * @}
 */

#endif //LIBZRTPCPP_ZRTPCODETOSTRING_H
