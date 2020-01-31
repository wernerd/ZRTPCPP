//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Created by werner on 31.01.20.
// Copyright (c) 2020 Werner Dittmann. All rights reserved.
//

#ifndef LIBZRTPCPP_ZRTPTESTCOMMON_H
#define LIBZRTPCPP_ZRTPTESTCOMMON_H

#include <zrtp/libzrtpcpp/ZrtpCallback.h>
#include "gmock/gmock.h"

using testing::Return;

class MockZrtpCallback : public ZrtpCallback {
public:
    MOCK_METHOD(int32_t, sendDataZRTP, (const uint8_t* data, int32_t length), (override));
    MOCK_METHOD(int32_t, activateTimer, (int32_t time), (override));
    MOCK_METHOD(int32_t, cancelTimer, (), (override));
    MOCK_METHOD(void, sendInfo, (GnuZrtpCodes::MessageSeverity severity, int32_t subCode), (override));
    MOCK_METHOD(bool, srtpSecretsReady, (SrtpSecret_t* secrets, EnableSecurity part), (override));
    MOCK_METHOD(void, srtpSecretsOff, (EnableSecurity part), (override));
    MOCK_METHOD(void, srtpSecretsOn, (std::string c, std::string s, bool verified), (override));
    MOCK_METHOD(void, handleGoClear, (), (override));
    MOCK_METHOD(void, zrtpNegotiationFailed, (GnuZrtpCodes::MessageSeverity severity, int32_t subCode), (override));
    MOCK_METHOD(void, zrtpNotSuppOther, (), (override));
    MOCK_METHOD(void, synchEnter, (), (override));
    MOCK_METHOD(void, synchLeave, (), (override));
    MOCK_METHOD(void, zrtpAskEnrollment, (GnuZrtpCodes::InfoEnrollment info), (override));
    MOCK_METHOD(void, zrtpInformEnrollment, (GnuZrtpCodes::InfoEnrollment info), (override));
    MOCK_METHOD(void, signSAS, (uint8_t* sasHash), (override));
    MOCK_METHOD(bool, checkSASSignature, (uint8_t* sasHash), (override));

    // Setup defaults with appropriate return values, overwrite in tests as required
    MockZrtpCallback() {
        ON_CALL(*this, sendDataZRTP).WillByDefault(Return(1));

        ON_CALL(*this, activateTimer).WillByDefault(Return(1));
        ON_CALL(*this, cancelTimer).WillByDefault(Return(1));

        ON_CALL(*this, srtpSecretsReady).WillByDefault(Return(true));
        ON_CALL(*this, checkSASSignature).WillByDefault(Return(true));
    }
};

#endif //LIBZRTPCPP_ZRTPTESTCOMMON_H
