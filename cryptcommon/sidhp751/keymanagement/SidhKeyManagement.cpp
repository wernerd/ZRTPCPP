/*
Copyright 2017 Werner Dittmann

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//
// Created by werner on 21.05.17.
//
#include <condition_variable>
#include <thread>
#include <logging/ZrtpLogging.h>

#include "../SIDH_api.h"
#include "SidhKeyManagement.h"

#include "../../ZrtpRandom.h"

static CRYPTO_STATUS getRandomBytes(unsigned int numBytes, unsigned char* random_array)
{
    uint32_t length = ZrtpRandom::getRandomData(random_array, numBytes);
    return (length == numBytes) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}

using namespace std;

namespace sidh751KM {
    static mutex threadLock;
    static condition_variable entriesArrayCv;
    static thread generatingThread;

    static bool threadRunning = false;

    static mutex keyEntriesLockGenerating;

    static condition_variable entriesArrayACv;
    static condition_variable entriesArrayBCv;
    static mutex keyEntriesLockConsumeA;
    static mutex keyEntriesLockConsumeB;

    enum KeyEntryStatus {
        Empty,
        InUse,
        Generating,
        Ready
    };

    struct KeyEntry {
        KeyEntryStatus status;
        KeyEntryType type;
        KeyPair keyPair;

        KeyEntry() {
            status = Empty;
        }

        ~KeyEntry() {
            status = Empty;
            type = None;
        }
    };

    static KeyEntry keyEntriesA[KEY_ENTRIES];
    static KeyEntry keyEntriesB[KEY_ENTRIES];

    static PCurveIsogenyStruct CurveIsogeny = nullptr;

// Function assumes locked Array (keyEntriesLockGenerating)
    static KeyEntry *getEmptyEntry() {
        for (int i = 0; i < KEY_ENTRIES; i++) {
            if (keyEntriesA[i].status == Empty) {
                keyEntriesA[i].type = KeyA;
                return &keyEntriesA[i];
            }
        }
        for (int i = 0; i < KEY_ENTRIES; i++) {
            if (keyEntriesB[i].status == Empty) {
                keyEntriesB[i].type = KeyB;
                return &keyEntriesB[i];
            }
        }
        return nullptr;
    }

    static KeyEntry *getReadyEntryA() {
        unique_lock<mutex> arrayLock(keyEntriesLockGenerating);
        for (int i = 0; i < KEY_ENTRIES; i++) {
            if (keyEntriesA[i].status == Ready) {
                keyEntriesA[i].status = InUse;
                return &keyEntriesA[i];
            }
        }
        return nullptr;
    }

    static KeyEntry *getReadyEntryB() {
        unique_lock<mutex> arrayLock(keyEntriesLockGenerating);
        for (int i = 0; i < KEY_ENTRIES; i++) {
            if (keyEntriesB[i].status == Ready) {
                keyEntriesB[i].status = InUse;
                return &keyEntriesB[i];
            }
        }
        return nullptr;
    }

    static void setEntryEmpty(KeyEntry *entry) {
        unique_lock<mutex> arrayLock(keyEntriesLockGenerating);
        entry->status = Empty;
        arrayLock.unlock();
        entriesArrayCv.notify_one();
    }

    static void clearAllEntries() {
        unique_lock<mutex> arrayLock(keyEntriesLockGenerating);
        for (int i = 0; i < KEY_ENTRIES; i++) {
            keyEntriesA[i].status = Empty;
            keyEntriesB[i].status = Empty;
        }
    }

    static void generateKeys() {
        unique_lock<mutex> arrayLock(keyEntriesLockGenerating);
        while (threadRunning) {

            KeyEntry *entry;
            while ((entry = getEmptyEntry()) == nullptr && threadRunning) {
                entriesArrayCv.wait(arrayLock);
            }
            if (!threadRunning) {
                return;
            }
            entry->status = Generating;
            arrayLock.unlock();

            if (entry->type == KeyA) {
                LOGGER(INFO, " Generate type A");
                CRYPTO_STATUS status = EphemeralKeyGeneration_A(entry->keyPair.privateKey, entry->keyPair.publicKey,
                                                                CurveIsogeny);
                if (status != CRYPTO_SUCCESS) {
                    LOGGER(ERROR, " Key generation (A) failed: ", status);
                    entry->status = Empty;
                } else {
                    entry->status = Ready;
                    entriesArrayACv.notify_one();
                }
            } else {
                LOGGER(INFO, " Generate type B");
                CRYPTO_STATUS status = EphemeralKeyGeneration_B(entry->keyPair.privateKey, entry->keyPair.publicKey,
                                                                CurveIsogeny);
                if (status != CRYPTO_SUCCESS) {
                    LOGGER(ERROR, "Key generation (B) failed: ", status);
                    entry->status = Empty;
                } else {
                    entry->status = Ready;
                    entriesArrayBCv.notify_one();
                }
            }
            arrayLock.lock();
        }
    }

    bool SidhKeyManagement::initialize() {
        LOGGER(DEBUGGING, __func__, " -->");

        if (!threadRunning) {
            unique_lock<mutex> lck(threadLock);
            if (!threadRunning) {
                CurveIsogeny = SIDH_curve_allocate(&CurveIsogeny_SIDHp751);

                if (CurveIsogeny == NULL) {
                    return false;
                }
                CRYPTO_STATUS status = SIDH_curve_initialize(CurveIsogeny, getRandomBytes, &CurveIsogeny_SIDHp751);
                if (status != CRYPTO_SUCCESS) {
                    LOGGER(ERROR, "SIDH curve initialization failed: ", status);
                    SIDH_curve_free(CurveIsogeny);
                    return false;
                }
                threadRunning = true;
                generatingThread = thread(generateKeys);
            }
            lck.unlock();
        }
        LOGGER(DEBUGGING, __func__, " <--");
        return true;
    }

    bool SidhKeyManagement::getKeyPair(KeyEntryType type, KeyPair *keyPair) {
        LOGGER(DEBUGGING, __func__, " -->");
        if (keyPair == nullptr || !threadRunning) {
            return false;
        }
        KeyEntry *entry;
        if (type == KeyA) {
            unique_lock<mutex> arrayLock(keyEntriesLockConsumeA);
            while ((entry = getReadyEntryA()) == nullptr) {
                entriesArrayACv.wait(arrayLock);
            }
        } else if (type == KeyB) {
            unique_lock<mutex> arrayLock(keyEntriesLockConsumeB);
            while ((entry = getReadyEntryB()) == nullptr) {
                entriesArrayBCv.wait(arrayLock);
            }
        } else {
            return false;
        }
        memcpy(keyPair->privateKey, entry->keyPair.privateKey, sizeof(PrivateKey));
        memcpy(keyPair->publicKey, entry->keyPair.publicKey, sizeof(PublicKey));
        entry->keyPair.clearKeys();
        setEntryEmpty(entry);
        LOGGER(DEBUGGING, __func__, " <--");
        return true;
    }

    void SidhKeyManagement::stopKeyGeneration() {
        LOGGER(DEBUGGING, __func__, " -->");
        unique_lock<mutex> lck(threadLock);
        if (!threadRunning) {
            return;
        }
        threadRunning = false;
        entriesArrayCv.notify_one();
        generatingThread.join();

        clearAllEntries();
        SIDH_curve_free(CurveIsogeny);
        LOGGER(DEBUGGING, __func__, " <--");
    }

    int32_t SidhKeyManagement::secretAgreement_A(const unsigned char* pPrivateKeyA, const unsigned char* pPublicKeyB, unsigned char* pSharedSecretA) {
        LOGGER(DEBUGGING, __func__, " -->");
        CRYPTO_STATUS status = EphemeralSecretAgreement_A(pPrivateKeyA, pPublicKeyB, pSharedSecretA, CurveIsogeny);
        LOGGER(DEBUGGING, __func__, " <--");
        return status;
    }

    int32_t SidhKeyManagement::secretAgreement_B(const unsigned char* pPrivateKeyB, const unsigned char* pPublicKeyA, unsigned char* pSharedSecretB) {
        LOGGER(DEBUGGING, __func__, " -->");
        CRYPTO_STATUS status = EphemeralSecretAgreement_B(pPrivateKeyB, pPublicKeyA, pSharedSecretB, CurveIsogeny);
        LOGGER(DEBUGGING, __func__, " <--");
        return status;
    }
}
