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

#include "../SIDH_api.h"
#include "SidhKeyManagement.h"

#include "../../ZrtpRandom.h"

static CRYPTO_STATUS getRandomBytes(unsigned int nbytes, unsigned char* random_array)
{
    uint32_t length = ZrtpRandom::getRandomData(random_array, nbytes);
    return (length == nbytes) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
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

    static KeyEntry keyEntriesA[5];
    static KeyEntry keyEntriesB[5];

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

    static void generateKeys() {
        unique_lock<mutex> arrayLock(keyEntriesLockGenerating);
        while (threadRunning) {

            KeyEntry *entry;
            while ((entry = getEmptyEntry()) == nullptr && threadRunning) {
                entriesArrayCv.wait(arrayLock);
            }
            entry->status = Generating;
            arrayLock.unlock();

            if (entry->type == KeyA) {
                printf("Generate type A\n");
                CRYPTO_STATUS status = EphemeralKeyGeneration_A(entry->keyPair.privateKey, entry->keyPair.publicKey,
                                                                CurveIsogeny);
                if (status != CRYPTO_SUCCESS) {
                    printf("Key generation (A) failed: %d\n", status);
                    entry->status = Empty;
                } else {
                    entry->status = Ready;
                    entriesArrayACv.notify_one();
                }
            } else {
                printf("Generate type B\n");
                CRYPTO_STATUS status = EphemeralKeyGeneration_B(entry->keyPair.privateKey, entry->keyPair.publicKey,
                                                                CurveIsogeny);
                if (status != CRYPTO_SUCCESS) {
                    printf("Key generation (B) failed: %d\n", status);
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

        if (!threadRunning) {
            unique_lock<mutex> lck(threadLock);
            if (!threadRunning) {
                CurveIsogeny = SIDH_curve_allocate(&CurveIsogeny_SIDHp751);

                if (CurveIsogeny == NULL) {
                    return false;
                }
                CRYPTO_STATUS status = SIDH_curve_initialize(CurveIsogeny, getRandomBytes, &CurveIsogeny_SIDHp751);
                if (status != CRYPTO_SUCCESS) {
                    printf("SIDH curve initialization failed: %d\n", status);
                    SIDH_curve_free(CurveIsogeny);
                    return false;
                }
                threadRunning = true;
                generatingThread = thread(generateKeys);
            }
            lck.unlock();
        }
        return true;
    }

    bool SidhKeyManagement::getKeyPair(KeyEntryType type, KeyPair *keyPair) {
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
        return true;
    }

    void SidhKeyManagement::stopKeyGeneration() {
        unique_lock<mutex> lck(threadLock);
        if (!threadRunning) {
            return;
        }
        threadRunning = false;
        entriesArrayCv.notify_one();
        generatingThread.join();
    }

    int32_t SidhKeyManagement::secretAgreement_A(const unsigned char* pPrivateKeyA, const unsigned char* pPublicKeyB, unsigned char* pSharedSecretA) {
        return EphemeralSecretAgreement_A(pPrivateKeyA, pPublicKeyB, pSharedSecretA, CurveIsogeny);
    }

    int32_t SidhKeyManagement::secretAgreement_B(const unsigned char* pPrivateKeyB, const unsigned char* pPublicKeyA, unsigned char* pSharedSecretB) {
        return EphemeralSecretAgreement_B(pPrivateKeyB, pPublicKeyA, pSharedSecretB, CurveIsogeny);
    }

}
#ifdef UNITTESTS
int main(int argc, char *argv[]) {
    printf("Key Management main\n");
    if (!sidh751KM::SidhKeyManagement::initialize()) {
        printf("SIDH initialization failed.\n");
        return 1;
    }
    printf("Get a B key pair, start at: %ld\n", time(nullptr));
    sidh751KM::KeyPair bKey;
    if (!sidh751KM::SidhKeyManagement::getKeyPairB(&bKey)) {
        printf("getting a B key pair failed.\n");
        return 2;
    }
    printf("Got a B key pair, end at: %ld\n", time(nullptr));

    sidh751KM::SidhKeyManagement::stopKeyGeneration();

    if (sidh751KM::SidhKeyManagement::getKeyPairB(&bKey)) {
        printf("Get a B key pair must failed now.\n");
        return 3;
    }
    return 0;
}
#endif