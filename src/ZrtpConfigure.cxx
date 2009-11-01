/*
  Copyright (C) 2006-2008 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <stdio.h>

#include <libzrtpcpp/ZrtpConfigure.h>

ZrtpConfigure::ZrtpConfigure() {
    hashes.endSupportedAlgos = EndSupportedHashes;
    symCiphers.endSupportedAlgos = EndSupportedSymCiphers;
    publicKeyAlgos.endSupportedAlgos = EndSupportedPubKeys;
    sasTypes.endSupportedAlgos = EndSupportedSASTypes;
    authLengths.endSupportedAlgos = EndSupportedAuthLenghts;

    clear();
}

void ZrtpConfigure::setStandardConfig() {
    clear();

    hashes.numConfiguredAlgos = 1;
    hashes.algos[0] = Sha256;

    symCiphers.numConfiguredAlgos = 2;
    symCiphers.algos[0] = Aes256;
    symCiphers.algos[1] = Aes128;

    publicKeyAlgos.numConfiguredAlgos = 3;
    publicKeyAlgos.algos[0] = Dh3072;
    publicKeyAlgos.algos[1] = Dh2048;
    publicKeyAlgos.algos[2] = MultiStream;

    sasTypes.numConfiguredAlgos = 1;
    sasTypes.algos[0] = Libase32;

    authLengths.numConfiguredAlgos = 2;
    authLengths.algos[0] = AuthLen32;
    authLengths.algos[1] = AuthLen80;
}

void ZrtpConfigure::setMandatoryOnly() {
    clear();

    hashes.numConfiguredAlgos = 1;
    hashes.algos[0] = Sha256;

    symCiphers.numConfiguredAlgos = 1;
    symCiphers.algos[0] = Aes128;

    publicKeyAlgos.numConfiguredAlgos = 2;
    publicKeyAlgos.algos[0] = Dh3072;
    publicKeyAlgos.algos[1] = MultiStream;

    sasTypes.numConfiguredAlgos = 1;
    sasTypes.algos[0] = Libase32;

    authLengths.numConfiguredAlgos = 2;
    authLengths.algos[0] = AuthLen32;
    authLengths.algos[1] = AuthLen80;
}

void ZrtpConfigure::clear() {
    for (int i = 0; i < MAX_NO_OF_ALGOS; i++) {
	hashes.algos[i] = hashes.endSupportedAlgos;
    }
    hashes.numConfiguredAlgos = 0;

    for (int i = 0; i < MAX_NO_OF_ALGOS; i++) {
	symCiphers.algos[i] = symCiphers.endSupportedAlgos;
    }
    symCiphers.numConfiguredAlgos = 0;

    for (int i = 0; i < MAX_NO_OF_ALGOS; i++) {
	publicKeyAlgos.algos[i] = publicKeyAlgos.endSupportedAlgos;
    }
    publicKeyAlgos.numConfiguredAlgos = 0;

    for (int i = 0; i < MAX_NO_OF_ALGOS; i++) {
	sasTypes.algos[i] = sasTypes.endSupportedAlgos;
    }
    sasTypes.numConfiguredAlgos = 0;

    for (int i = 0; i < MAX_NO_OF_ALGOS; i++) {
	authLengths.algos[i] = authLengths.endSupportedAlgos;
    }
    authLengths.numConfiguredAlgos = 0;
}

ZrtpConfigure::~ZrtpConfigure() {
}

/*
 * Hash functions
 */
int32_t ZrtpConfigure::addHashAlgo(SupportedHashes algo) {
    return addAlgo(&hashes, algo);
}

int32_t ZrtpConfigure::removeHashAlgo(SupportedHashes algo) {
    return removeAlgo(&hashes, algo);
}

int32_t ZrtpConfigure::getNumConfiguredHashes() {
    return getNumConfiguredAlgos(&hashes);
}

SupportedHashes ZrtpConfigure::getHashAlgoAt(int32_t index) {
    return (SupportedHashes)getAlgoAt(&hashes, index);
}

/* ***
void ZrtpConfigure::dumpHash() {
    dumpAlgorithms(&hashes);
}
*** */
/*
 * SymCipher configuration functions
 */
int32_t ZrtpConfigure::addSymCipherAlgo(SupportedSymCiphers algo) {
    return addAlgo(&symCiphers, algo);
}

int32_t ZrtpConfigure::removeSymCipherAlgo(SupportedSymCiphers algo) {
    return removeAlgo(&symCiphers, algo);
}

int32_t ZrtpConfigure::getNumConfiguredSymCiphers() {
    return getNumConfiguredAlgos(&symCiphers);
}

SupportedSymCiphers ZrtpConfigure::getSymCipherAlgoAt(int32_t index) {
    return (SupportedSymCiphers)getAlgoAt(&symCiphers, index);
}

/*
 * Public key configuration functions
 */
int32_t ZrtpConfigure::addPubKeyAlgo(SupportedPubKeys algo) {
    return addAlgo(&publicKeyAlgos, algo);
}

int32_t ZrtpConfigure::removePubKeyAlgo(SupportedPubKeys algo) {
    return removeAlgo(&publicKeyAlgos, algo);
}

int32_t ZrtpConfigure::getNumConfiguredPubKeys() {
    return getNumConfiguredAlgos(&publicKeyAlgos);
}

SupportedPubKeys ZrtpConfigure::getPubKeyAlgoAt(int32_t index) {
    return (SupportedPubKeys)getAlgoAt(&publicKeyAlgos, index);
}

/*
 * SAS type configuration functions
 */
int32_t ZrtpConfigure::addSasTypeAlgo(SupportedSASTypes algo) {
    return addAlgo(&sasTypes, algo);
}

int32_t ZrtpConfigure::removeSasTypeAlgo(SupportedSASTypes algo) {
    return removeAlgo(&sasTypes, algo);
}

int32_t ZrtpConfigure::getNumConfiguredSasTypes() {
    return getNumConfiguredAlgos(&sasTypes);
}

SupportedSASTypes ZrtpConfigure::getSasTypeAlgoAt(int32_t index) {
    return (SupportedSASTypes)getAlgoAt(&sasTypes, index);
}

/*
 * Authentication length configuration functions
 */
int32_t ZrtpConfigure::addAuthLength(SupportedAuthLengths algo) {
    return addAlgo(&authLengths, algo);
}

int32_t ZrtpConfigure::removeAuthLength(SupportedAuthLengths algo) {
    return removeAlgo(&authLengths, algo);
}

int32_t ZrtpConfigure::getNumConfiguredAuthLengths() {
    return getNumConfiguredAlgos(&authLengths);
}

SupportedAuthLengths ZrtpConfigure::getAuthLengthAt(int32_t index) {
    return (SupportedAuthLengths)getAlgoAt(&authLengths, index);
}


/* ****
// private functions
void ZrtpConfigure::dumpAlgorithms(algorithms_t* a) {
    fprintf(stderr, "numConfiguredAlgos: %d\n", a->numConfiguredAlgos);
    fprintf(stderr, "endSupportedAlgos: %d\n", a->endSupportedAlgos);
    for (int i = 0; i < MAX_NO_OF_ALGOS; i++) {
	fprintf(stderr, "algo %d: %d\n", i, a->algos[i]);
    }
}

**** */

int32_t ZrtpConfigure::addAlgo(algorithms_t* a, int32_t algo) {

    // Check if algo is already configured, silently ignore
    for (int i = 0; i < a->numConfiguredAlgos; i++) {
	if (a->algos[i] == algo) 
	    return MAX_NO_OF_ALGOS - a->numConfiguredAlgos;
    }
    if (a->numConfiguredAlgos < MAX_NO_OF_ALGOS) {
	a->algos[hashes.numConfiguredAlgos++] = algo;
    }
    return MAX_NO_OF_ALGOS - a->numConfiguredAlgos;
}

int32_t ZrtpConfigure::removeAlgo(algorithms_t* a, int32_t algo) {
    int index = 0;

    // locate the algo to remove
    for (; index < a->numConfiguredAlgos; index++) {
	if (a->algos[index] == algo) 
	    break;
    }
    // check if the algo to remove was found.
    if (index == a->numConfiguredAlgos)
	return MAX_NO_OF_ALGOS - a->numConfiguredAlgos;

    // check if index points to last algo entry, just overwrite and return
    if (index == MAX_NO_OF_ALGOS-1) {
	a->algos[MAX_NO_OF_ALGOS-1] = a->endSupportedAlgos;
	a->numConfiguredAlgos--;
	return MAX_NO_OF_ALGOS - a->numConfiguredAlgos;
    }
    // shuffle forward rest of algos
    for (; index < a->numConfiguredAlgos; index++) {
	a->algos[index] = a->algos[index+1] ;
    }
    a->algos[a->numConfiguredAlgos] = a->endSupportedAlgos;
    a->numConfiguredAlgos--;

    return MAX_NO_OF_ALGOS - a->numConfiguredAlgos;
}

int32_t ZrtpConfigure::getNumConfiguredAlgos(algorithms_t* a) {
    return a->numConfiguredAlgos;
}

int32_t ZrtpConfigure::getAlgoAt(algorithms_t* a, int32_t index) {
    if (index < a->numConfiguredAlgos)
	return a->algos[index];
    else
	return a->endSupportedAlgos;
}
/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
