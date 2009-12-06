/*
  Copyright (C) 2009 Werner Dittmann

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

#ifndef _ZRTPCONFIGURE_H_
#define _ZRTPCONFIGURE_H_

#include <stdio.h>
#include <stdint.h>
#include <list>
#include <string>
#include <vector>
#include <string.h>

/**
 * This enumerations list all configurable algorithm types.
 */

enum AlgoTypes {
    HashAlgorithm = 1, CipherAlgorithm, PubKeyAlgorithm, SasType, AuthLength
};

/**
 * The algorithm enumration class.
 *
 * This simple class is just a container of an algorithm's name and
 * its associated algorithm type. We use this class together with the
 * EnumBase class to implement a Java-like enum class functionality
 * (not fully, but OK for our use case at hand).
 */
class AlgorithmEnum {
public:
    AlgorithmEnum(const int type, const char* name);
    const char* getName();
    int getAlgoType();
    bool isValid();

private:
    int algoType;
    const char* algoName;
};

/**
 * EnumBase provides methods to access the algorithm enumerations.
 */
class EnumBase {
public:
    AlgorithmEnum& getByName(const char* name);
    std::list<std::string>* getAllNames();
    int getSize();
    AlgoTypes getAlgoType();
    AlgorithmEnum& getByOrdinal(int ord);
    int getOrdinal(AlgorithmEnum& algo);

protected:
    EnumBase(AlgoTypes algo);
    void insert(const char* name);

private:
    AlgoTypes algoType;
    std::vector <AlgorithmEnum* > algos;
};

/**
 * The enumaration subclasses that contain the supported algorithm enumerations.
 */

class HashEnum : public EnumBase {
public:
    HashEnum();
};

class SymCipherEnum : public EnumBase {
public:
    SymCipherEnum();
};

class PubKeyEnum : public EnumBase {
public:
    PubKeyEnum();
};

class SasTypeEnum : public EnumBase {
public:
    SasTypeEnum();
};

class AuthLengthEnum : public EnumBase {
public:
    AuthLengthEnum();
};

extern HashEnum zrtpHashes;
extern SymCipherEnum zrtpSymCiphers;
extern PubKeyEnum zrtpPubKeys;
extern SasTypeEnum zrtpSasTypes;
extern AuthLengthEnum zrtpAuthLengths;

/**
 * ZRTP configuration data.
 *
 * This class contains data and functions to set ZRTP configuration data.
 * An application may use this class to set configuration information for
 * ZRTP. ZRTP uses this configuration information to announce various
 * algorithms via its Hello message. An application may use this class to
 * restrict or allow use of algorithms.
 *
 * The constructor does not set any algorithms, thus it is an empty
 * configuration. An application may use this empty configuration and
 * hand it over to ZRTP. In this case ZRTP does not announce any algorithms
 * in its Hello message and uses mandatory algorithms only.
 *
 * An application can configure implemented algorithms only.
 */

class ZrtpConfigure {
public:
    ZrtpConfigure();		 /* Creates Configuration data */
    ~ZrtpConfigure();

    /**
     * Set the maximum number of algorithms per algorithm type that an application can
     * configure.
     */
    static const int maxNoOfAlgos = 7;
    /**
     * Convenience function that sets a pre-defined standard configuration.
     *
     * The standard configuration consists of the following algorithms:
     * <ul>
     * <li> Hash: SHA256 </li>
     * <li> Symmetric Cipher: AES 128, AES 256 </li>
     * <li> Public Key Algorithm: DH2048, DH3027, MultiStream </li>
     * <li> SAS type: libase 32 </li>
     * <li> SRTP Authentication lengths: 32, 80 </li>
     *</ul>
     */
    void setStandardConfig();

    /**
     * Convenience function that sets the mandatory algorithms only.
     *
     * Mandatory algorithms are:
     * <ul>
     * <li> Hash: SHA256 </li>
     * <li> Symmetric Cipher: AES 128 </li>
     * <li> Public Key Algorithm: DH3027, MultiStream </li>
     * <li> SAS type: libase 32 </li>
     * <li> SRTP Authentication lengths: 32, 80 </li>
     *</ul>
     */
    void setMandatoryOnly();

    /**
     * Clear all configuration data.
     *
     * The functions clears all configuration data.
     */
    void clear();

    /**
     * Add a hash algorithm to configuration data.
     *
     * Adds the specified algorithm to the configuration data.
     * If no free configuration data slot is available the
     * function does not add the algorithm and return zero. The
     * methods appends the algorithm to the existing algorithms.
     *
     * @param algoType
     *    Specifies which algorithm type to select
     * @param algo
     *    The enumeration of the algorithm to add.
     * @return
     *    Number of free configuration data slots.
     */
    int32_t addAlgo(AlgoTypes algoType, AlgorithmEnum& algo);

    /**
     * Add a algorithm to configuration data.
     *
     * Adds the specified algorithm to the configuration data.
     * If no free configuration data slot is available the
     * function does not add the algorithm and return zero.
     *
     * @param algoType
     *    Specifies which algorithm type to select
     * @param algo
     *    The enumeration of the algorithm to add.
     * @param index
     *    The index where to add the algorihm
     * @return
     *    Number of free configuration data slots.
     */
    int32_t addAlgoAt(AlgoTypes algoType, AlgorithmEnum& algo, int32_t index);

    /**
     * Remove a algorithm from configuration data.
     *
     * Removes the specified algorithm from configuration data. If
     * the algorithm was not configured previously the function does
     * not modify the configuration data and returns the number of
     * free configuration data slots.
     *
     * If an application removes all algorithms then ZRTP does not
     * include any algorithm into the hello message and falls back
     * to a predefined mandatory algorithm.
     *
     * @param algoType
     *    Specifies which algorithm type to select
     * @param algo
     *    The enumeration of the algorithm to remove.
     * @return
     *    Number of free configuration slots.
     */
    int32_t removeAlgo(AlgoTypes algoType, AlgorithmEnum& algo);

    /**
     * Returns the number of configured algorithms.
     *
     * @param algoType
     *    Specifies which algorithm type to select
     * @return
     *    The number of configured algorithms (used configuration 
     *    data slots)
     */
    int32_t getNumConfiguredAlgos(AlgoTypes algoType);

    /**
     * Returns the identifier of the algorithm at index.
     *
     * @param algoType
     *    Specifies which algorithm type to select
     * @param index
     *    The index in the list of the algorihm type
     * @return
     *    A pointer the the algorithm enumeration. If the index 
     *    does not point to a configured slot then the function
     *    returns NULL.
     *
     */
    AlgorithmEnum& getAlgoAt(AlgoTypes algoType, int32_t index);

    /**
     * Checks if the configuration data of the algorihm type already contains
     * a specific algorithms.
     *
     * @param algoType
     *    Specifies which algorithm type to select
     * @param algo
     *    The algorithm to check
     * @return
     *    True if the algorithm was found, false otherwise.
     *
     */
    bool containsAlgo(AlgoTypes algoType, AlgorithmEnum& algo);

    /**
     * Enables or disables trusted MitM processing.
     *
     * For further details of trusted MitM processing refer to ZRTP
     * specification, chapter 7.3
     * 
     * @param yesNo
     *    If set to true then trusted MitM processing is enabled.
     */
    void setTrustedMitM(bool yesNo);
    
    /**
     * Check status of trusted MitM processing.
     * 
     * @return
     *    Returns true if trusted MitM processing is enabled.
     */
    bool isTrustedMitM();
    
    /**
     * Enables or disables SAS signature processing.
     * 
     * For further details of trusted MitM processing refer to ZRTP
     * specification, chapter 7.2
     *
     * @param yesNo
     *    If set to true then certificate processing is enabled.
     */
    void setSasSignature(bool yesNo);
    
    /**
     * Check status of SAS signature processing.
     * 
     * @return
     *    Returns true if certificate processing is enabled.
     */
    bool isSasSignature();
    
    void printConfiguredAlgos(AlgoTypes algoTyp);

  private:
    std::vector<AlgorithmEnum* > hashes;
    std::vector<AlgorithmEnum* > symCiphers;
    std::vector<AlgorithmEnum* > publicKeyAlgos;
    std::vector<AlgorithmEnum* > sasTypes;
    std::vector<AlgorithmEnum* > authLengths;
    
    bool enableTrustedMitM;
    bool enableSasSignature;

    AlgorithmEnum& getAlgoAt(std::vector<AlgorithmEnum* >& a, int32_t index);
    int32_t addAlgo(std::vector<AlgorithmEnum* >& a, AlgorithmEnum& algo);
    int32_t addAlgoAt(std::vector<AlgorithmEnum* >& a, AlgorithmEnum& algo, int32_t index);
    int32_t removeAlgo(std::vector<AlgorithmEnum* >& a,  AlgorithmEnum& algo);
    int32_t getNumConfiguredAlgos(std::vector<AlgorithmEnum* >& a);
    bool containsAlgo(std::vector<AlgorithmEnum* >& a, AlgorithmEnum& algo);
    std::vector<AlgorithmEnum* >& getEnum(AlgoTypes algoType);

    void printConfiguredAlgos(std::vector<AlgorithmEnum* >& a);

  protected:

  public:
};





#endif

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
