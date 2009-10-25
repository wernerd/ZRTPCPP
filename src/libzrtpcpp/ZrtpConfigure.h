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

#include <stdint.h>

// Keep the Hash identifers in supportedHashes in the same order than the
// following enum, starting with zero.

/**
 * This enum lists the implemented hashes that ZRTP can use.
 *
 * Applications can use the enum values to configure ZRTP.
 */
enum SupportedHashes {
    Sha256,    //!< SHA256 - this is a mandatory hash algorithm
    EndSupportedHashes
};

// Keep the Cipher identifers in supportedCipher in the same order than the
// following enum, starting with zero.
/**
 * This enum lists the implemented symmetric ciphers that ZRTP can use.
 *
 * Applications can use the enum values to configure ZRTP.
 */
enum SupportedSymCiphers {
    Aes256,    //!< AES 256 - this is an optional symmetric cipher
    Aes128,    //!< AES 128 - this is a mandatory symmetric cipher
    EndSupportedSymCiphers
};

// Keep the PubKey identifers in supportedPubKey in the same order than the
// following enum, starting with zero.
/**
 * This enum lists the implemented public key algorithms that ZRTP can use.
 *
 * Applications can use the enum values to configure ZRTP.
 */
enum SupportedPubKeys {
    Dh2048,      //<! DH 2048 - this is an optional PK algorithm
    // Ec256,
    Dh3072,      //<! DH 3072 - this is a mandatory PK algorithm
    // Ec384,
    MultiStream, //<! Multi stream mode is an optional mode, in some cases mandatory
    EndSupportedPubKeys
};

// Keep the SAS identifers in supportedSASType in the same order than the
// following enum, starting with zero.
/**
 * This enum lists the implemented SAS type algorithms that ZRTP can use.
 *
 * Applications can use the enum values to configure ZRTP.
 */
enum SupportedSASTypes {
    Libase32,    //!< SAS base 32 - this is a mandatory SAS type
    EndSupportedSASTypes
};

// Keep the auth len identifers in supportedAuthLen in the same order than the
// following enum, starting with zero.
/**
 * This enum lists the implemented SRTP authentication lengths that ZRTP can use.
 *
 * Application can use the enum values to configure ZRTP.
 */
enum SupportedAuthLengths {
    AuthLen32,    //!< Length 32 - this is a mandatory SRTP authentication length
    AuthLen80,    //!< Length 80 - this is a mandatory SRTP authentication length
    EndSupportedAuthLenghts
};

#define MAX_NO_OF_ALGOS   7

typedef struct algorithms {
    int32_t numConfiguredAlgos;
    int32_t endSupportedAlgos;
    int32_t algos[MAX_NO_OF_ALGOS];
} algorithms_t;

/**
 * ZRTP configuration data.
 *
 * This class contains data and functions to set ZRTP configuration data.
 * An application may use this class to set configuration information for
 * ZRTP. ZRTP uses this configuration information to announce various
 * algorithms via its Hell message. An application may use this class to
 * restrict or allow use of algorithms.
 *
 * An application can configure implemented algorithms only.
 */
class ZrtpConfigure {

  private:
    algorithms_t  hashes;
    algorithms_t  symCiphers;
    algorithms_t  publicKeyAlgos;
    algorithms_t  sasTypes;
    algorithms_t  authLengths;

    int32_t getAlgoAt(algorithms_t* a, int32_t index);
    int32_t addAlgo(algorithms_t* a, int32_t algo);
    int32_t removeAlgo(algorithms_t* a, int32_t algo);
    int32_t getNumConfiguredAlgos(algorithms_t* a);

//    void dumpAlgorithms(algorithms_t* a);

  protected:

  public:
    ZrtpConfigure();		 /* Creates Configuration data */
    ~ZrtpConfigure();

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
/*
 * Hash configuration functions
 */
    /**
     * Add a hash algorithm to configuration data.
     *
     * Adds the specified hash algorithm to the configuration data.
     * If no free configuration data slot is available the
     * function does not add the algorithm and return zero.
     *
     * @param algo
     *    The identifier of the hash algorithm to add.
     * @return
     *    Number of free hash configuration data slots.
     */
    int32_t addHashAlgo(SupportedHashes algo);

    /**
     * Remove a hash algorithm from configuration data.
     *
     * Removes the specified algorithm from hash configuration data. If
     * the algorithm was not configured previously the function does
     * not modify the configuration data and return the number of
     * free configuration data slots.
     *
     * If an application removes all algorithms then ZRTP does not
     * include any algorithm into the hello message and falls back
     * to a predefined mandatory algorithm. In this case SHA256.
     *
     * @param algo
     *    The identifier of the hash algorithm to remove.
     * @return
     *    Number of free hash configuration slots.
     */
    int32_t removeHashAlgo(SupportedHashes algo);

    /**
     * Returns the number of configured hash algorithms.
     *
     * @return
     *    The number of configured hash algorithms (used configuration 
     *    data slots)
     */
    int32_t getNumConfiguredHashes();

    /**
     * Returns the identifier of the hash algorithm at the 
     * given index.
     *
     * If the index does not point to a configured slot then the function
     * returns the value <code>EndSupportedHashes</code>.
     */
    SupportedHashes getHashAlgoAt(int32_t index);

    //    void dumpHash();

/*
 * SymCipher configuration functions
 */
    /**
     * Add a symmetric cipher algorithm to configuration data.
     *
     * Adds the specified cipher algorithm to the configuration data.
     * If no free configuration data slot is available the
     * function does not add the algorithm and return zero.
     *
     * @param algo
     *    The identifier of the cipher algorithm to add.
     * @return
     *    Number of free cipher configuration data slots.
     */
    int32_t addSymCipherAlgo(SupportedSymCiphers algo);

    /**
     * Remove a symmetric cipher algorithm from configuration data.
     *
     * Removes the specified algorithm from cipher configuration data. If
     * the algorithm was not configured previously the function does
     * not modify the configuration data and return the number of
     * free configuration data slots.
     *
     * If an application removes all algorithms then ZRTP does not
     * include any algorithm into the hello message and falls back
     * to a predefined mandatory algorithm. In this case AES 128.
     *
     * @param algo
     *    The identifier of the cipher algorithm to remove.
     * @return
     *    Number of free cipher configuration slots.
     */
    int32_t removeSymCipherAlgo(SupportedSymCiphers algo);

    /**
     * Returns the number of configured symmetric cipher algorithms.
     *
     * @return
     *    The number of configured cipher algorithms (used configuration 
     *    data slots)
     */
    int32_t getNumConfiguredSymCiphers();

    /**
     * Returns the identifier of the symmetric cipher algorithm at 
     * the given index.
     *
     * If the index does not point to a configured slot then the function
     * returns the value <code>EndSupportedSymCiphers</code>.
     */
    SupportedSymCiphers getSymCipherAlgoAt(int32_t index);

/*
 * Public key configuration functions
 */
    /**
     * Add a public key algorithm to configuration data.
     *
     * Adds the specified public key algorithm to the configuration data.
     * If no free configuration data slot is available the
     * function does not add the algorithm and return zero.
     *
     * If an application removes all algorithms then ZRTP does not
     * include any algorithm into the hello message and falls back
     * to a predefined mandatory algorithm. In this case DH 3072.
     *
     * @param algo
     *    The identifier of the public key algorithm to add.
     * @return
     *    Number of free public key configuration data slots.
     */
    int32_t addPubKeyAlgo(SupportedPubKeys algo);

    /**
     * Remove a public key algorithm from configuration data.
     *
     * Removes the specified algorithm from public key configuration data. If
     * the algorithm was not configured previously the function does
     * not modify the configuration data and return the number of
     * free configuration data slots.
     *
     * @param algo
     *    The identifier of the public key algorithm to remove.
     * @return
     *    Number of free public key configuration slots.
     */
    int32_t removePubKeyAlgo(SupportedPubKeys algo);

    /**
     * Returns the number of configured public key algorithms.
     *
     * @return
     *    The number of configured public key algorithms (used configuration 
     *    data slots)
     */
    int32_t getNumConfiguredPubKeys();

    /**
     * Returns the identifier of the public key algorithm at 
     * the given index.
     *
     * If the index does not point to a configured slot then the function
     * returns the value <code>EndSupportedPubKeys</code>.
     */
    SupportedPubKeys getPubKeyAlgoAt(int32_t index);

/*
 * SAS type configuration functions
 */
    /**
     * Add a SAS type algorithm to configuration data.
     *
     * Adds the specified SAS type algorithm to the configuration data.
     * If no free configuration data slot is available the
     * function does not add the algorithm and return zero.
     *
     * @param algo
     *    The identifier of the SAS type algorithm to add.
     * @return
     *    Number of free SAS type configuration data slots.
     */
    int32_t addSasTypeAlgo(SupportedSASTypes algo);

    /**
     * Remove a SAS type algorithm from configuration data.
     *
     * Removes the specified algorithm from SAS type configuration data. 
     * If the algorithm was not configured previously the function does
     * not modify the configuration data and return the number of
     * free configuration data slots.
     *
     * If an application removes all algorithms then ZRTP does not
     * include any algorithm into the hello message and falls back
     * to a predefined mandatory algorithm. In this case base 32.
     *
     * @param algo
     *    The identifier of the SAS type algorithm to remove.
     * @return
     *    Number of free SAS type configuration slots.
     */
    int32_t removeSasTypeAlgo(SupportedSASTypes algo);
    /**
     * Returns the number of configured SAS type algorithms.
     *
     * @return
     *    The number of configured SAS type algorithms (used configuration 
     *    data slots)
     */
    int32_t getNumConfiguredSasTypes();
    /**
     * Returns the identifier of the SAS type algorithm at the given index.
     *
     * If the index does not point to a configured slot then the function
     * returns the value <code>EndSupportedSASTypes</code>.
     */
    SupportedSASTypes getSasTypeAlgoAt(int32_t index);

/*
 * Authentication length configuration functions
 */
    /**
     * Add a SRTP authentication length to configuration data.
     *
     * Adds the specified SRTP authentication length to the 
     * configuration data.
     * If no free configuration data slot is available the
     * function does not add the algorithm and return zero.
     *
     * @param algo
     *    The identifier of the SRTP authentication length to add.
     * @return
     *    Number of free SRTP authentication length configuration data 
     *    slots.
     */
    int32_t addAuthLength(SupportedAuthLengths algo);

    /**
     * Remove a SRTP authentication length from configuration data.
     *
     * Removes the specified algorithm from SRTP authentication length 
     * configuration data. If the algorithm was not configured previously 
     * the function does not modify the configuration data and retursn 
     * the number of free configuration data slots.
     *
     * If an application removes all algorithms then ZRTP does not
     * include any algorithm into the hello message and falls back
     * to a predefined mandatory algorithm. In this case length 32.
     *
     * @param algo
     *    The identifier of the SRTP authentication length to remove.
     * @return
     *    Number of free SRTP authentication length configuration slots.
     */
    int32_t removeAuthLength(SupportedAuthLengths algo);
    /**
     * Returns the number of configured SRTP authentication lengths.
     *
     * @return
     *    The number of configured SRTP authentication lengths (used 
     * configuration data slots)
     */
    int32_t getNumConfiguredAuthLengths();
    /**
     * Returns the identifier of the SRTP authentication length at the 
     * given index.
     *
     * If the index does not point to a configured slot then the function
     * returns the value <code>EndSupportedAuthLength</code>.
     */
    SupportedAuthLengths getAuthLengthAt(int32_t index);
};

#endif

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
