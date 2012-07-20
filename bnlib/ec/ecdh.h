#ifndef _ECDH_H_
#define _ECDH_H_

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Takes a secret large random number and computes the public EC point.
 *
 * @param curve is the NIST curve to use.
 *
 * @param Q the functions writes the computed public point in this parameter.
 *
 * @param d is the secret random number.
 */
int ecdhGeneratePublic(const NistECpCurve *curve, EcPoint *Q, const BigNum *d);

/**
 * Computes the key agreement value.
 *
 * Takes the public EC point of the other party and applies the EC DH algorithm
 * to compute the agreed value.
 *
 * @param curve is the NIST curve to use, must be the same curve as used in
 *              @c ecdhGeneratePublic.
 *
 * @param agreemtn the functions writes the computed agreed value in this parameter.
 *
 * @param Q is the other party's public point.
 *
 * @param d is the secret random number.
 */
int ecdhComputeAgreement(const NistECpCurve *curve, BigNum *agreement, const EcPoint *Q, const BigNum *d);

#ifdef __cplusplus
}
#endif

#endif