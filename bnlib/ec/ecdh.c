
#include <ec/ec.h>
#include <ec/ecdh.h>

int ecdhGeneratePublic(const NistECpCurve *curve, EcPoint *Q, const BigNum *d)
{
    EcPoint G;

    INIT_EC_POINT(&G);
    SET_EC_BASE_POINT(curve, &G);

    ecMulPointScalar(curve, Q, &G, d);

    FREE_EC_POINT(&G);

    return 0;
}

int ecdhComputeAgreement(const NistECpCurve *curve, BigNum *agreement, const EcPoint *Q, const BigNum *d)
{
    EcPoint t0;

    INIT_EC_POINT(&t0);

    ecMulPointScalar(curve, &t0, Q, d);
/*    ecGetAffine(curve, &t0, &t0); */
    /* TODO: check for infinity here */

    bnCopy(agreement, t0.x);

    FREE_EC_POINT(&t0);

    return 0;
}
