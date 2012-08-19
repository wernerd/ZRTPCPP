/*
 * Copyright (C) 2012 Werner Dittmann
 * All rights reserved. For licensing and other legal details, see the file legal.c.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */
#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdint.h>

#include <bn.h>
#include <bnprint.h>

#include <ec/ec.h>

static BigNum _mpiZero;
static BigNum _mpiOne;
static BigNum _mpiTwo;
static BigNum _mpiThree;
static BigNum _mpiFour;
static BigNum _mpiEight;

static BigNum* mpiZero  = &_mpiZero;
static BigNum* mpiOne   = &_mpiOne;
static BigNum* mpiTwo   = &_mpiTwo;
static BigNum* mpiThree = &_mpiThree;
static BigNum* mpiFour  = &_mpiFour;
static BigNum* mpiEight = &_mpiEight;
static int initialized = 0;


/* The following parameters are given:
 - The prime modulus p
 - The order n
 - The 160-bit input seed SEED to the SHA-1 based algorithm (i.e., the domain parameter seed)
 - The output c of the SHA-1 based algorithm
 - The coefficient b (satisfying b2 c ≡ –27 (mod p))
 - The base point x coordinate Gx
 - The base point y coordinate Gy
*/

typedef struct _curveData {
    char *p;
    char *n;
    char *SEED;
    char *c;
    char *b;
    char *Gx;
    char *Gy;
} curveData;

static curveData nist192 = {
    "6277101735386680763835789423207666416083908700390324961279",
    "6277101735386680763835789423176059013767194773182842284081",
    "3045ae6fc8422f64ed579528d38120eae12196d5",
    "3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65",
    "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
    "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
    "07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
};

static curveData nist224 = {
    "26959946667150639794667015087019630673557916260026308143510066298881",
    "26959946667150639794667015087019625940457807714424391721682722368061",
    "bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5",
    "5b056c7e11dd68f40469ee7f3c7a7d74f7d121116506d031218291fb",
    "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
    "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
    "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
};

static curveData nist256 = {
    "115792089210356248762697446949407573530086143415290314195533631308867097853951",
    "115792089210356248762697446949407573529996955224135760342422259061068512044369",
    "c49d360886e704936a6678e1139d26b7819f7e90",
    "7efba1662985be9403cb055c75d4f7e0ce8d84a9c5114abcaf3177680104fa0d",
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
};

static curveData nist384 = {
    "39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319",
    "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643",
    "a335926aa319a27a1d00896a6773a4827acdac73",
    "79d1e655f868f02fff48dcdee14151ddb80643c1406d0ca10dfe6fc52009540a495e8042ea5f744f6e184667cc722483",
    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
};

static curveData nist521 = {
    "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151",
    "6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449",
    "d09e8800291cb85396cc6717393284aaa0da64ba",
        "0b48bfa5f420a34949539d2bdfc264eeeeb077688e44fbf0ad8f6d0edb37bd6b533281000518e19f1b9ffbe0fe9ed8a3c2200b8f875e523868c70c1e5bf55bad637",
        "051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
         "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
        "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
};

/*============================================================================*/
/*    Bignum Shorthand Functions                                              */
/*============================================================================*/

int bnAddMod_ (struct BigNum *rslt, struct BigNum *n1, struct BigNum *mod)
{
    bnAdd (rslt, n1);
    if (bnCmp (rslt, mod) >= 0) {
        bnSub (rslt, mod);
    }
    return 0;
}

int bnAddQMod_ (struct BigNum *rslt, unsigned n1, struct BigNum *mod)
{
    bnAddQ (rslt, n1);
    if (bnCmp (rslt, mod) >= 0) {
        bnSub (rslt, mod);
    }
    return 0;
}

int bnSubMod_ (struct BigNum *rslt, struct BigNum *n1, struct BigNum *mod)
{
    if (bnCmp (rslt, n1) < 0) {
        bnAdd (rslt, mod);
    }
    bnSub (rslt, n1);
    return 0;
}

int bnSubQMod_ (struct BigNum *rslt, unsigned n1, struct BigNum *mod)
{
    if (bnCmpQ (rslt, n1) < 0) {
        bnAdd (rslt, mod);
    }
    bnSubQ (rslt, n1);
    return 0;
}

int bnMulMod_ (struct BigNum *rslt, struct BigNum *n1, struct BigNum *n2, struct BigNum *mod)
{
    bnMul (rslt, n1, n2);
    bnMod (rslt, rslt, mod);
    return 0;
}

int bnMulQMod_ (struct BigNum *rslt, struct BigNum *n1, unsigned n2, struct BigNum *mod)
{
    bnMulQ (rslt, n1, n2);
    bnMod (rslt, rslt, mod);
    return 0;
}

int bnSquareMod_ (struct BigNum *rslt, struct BigNum *n1, struct BigNum *mod)
{
    bnSquare (rslt, n1);
    bnMod (rslt, rslt, mod);
    return 0;
}

/**
 * \brief          Signed substraction modulo: X = A - B mod M.
 *
 * \param          X  Address of destination MPI
 * \param          A  Address of Left-hand MPI
 * \param          B  Address of Right-hand MPI
 * \param          M  Address of Modulo
 */
/* #define MPI_SUB_MPI_MOD(X, A, B, M) {MPI_CHK(mpi_sub_mpi(X, A, B)); if (mpi_cmp_int(X, 0) < 0) {MPI_CHK(mpi_add_mpi(X, X, M));}} */

/**
 * \brief          Signed addition modulo: X = A + B mod M.
 *
 * \param          X  Address of destination MPI
 * \param          A  Address of Left-hand MPI
 * \param          B  Address of Right-hand MPI
 * \param          M  Address of Modulo
 */
/*#define MPI_ADD_MPI_MOD(X, A, B, M) {MPI_CHK(mpi_add_mpi(X, A, B)); if (mpi_cmp_mpi(X, M) >= 0) {MPI_CHK(mpi_sub_mpi(X, X, M));}} */

/**
 * \brief          Signed multiplication modulo: X = A * B mod M.
 *
 * \param          X  Address of destination MPI
 * \param          A  Address of Left-hand MPI
 * \param          B  Address of Right-hand MPI
 * \param          M  Address of Modulo
 */
/*#define MPI_MUL_MPI_MOD(X, A, B, M) {MPI_CHK(mpi_mul_mpi(X, A, B)); if (mpi_cmp_mpi(X, M) >= 0) {MPI_CHK(mpi_mod_mpi(X, X, M));}}*/


int ecGetCurveNistECp(NistCurves curveId, NistECpCurve *curve)
{
    size_t maxBits;
    curveData *cd;

    if (!initialized) {
        bnBegin(mpiZero); bnSetQ(mpiZero, 0);
        bnBegin(mpiOne); bnSetQ(mpiOne, 1);
        bnBegin(mpiTwo); bnSetQ(mpiTwo, 2);
        bnBegin(mpiThree); bnSetQ(mpiThree, 3);
        bnBegin(mpiFour); bnSetQ(mpiFour, 4);
        bnBegin(mpiEight); bnSetQ(mpiEight, 8);
        initialized = 1;
    }
    if (curve == NULL)
        return -2;

    bnBegin(&curve->_p);    curve->p = &curve->_p;
    bnBegin(&curve->_n);    curve->n = &curve->_n;
    bnBegin(&curve->_SEED); curve->SEED = &curve->_SEED;
    bnBegin(&curve->_c);    curve->c = &curve->_c;
    bnBegin(&curve->_a);    curve->a = &curve->_a;
    bnBegin(&curve->_b);    curve->b = &curve->_b;
    bnBegin(&curve->_Gx);   curve->Gx = &curve->_Gx;
    bnBegin(&curve->_Gy);   curve->Gy = &curve->_Gy;

    /* Initialize scratchpad variables and their pointers */
    bnBegin(&curve->_S1); curve->S1 = &curve->_S1;
    bnBegin(&curve->_U1); curve->U1 = &curve->_U1;
    bnBegin(&curve->_H);  curve->H = &curve->_H;
    bnBegin(&curve->_R);  curve->R = &curve->_R;
    bnBegin(&curve->_t0); curve->t0 = &curve->_t0;
    bnBegin(&curve->_t1); curve->t1 = &curve->_t1;
    bnBegin(&curve->_t2); curve->t2 = &curve->_t2;
    bnBegin(&curve->_t3); curve->t3 = &curve->_t3;

    switch (curveId) {
    case NIST192P:
        cd = &nist192;
        break;

    case NIST224P:
        cd = &nist224;
        break;

    case NIST256P:
        cd = &nist256;
        break;

    case NIST384P:
        cd = &nist384;
        break;

    case NIST521P:
        cd = &nist521;
        break;

    default:
        return -2;
    }

    bnReadAscii(curve->p, cd->p, 10);
    bnReadAscii(curve->n, cd->n, 10);
    bnReadAscii(curve->SEED, cd->SEED, 16);
    bnReadAscii(curve->c, cd->c, 16);
    bnCopy(curve->a, curve->p);
    bnSub(curve->a, mpiThree);
    bnReadAscii(curve->b, cd->b, 16);
    bnReadAscii(curve->Gx, cd->Gx, 16);
    bnReadAscii(curve->Gy, cd->Gy, 16);

    /* variables must be able to hold p^2, plus one nimb (min. 15 bits) for overflow */
    maxBits = bnBits(curve->p) * 2 + 15;

    /* The set_bit allocates enough memory to hold maximum values */
    /* Initialize scratchpad variables before use */
    bnPrealloc(curve->S1, maxBits);
    bnPrealloc(curve->U1, maxBits);
    bnPrealloc(curve->H, maxBits);
    bnPrealloc(curve->R, maxBits);
    bnPrealloc(curve->S1, maxBits);
    bnPrealloc(curve->t1, maxBits);
    bnPrealloc(curve->t2, maxBits);
    bnPrealloc(curve->t3, maxBits);

    return 0;

/*     ecFreeCurveNistECp(curve);
     return ret;
*/
}


void ecFreeCurveNistECp(NistECpCurve *curve) 
{
    if (curve == NULL)
        return;

    bnEnd(curve->p);
    bnEnd(curve->n);
    bnEnd(curve->SEED);
    bnEnd(curve->c);
    bnEnd(curve->b);
    bnEnd(curve->Gx);
    bnEnd(curve->Gy);

    bnEnd(curve->S1);
    bnEnd(curve->U1);
    bnEnd(curve->H);
    bnEnd(curve->R);
    bnEnd(curve->t0);
    bnEnd(curve->t1);
    bnEnd(curve->t2);
    bnEnd(curve->t3);
}


/*============================================================================*/
/*    Elliptic Curve arithmetic                                               */
/*============================================================================*/

/* Add two elliptic curve points. Any of them may be the same object. */
int ecAddPoint(const NistECpCurve *curve, EcPoint *R, const EcPoint *P, const EcPoint *Q)
{
    struct BigNum trsltx, trslty;
    struct BigNum t1, gam;
    struct BigNum bnzero;

    bnBegin (&bnzero);

    /* Check for an operand being zero */
    if (bnCmp (P->x, &bnzero) == 0 && bnCmp (P->y, &bnzero) == 0) {
        bnCopy (R->x, Q->x); bnCopy (R->y, Q->y);
        bnEnd (&bnzero);
        return 0;
    }
    if (bnCmp (Q->x, &bnzero) == 0 && bnCmp (Q->y, &bnzero) == 0) {
        bnCopy (R->x, P->x); bnCopy (R->y, P->y);
        bnEnd (&bnzero);
        return 0;
    }

    /* Check if p1 == -p2 and return 0 if so */
    if (bnCmp (P->x, Q->x) == 0) {
        struct BigNum tsum;
        bnBegin (&tsum);
        bnCopy (&tsum, P->x);
        bnAddMod_ (&tsum, Q->x, curve->p);
        if (bnCmp (&tsum, &bnzero) == 0) {
            bnSetQ (R->x, 0); bnSetQ (R->y, 0);
            bnEnd (&tsum);
            bnEnd (&bnzero);
            return 0;
        }
        bnEnd (&tsum);
    }

    bnBegin (&t1);
    bnBegin (&gam);
    bnBegin (&trsltx);
    bnBegin (&trslty);

    /* Check for doubling, different formula for gamma */
    if (bnCmp (P->x, Q->x) == 0 && bnCmp (P->y, Q->y) == 0) {
        bnCopy (&t1, P->y);
        bnAddMod_ (&t1, P->y, curve->p);
        bnInv (&t1, &t1, curve->p);
        bnSquareMod_ (&gam, P->x, curve->p);
        bnMulQMod_ (&gam, &gam, 3, curve->p);
        bnSubQMod_ (&gam, 3, curve->p);
        bnMulMod_ (&gam, &gam, &t1, curve->p);
    } else {
        bnCopy (&t1, Q->x);
        bnSubMod_ (&t1, P->x, curve->p);
        bnInv (&t1, &t1, curve->p);
        bnCopy (&gam, Q->y);
        bnSubMod_ (&gam, P->y, curve->p);
        bnMulMod_ (&gam, &gam, &t1, curve->p);
    }

    bnSquareMod_ (&trsltx, &gam, curve->p);
    bnSubMod_ (&trsltx, P->x, curve->p);
    bnSubMod_ (&trsltx, Q->x, curve->p);

    bnCopy (&trslty, P->x);
    bnSubMod_ (&trslty, &trsltx, curve->p);
    bnMulMod_ (&trslty, &trslty, &gam, curve->p);
    bnSubMod_ (&trslty, P->y, curve->p);

    bnCopy (R->x, &trsltx);
    bnCopy (R->y, &trslty);

    bnEnd (&t1);
    bnEnd (&gam);
    bnEnd (&trsltx);
    bnEnd (&trslty);
    bnEnd (&bnzero);

    return 0;
}

int ecMulPointScalar(const NistECpCurve *curve, EcPoint *R, const EcPoint *P, const BigNum *scalar)
{

    /* MPI_CHK below macro requires a 'ret' variable and a cleanup label */
    int ret = 0;
    int i;
    int bits = bnBits(scalar);
    EcPoint n;

    INIT_EC_POINT(&n);
    bnCopy(n.x, P->x);
    bnCopy(n.y, P->y);
    bnCopy(n.z, P->z);

    bnSetQ(R->x, 0);
    bnSetQ(R->y, 0);
    bnSetQ(R->z, 0);

    for (i = 0; i < bits; i++) {
        if (bnReadBit(scalar, i))
            ecAddPoint(curve, R, R, &n);

        ecAddPoint(curve, &n, &n, &n);
/*        ecDoublePoint(curve, &n, &n); */
    }
    FREE_EC_POINT(&n);
    return ret;
}

#ifdef WEAKRANDOM
/*
 * A standard random number generator that uses the portable random() system function.
 *
 * This should be enhanced to use a better random generator
 */
static int _random(unsigned char *output, size_t len)
{
    size_t i;

    for(i = 0; i < len; ++i )
        output[i] = random();

    return( 0 );
}
#else
#include <cryptcommon/ZrtpRandom.h>
static int _random(unsigned char *output, size_t len)
{
    return zrtp_getRandomData(output, len);
}
#endif

int ecGenerateRandomNumber(const NistECpCurve *curve, BigNum *d)
{
    BigNum c, nMinusOne;

    size_t randomBytes = ((bnBits(curve->n) + 64) + 7) / 8;

    uint8_t *ran = malloc(randomBytes);

    bnBegin(&c);
    bnBegin(&nMinusOne);

    bnCopy(&nMinusOne, curve->n);
    bnSubMod_(&nMinusOne, mpiOne, curve->p);

    bnSetQ(d, 0);

    while (!bnCmpQ(d, 0)) {
        /* use _random function */
        _random(ran, randomBytes);
        bnInsertBigBytes(&c, ran, 0, randomBytes);
        bnMod(d, &c, &nMinusOne);
    }

    bnEnd(&c);
    bnEnd(&nMinusOne);
    free(ran);

    return 0;
}
