/*
 * Public Domain, Authors:
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */
// Prepared for C++ compile, extracted common functions by Werner Dittmann

#include "crypto/zrtpKem.h"

/* from supercop/crypto_sort/int32/portable4/sort.c */

void crypto_sort_int32(void *array,long long n)
{
    long long top,p,q,r,i,j;
    auto *x = reinterpret_cast<int32 *>(array);

    if (n < 2) return;
    top = 1;
    while (top < n - top) top += top;

    for (p = top;p >= 1;p >>= 1) {
        i = 0;
        while (i + 2 * p <= n) {
            for (j = i;j < i + p;++j)
                int32_MINMAX(x[j],x[j+p]);
            i += 2 * p;
        }
        for (j = i;j < n - p;++j)
            int32_MINMAX(x[j],x[j+p]);

        i = 0;
        j = 0;
        for (q = top;q > p;q >>= 1) {
            if (j != i) for (;;) {
                    if (j == n - q) goto done;
                    int32 a = x[j + p];
                    for (r = q;r > p;r >>= 1)
                        int32_MINMAX(a,x[j + r]);
                    x[j + p] = a;
                    ++j;
                    if (j == i + p) {
                        i += 2 * p;
                        break;
                    }
                }
            while (i + p <= n - q) {
                for (j = i;j < i + p;++j) {
                    int32 a = x[j + p];
                    for (r = q;r > p;r >>= 1)
                        int32_MINMAX(a,x[j+r]);
                    x[j + p] = a;
                }
                i += 2 * p;
            }
            /* now i + p > n - q */
            j = i;
            while (j < n - q) {
                int32 a = x[j + p];
                for (r = q;r > p;r >>= 1)
                    int32_MINMAX(a,x[j+r]);
                x[j + p] = a;
                ++j;
            }

            done: ;
        }
    }
}

/* from supercop/crypto_sort/uint32/useint32/sort.c */

/* can save time by vectorizing xor loops */
/* can save time by integrating xor loops with int32_sort */

void crypto_sort_uint32(void *array,long long n)
{
    auto *x = reinterpret_cast<uint32 *>(array);
    long long j;
    for (j = 0;j < n;++j) x[j] ^= 0x80000000;
    crypto_sort_int32(array,n);
    for (j = 0;j < n;++j) x[j] ^= 0x80000000;
}

/* from supercop/crypto_kem/sntrup761/ref/uint32.c */

/*
CPU division instruction typically takes time depending on x.
This software is designed to take time independent of x.
Time still varies depending on m; user must ensure that m is constant.
Time also varies on CPUs where multiplication is variable-time.
There could be more CPU issues.
There could also be compiler issues.
*/

void uint32_divmod_uint14(uint32 *q,uint16 *r,uint32 x,uint16 m)
{
    uint32 v = 0x80000000;
    uint32 qpart;
    uint32 mask;

    v /= m;

    /* caller guarantees m > 0 */
    /* caller guarantees m < 16384 */
    /* vm <= 2^31 <= vm+m-1 */
    /* xvm <= 2^31 x <= xvm+x(m-1) */

    *q = 0;

    qpart = (x*(uint64)v)>>31;
    /* 2^31 qpart <= xv <= 2^31 qpart + 2^31-1 */
    /* 2^31 qpart m <= xvm <= 2^31 qpart m + (2^31-1)m */
    /* 2^31 qpart m <= 2^31 x <= 2^31 qpart m + (2^31-1)m + x(m-1) */
    /* 0 <= 2^31 newx <= (2^31-1)m + x(m-1) */
    /* 0 <= newx <= (1-1/2^31)m + x(m-1)/2^31 */
    /* 0 <= newx <= (1-1/2^31)(2^14-1) + (2^32-1)((2^14-1)-1)/2^31 */

    x -= qpart*m; *q += qpart;
    /* x <= 49146 */

    qpart = (x*(uint64)v)>>31;
    /* 0 <= newx <= (1-1/2^31)m + x(m-1)/2^31 */
    /* 0 <= newx <= m + 49146(2^14-1)/2^31 */
    /* 0 <= newx <= m + 0.4 */
    /* 0 <= newx <= m */

    x -= qpart*m; *q += qpart;
    /* x <= m */

    x -= m; *q += 1;
    mask = -(x>>31);
    x += mask&(uint32)m; *q += mask;
    /* x < m */

    *r = x;
}

uint32 uint32_div_uint14(uint32 x,uint16 m)
{
    uint32 q;
    uint16 r;
    uint32_divmod_uint14(&q,&r,x,m);
    return q;
}

uint16 uint32_mod_uint14(uint32 x,uint16 m)
{
    uint32 q;
    uint16 r;
    uint32_divmod_uint14(&q,&r,x,m);
    return r;
}

/* from supercop/crypto_kem/sntrup761/ref/int32.c */

void int32_divmod_uint14(int32 *q,uint16 *r,int32 x,uint16 m)
{
    uint32 uq,uq2;
    uint16 ur,ur2;
    uint32 mask;

    uint32_divmod_uint14(&uq,&ur,0x80000000+(uint32)x,m);
    uint32_divmod_uint14(&uq2,&ur2,0x80000000,m);
    ur -= ur2; uq -= uq2;
    mask = -(uint32)(ur>>15);
    ur += mask&m; uq += mask;
    *r = ur; *q = uq;
}

int32 int32_div_uint14(int32 x,uint16 m)
{
    int32 q;
    uint16 r;
    int32_divmod_uint14(&q,&r,x,m);
    return q;
}

uint16 int32_mod_uint14(int32 x,uint16 m)
{
    int32 q;
    uint16 r;
    int32_divmod_uint14(&q,&r,x,m);
    return r;
}

int crypto_hash_sha512(unsigned char *out,const unsigned char *in,unsigned long long inlen) {
    auto hash = Botan::HashFunction::create("SHA-384");
    hash->update(in, inlen);
    hash->final(out);
    return 0;
}
