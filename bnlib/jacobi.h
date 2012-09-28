/*
 * For a small (usually prime, but not necessarily) prime p,
 * Return Jacobi(p,bn), which is -1, 0 or +1.
 * bn must be odd.
 */
struct BigNum;
int bnJacobiQ(unsigned p, struct BigNum const *bn);
