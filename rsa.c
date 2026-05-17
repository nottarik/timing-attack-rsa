#include "rsa.h"

/* square-and-multiply sa grananjem — bit=1 izvršava extra mulmod */
__attribute__((noinline))
__attribute__((optimize("O0")))
uint64_t mod_exp_vulnerable(uint64_t base, uint64_t exp, uint64_t mod, int num_bits) {
    uint64_t result = 1ULL;
    base = base % mod;

    for (int i = num_bits - 1; i >= 0; i--) {
        result = mulmod(result, result, mod);
        if ((exp >> i) & 1) {
            result = mulmod(result, base, mod);  /* samo za bit=1 → timing leak */
        }
    }

    return result;
}

/* constant-time: uvijek radi oba mulmod, ct_select bira rezultat bez grananja */
__attribute__((noinline))
uint64_t mod_exp_constant_time(uint64_t base, uint64_t exp, uint64_t mod, int num_bits) {
    uint64_t result = 1ULL;
    base = base % mod;

    for (int i = num_bits - 1; i >= 0; i--) {
        uint64_t bit = (exp >> i) & 1;
        result = mulmod(result, result, mod);
        uint64_t mul_result = mulmod(result, base, mod);
        result = ct_select(bit, mul_result, result);
    }

    return result;
}

/* Montgomery ladder: constant-time kroz simetrično ažuriranje R0/R1 */
__attribute__((noinline))
uint64_t mod_exp_montgomery_ladder(uint64_t base, uint64_t exp, uint64_t mod, int num_bits) {
    uint64_t R0 = 1ULL;
    uint64_t R1 = base % mod;

    for (int i = num_bits - 1; i >= 0; i--) {
        uint64_t bit = (exp >> i) & 1;
        uint64_t prod = mulmod(R0, R1, mod);
        uint64_t sq0  = mulmod(R0, R0, mod);
        uint64_t sq1  = mulmod(R1, R1, mod);
        R0 = ct_select(bit, prod, sq0);
        R1 = ct_select(bit, sq1,  prod);
    }

    return R0;
}

/* modularni inverz proširenim euklidskim algoritmom; vraća 0 ako gcd(a,m) != 1 */
uint64_t modinv(uint64_t a, uint64_t m) {
    if (m == 0) return 0;
    int64_t old_r = (int64_t)a, r = (int64_t)m;
    int64_t old_s = 1, s = 0;
    while (r != 0) {
        int64_t q = old_r / r;
        int64_t tmp;
        tmp = r;   r   = old_r - q * r;   old_r = tmp;
        tmp = s;   s   = old_s - q * s;   old_s = tmp;
    }
    if (old_r != 1) return 0;
    return (uint64_t)((old_s % (int64_t)m + (int64_t)m) % (int64_t)m);
}

/* RSA blinding: randomizuje bazu (m' = m*r mod n) prije modexp */
__attribute__((noinline))
uint64_t mod_exp_blinded(uint64_t base, uint64_t exp, uint64_t mod, int num_bits,
                         uint64_t *prng_state_ptr) {
    uint64_t x = *prng_state_ptr;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *prng_state_ptr = x;
    uint64_t r = (x % (mod - 2)) + 2;

    uint64_t blinded_base = mulmod(base % mod, r, mod);
    uint64_t s_prime      = mod_exp_vulnerable(blinded_base, exp, mod, num_bits);

    uint64_t r_inv = modinv(r, mod);
    if (r_inv == 0) return s_prime;

    return mulmod(s_prime, r_inv, mod);
}
