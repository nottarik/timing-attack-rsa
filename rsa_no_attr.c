/* rsa_no_attr.c — mod_exp bez __attribute__((optimize("O0"))), kompajlira se s globalnim CFLAGS */

#include "rsa.h"

__attribute__((noinline))
uint64_t mod_exp_vulnerable(uint64_t base, uint64_t exp, uint64_t mod, int num_bits) {
    uint64_t result = 1ULL;
    base = base % mod;

    for (int i = num_bits - 1; i >= 0; i--) {
        result = mulmod(result, result, mod);
        if ((exp >> i) & 1) {
            result = mulmod(result, base, mod);
        }
    }

    return result;
}

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
