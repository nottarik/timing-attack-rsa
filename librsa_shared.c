/* librsa_shared.c — dijeljeni shared library za Flush+Reload demo */

#include "rsa.h"
#include <stdint.h>

/* rsa_multiply_step je na zasebnoj cache liniji; attacker cilja ovu adresu */
uint64_t __attribute__((noinline, aligned(64)))
rsa_multiply_step(uint64_t result, uint64_t base, uint64_t mod) {
    return mulmod(result, base, mod);
}

/* ranjivi modexp koji poziva rsa_multiply_step samo za bit=1 */
uint64_t __attribute__((noinline))
rsa_decrypt_shared(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1ULL;
    base = base % mod;

    for (int i = EXP_BITS - 1; i >= 0; i--) {
        result = mulmod(result, result, mod);
        if ((exp >> i) & 1) {
            result = rsa_multiply_step(result, base, mod);
        }
    }

    return result;
}
