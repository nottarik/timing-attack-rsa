/* victim_fr.c — simulira RSA server koji prima zahtjeve za dekriptovanje */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <inttypes.h>
#include "rsa.h"

#define VICTIM_SECRET_KEY  0xDEADBEEFCAFEBABEULL
#define VICTIM_ITERATIONS  5000000
/* 50us pauza između dekriptacija; active_fraction ≈ 9% */
#define VICTIM_SLEEP_NS    50000

extern uint64_t rsa_decrypt_shared(uint64_t base, uint64_t exp, uint64_t mod);

static uint64_t prng_state = 0xFEEDFACEULL;
static inline uint64_t prng_next(void) {
    uint64_t x = prng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return (prng_state = x);
}

int main(void) {
    printf("[VICTIM] RSA decryption server started (PID=%d)\n", (int)getpid());
    printf("[VICTIM] Secret key: 0x%016" PRIX64 "\n", (uint64_t)VICTIM_SECRET_KEY);
    printf("[VICTIM] Processing %d requests...\n", VICTIM_ITERATIONS);
    fflush(stdout);

    /* CPU 2 je HT par drugog fizičkog P-core-a — odvojen L1/L2 od attackera na CPU 0 */
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(2, &cs);
    if (sched_setaffinity(0, sizeof(cs), &cs) == 0)
        printf("[VICTIM] Pinned to CPU 2\n");
    fflush(stdout);

    for (int i = 0; i < VICTIM_ITERATIONS; i++) {
        uint64_t ciphertext = (prng_next() % (RSA_MODULUS - 2)) + 2;
        volatile uint64_t plaintext = rsa_decrypt_shared(
            ciphertext, VICTIM_SECRET_KEY, RSA_MODULUS
        );
        (void)plaintext;

        struct timespec sleep_req = {0, VICTIM_SLEEP_NS};
        nanosleep(&sleep_req, NULL);

        if ((i + 1) % 100000 == 0) {
            printf("[VICTIM] Processed %d requests\n", i + 1);
            fflush(stdout);
        }
    }

    printf("[VICTIM] Done. Processed %d requests.\n", VICTIM_ITERATIONS);
    return 0;
}
