/* oracle_blind.c — enkapsulira tajni ključ; napadački kod ga ne može pročitati */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>

#include "timing.h"
#include "rsa.h"
#include "oracle_blind.h"

/* static garantuje nevidljivost izvan ovog translation unit-a */
static uint64_t g_secret_key = 0;

static uint64_t generate_random_key(void) {
    uint64_t key = 0;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, &key, sizeof(key));
        close(fd);
        if (n == (ssize_t)sizeof(key) && key != 0)
            return key;
    }

    /* fallback ako /dev/urandom nije dostupan */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    key = (uint64_t)ts.tv_nsec
          ^ ((uint64_t)ts.tv_sec  << 32)
          ^ 0xC0FFEE1337DEADULL
          ^ (uint64_t)(uintptr_t)&key;

    return key ? key : 0xFACEB00CCAFEF00DULL;
}

void oracle_init(uint64_t key_override) {
    if (key_override != 0) {
        g_secret_key = key_override;
        printf("[ORACLE] Koristi se zadani ključ (key_override != 0).\n");
    } else {
        g_secret_key = generate_random_key();
        printf("[ORACLE] Tajni ključ generisan iz /dev/urandom.\n");
    }

    printf("[ORACLE] Zagrijavanje oracle-a (5000 iteracija)...\n");
    for (int i = 0; i < 5000; i++) {
        uint64_t wb = ((uint64_t)(i + 1) * 6364136223846793005ULL)
                      % (RSA_MODULUS - 2) + 2;
        volatile uint64_t r = mod_exp_vulnerable(wb, g_secret_key,
                                                  RSA_MODULUS, EXP_BITS);
        (void)r;
    }
    printf("[ORACLE] Spreman.\n\n");
}

/* vraća trajanje mod_exp s tajnim ključem */
uint64_t oracle_secret_time(uint64_t base) {
    volatile uint64_t result;
    uint32_t cpu_id;

    COMPILER_BARRIER();
    uint64_t ts = tsc_start();
    COMPILER_BARRIER();
    result = mod_exp_vulnerable(base, g_secret_key, RSA_MODULUS, EXP_BITS);
    COMPILER_BARRIER();
    uint64_t te = tsc_end_with_cpu(&cpu_id);
    COMPILER_BARRIER();
    DO_NOT_OPTIMIZE(result);

    if (cpu_id != 0) return 0;
    return te - ts;
}

/* vraća trajanje mod_exp s perturbiranim ključem (SECRET_KEY XOR xor_mask) */
uint64_t oracle_perturbed_time(uint64_t base, uint64_t xor_mask) {
    uint64_t perturbed = g_secret_key ^ xor_mask;

    volatile uint64_t result;
    uint32_t cpu_id;

    COMPILER_BARRIER();
    uint64_t ts = tsc_start();
    COMPILER_BARRIER();
    result = mod_exp_vulnerable(base, perturbed, RSA_MODULUS, EXP_BITS);
    COMPILER_BARRIER();
    uint64_t te = tsc_end_with_cpu(&cpu_id);
    COMPILER_BARRIER();
    DO_NOT_OPTIMIZE(result);

    if (cpu_id != 0) return 0;
    return te - ts;
}

/* resetuje branch predictor nasumičnim mod_exp-om; ne koristi g_secret_key */
void oracle_scramble(uint64_t rand_base, uint64_t rand_exp) {
    volatile uint64_t r = mod_exp_vulnerable(rand_base, rand_exp,
                                              RSA_MODULUS, EXP_BITS);
    (void)r;
}

/* otkriva tajni ključ za post-hoc validaciju — poziva se tek nakon rekonstrukcije */
uint64_t oracle_reveal_secret(void) {
    return g_secret_key;
}
