#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include <sys/resource.h>
#include <inttypes.h>

#include "timing.h"
#include "rsa.h"

#define NUM_SAMPLES         200000
#define WARMUP_SAMPLES      5000
#define OUTLIER_THRESHOLD   50000
#define MIN_CYCLES          500
#define OUTPUT_FILE         "blinded_timing.csv"
#define META_FILE           "blinded_meta.json"

static uint64_t prng_state;
static inline void prng_seed(uint64_t s) { prng_state = s ? s : 0xCAFEBABEULL; }
static inline uint64_t prng_next(void) {
    uint64_t x = prng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return (prng_state = x);
}

static void pin_to_core(int cpu) {
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(cpu, &cs);
    if (sched_setaffinity(0, sizeof(cs), &cs) != 0)
        fprintf(stderr, "[WARN] CPU pinning failed\n");
    else
        printf("[OK] Pinned to CPU %d\n", cpu);
}

static inline uint64_t measure_blinded(uint64_t base, uint64_t exp, uint64_t mod) {
    volatile uint64_t result;
    uint32_t cpu_id;
    COMPILER_BARRIER();
    uint64_t t_start = tsc_start();
    COMPILER_BARRIER();
    result = mod_exp_blinded(base, exp, mod, EXP_BITS, &prng_state);
    COMPILER_BARRIER();
    uint64_t t_end = tsc_end_with_cpu(&cpu_id);
    COMPILER_BARRIER();
    DO_NOT_OPTIMIZE(result);
    if (cpu_id != 0) return 0;
    return t_end - t_start;
}

static inline uint64_t measure_vulnerable_local(uint64_t base, uint64_t exp, uint64_t mod) {
    volatile uint64_t result;
    uint32_t cpu_id;
    COMPILER_BARRIER();
    uint64_t t_start = tsc_start();
    COMPILER_BARRIER();
    result = mod_exp_vulnerable(base, exp, mod, EXP_BITS);
    COMPILER_BARRIER();
    uint64_t t_end = tsc_end_with_cpu(&cpu_id);
    COMPILER_BARRIER();
    DO_NOT_OPTIMIZE(result);
    if (cpu_id != 0) return 0;
    return t_end - t_start;
}

static void run_timing(FILE *fp, int use_blinding, const char *label) {
    const uint64_t base = RSA_BASE % RSA_MODULUS;
    const uint64_t mod  = RSA_MODULUS;
    int valid = 0, skipped = 0;

    printf("[%s] Prikupljanje %d parova...\n", label, NUM_SAMPLES);

    for (int iter = 0; iter < NUM_SAMPLES; iter++) {
        uint64_t base_exp = prng_next();
        uint64_t exp_0 = base_exp & ~(1ULL << TARGET_BIT);
        uint64_t exp_1 = base_exp |  (1ULL << TARGET_BIT);

        uint64_t do_swap = prng_next() & 1;
        if (do_swap) { uint64_t t = exp_0; exp_0 = exp_1; exp_1 = t; }

        uint64_t c_A, c_B;
        if (use_blinding) {
            c_A = measure_blinded(base, exp_0, mod);
            c_B = measure_blinded(base, exp_1, mod);
        } else {
            c_A = measure_vulnerable_local(base, exp_0, mod);
            c_B = measure_vulnerable_local(base, exp_1, mod);
        }

        uint64_t c0 = do_swap ? c_B : c_A;
        uint64_t c1 = do_swap ? c_A : c_B;

        if (c0 < MIN_CYCLES || c0 > OUTLIER_THRESHOLD ||
            c1 < MIN_CYCLES || c1 > OUTLIER_THRESHOLD) {
            skipped++;
            continue;
        }

        fprintf(fp, "%d,%" PRIu64 ",%d,0\n", iter, c0, TARGET_BIT);
        fprintf(fp, "%d,%" PRIu64 ",%d,1\n", iter, c1, TARGET_BIT);
        valid++;

        if ((iter + 1) % 10000 == 0) {
            printf("[%s]   %d/%d (skip: %d)\r", label, iter+1, NUM_SAMPLES, skipped);
            fflush(stdout);
        }
    }
    printf("[%s]   Gotovo. Validni parovi: %d  Preskoceno: %d\n\n",
           label, valid, skipped);
}

int main(int argc, char *argv[]) {
    printf("================================================================\n");
    printf("  RSA Blinding Countermeasure Evaluation\n");
    printf("  Ciljani bit: %d  |  Uzoraka: %d\n", TARGET_BIT, NUM_SAMPLES);
    printf("================================================================\n\n");

    pin_to_core(0);
    if (setpriority(PRIO_PROCESS, 0, -20) == 0)
        printf("[OK] High priority\n");

    uint64_t seed;
    if (argc > 1) {
        seed = strtoull(argv[1], NULL, 0);
        printf("[OK] PRNG seed (CLI): 0x%016" PRIX64 "\n", seed);
    } else {
        seed = 0xB11D12340B1A1DULL ^ (uint64_t)time(NULL);
        printf("[OK] PRNG seed (time): 0x%016" PRIX64 "\n", seed);
    }
    prng_seed(seed);

    printf("[INFO] Zagrijavanje (%d iter)...\n", WARMUP_SAMPLES);
    for (int i = 0; i < WARMUP_SAMPLES; i++) {
        volatile uint64_t d = measure_blinded(RSA_BASE, prng_next(), RSA_MODULUS);
        (void)d;
    }
    printf("[OK] Cache warm\n\n");

    FILE *fp = fopen(OUTPUT_FILE, "w");
    if (!fp) { perror("fopen"); return 1; }
    fprintf(fp, "iteration,cycles,bit_position,bit_value\n");
    run_timing(fp, 1, "BLINDED");
    fclose(fp);

    /* kontrolna varijanta bez blindinga */
    FILE *fp2 = fopen("unblinded_timing.csv", "w");
    if (fp2) {
        fprintf(fp2, "iteration,cycles,bit_position,bit_value\n");
        prng_seed(seed + 1ULL);
        run_timing(fp2, 0, "UNBLINDED");
        fclose(fp2);
    }

    {
        FILE *jf = fopen(META_FILE, "w");
        if (jf) {
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char ts[32];
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);
            fprintf(jf,
                "{\n"
                "  \"timestamp\": \"%s\",\n"
                "  \"num_samples\": %d,\n"
                "  \"exp_bits\": %d,\n"
                "  \"target_bit\": %d,\n"
                "  \"prng_seed\": \"0x%016" PRIX64 "\"\n"
                "}\n",
                ts, NUM_SAMPLES, EXP_BITS, TARGET_BIT, seed
            );
            fclose(jf);
        }
    }

    printf("================================================================\n");
    printf("  Fajlovi: %s (blinded), unblinded_timing.csv (kontrola)\n", OUTPUT_FILE);
    printf("  Pokreni: python3 blinding_analysis.py\n");
    printf("================================================================\n");

    return 0;
}
