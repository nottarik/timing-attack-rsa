/* multi_bit_sweep.c — mjeri timing leak za sve bit pozicije eksponenta */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include <sys/resource.h>
#include <inttypes.h>
#include <math.h>

#include "timing.h"
#include "rsa.h"

#define SAMPLES_PER_BIT    10000
#define WARMUP_SAMPLES     5000
#define OUTLIER_THRESHOLD  50000
#define MIN_CYCLES         500
#define OUTPUT_FILE        "multi_bit_sweep.csv"
#define META_FILE          "multi_bit_sweep_meta.json"

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
        fprintf(stderr, "[WARN] CPU pinning failed — use taskset -c 0\n");
    else
        printf("[OK] Pinned to CPU %d\n", cpu);
}

static inline uint64_t measure_one(uint64_t base, uint64_t exp) {
    volatile uint64_t result;
    uint32_t cpu_id;
    COMPILER_BARRIER();
    uint64_t t_start = tsc_start();
    COMPILER_BARRIER();
    result = mod_exp_vulnerable(base, exp, RSA_MODULUS, EXP_BITS);
    COMPILER_BARRIER();
    uint64_t t_end = tsc_end_with_cpu(&cpu_id);
    COMPILER_BARRIER();
    DO_NOT_OPTIMIZE(result);
    if (cpu_id != 0) return 0;
    return t_end - t_start;
}

int main(int argc, char *argv[]) {
    printf("================================================================\n");
    printf("  RSA Timing Side-Channel — Multi-Bit Sweep\n");
    printf("  Bit pozicije: 0-%d  |  Uzoraka po bitu: %d\n",
           EXP_BITS - 1, SAMPLES_PER_BIT);
    printf("================================================================\n\n");

    pin_to_core(0);
    if (setpriority(PRIO_PROCESS, 0, -20) == 0)
        printf("[OK] High process priority\n");

    uint64_t seed;
    if (argc > 1) {
        seed = strtoull(argv[1], NULL, 0);
        printf("[OK] PRNG seed (from CLI): 0x%016" PRIX64 "\n", seed);
    } else {
        seed = 0xA5A5BEEF12345678ULL ^ (uint64_t)time(NULL);
        printf("[OK] PRNG seed (time-based): 0x%016" PRIX64 "\n", seed);
        printf("     (reproduce: ./multi_bit_sweep 0x%016" PRIX64 ")\n", seed);
    }
    prng_seed(seed);

    printf("[INFO] Zagrijavanje (%d iter)...\n", WARMUP_SAMPLES);
    for (int i = 0; i < WARMUP_SAMPLES; i++) {
        volatile uint64_t d = measure_one(
            (prng_next() % (RSA_MODULUS - 2)) + 2,
            prng_next()
        );
        (void)d;
    }
    printf("[OK] Cache warm\n\n");

    FILE *fp = fopen(OUTPUT_FILE, "w");
    if (!fp) { perror("fopen"); return 1; }
    fprintf(fp, "target_bit,iteration,cycles,bit_value\n");

    const uint64_t base = RSA_BASE % RSA_MODULUS;

    double delta_arr[64], tstat_arr[64], pval_arr[64];
    memset(delta_arr, 0, sizeof(delta_arr));
    memset(tstat_arr, 0, sizeof(tstat_arr));
    memset(pval_arr, 0, sizeof(pval_arr));

    for (int b = EXP_BITS - 1; b >= 0; b--) {
        double sum0 = 0, sum1 = 0, sq0 = 0, sq1 = 0;
        int n0 = 0, n1 = 0, skipped = 0;

        for (int iter = 0; iter < SAMPLES_PER_BIT; iter++) {
            uint64_t base_exp = prng_next();
            uint64_t exp_0 = base_exp & ~(1ULL << b);
            uint64_t exp_1 = base_exp |  (1ULL << b);

            /* nasumični redosljed smanjuje sistematski bias */
            uint64_t do_swap = prng_next() & 1;
            if (do_swap) { uint64_t t = exp_0; exp_0 = exp_1; exp_1 = t; }

            uint64_t c_A = measure_one(base, exp_0);
            uint64_t c_B = measure_one(base, exp_1);

            uint64_t c0 = do_swap ? c_B : c_A;
            uint64_t c1 = do_swap ? c_A : c_B;

            if (c0 < MIN_CYCLES || c0 > OUTLIER_THRESHOLD ||
                c1 < MIN_CYCLES || c1 > OUTLIER_THRESHOLD) {
                skipped++;
                continue;
            }

            fprintf(fp, "%d,%d,%" PRIu64 ",0\n", b, iter, c0);
            fprintf(fp, "%d,%d,%" PRIu64 ",1\n", b, iter, c1);

            sum0 += c0; sq0 += (double)c0 * c0; n0++;
            sum1 += c1; sq1 += (double)c1 * c1; n1++;
        }

        double m0 = (n0 > 0) ? sum0 / n0 : 0;
        double m1 = (n1 > 0) ? sum1 / n1 : 0;
        double v0 = (n0 > 1) ? (sq0 / n0 - m0*m0) * n0 / (n0-1) : 0;
        double v1 = (n1 > 1) ? (sq1 / n1 - m1*m1) * n1 / (n1-1) : 0;

        /* Welch-ova t-statistika */
        double se = sqrt(v0/n0 + v1/n1);
        double t = (se > 0) ? (m1 - m0) / se : 0;
        double delta = m1 - m0;

        /* aproksimacija p-vrijednosti: p ≈ 2*(1-Φ(|t|)) za veliki N */
        double at = fabs(t);
        double p_approx;
        if (at > 10.0) {
            p_approx = 1e-20;
        } else {
            double z = at / sqrt(2.0);
            double t2 = 1.0 / (1.0 + 0.3275911 * z);
            double poly = t2 * (0.254829592 +
                          t2 * (-0.284496736 +
                          t2 * (1.421413741 +
                          t2 * (-1.453152027 +
                          t2 * 1.061405429))));
            p_approx = poly * exp(-z * z);
            if (p_approx < 1e-20) p_approx = 1e-20;
            if (p_approx > 1.0) p_approx = 1.0;
        }

        delta_arr[b] = delta;
        tstat_arr[b] = t;
        pval_arr[b]  = p_approx;

        printf("  bit %2d: n=%5d  Δmean=%+7.1f  t=%7.2f  p≈%.2e  skip=%d\n",
               b, n0, delta, t, p_approx, skipped);
        fflush(stdout);
    }

    fclose(fp);

    printf("\n================================================================\n");
    printf("  SAŽETAK: Delta po bit poziciji\n");
    printf("================================================================\n");
    int sig_count = 0;
    for (int b = 0; b < EXP_BITS; b++) {
        if (pval_arr[b] < 0.05) sig_count++;
    }
    printf("  Statistički značajnih bit pozicija (p<0.05): %d / %d\n",
           sig_count, EXP_BITS);
    printf("  Izlazni fajl: %s\n", OUTPUT_FILE);

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
                "  \"samples_per_bit\": %d,\n"
                "  \"exp_bits\": %d,\n"
                "  \"outlier_threshold\": %d,\n"
                "  \"min_cycles\": %d,\n"
                "  \"prng_seed\": \"0x%016" PRIX64 "\",\n"
                "  \"significant_bits\": %d\n"
                "}\n",
                ts, SAMPLES_PER_BIT, EXP_BITS,
                OUTLIER_THRESHOLD, MIN_CYCLES,
                seed, sig_count
            );
            fclose(jf);
        }
    }

    return 0;
}
