/* key_reconstruct.c — rekonstrukcija RSA ključa iz timing mjerenja (chosen-input) */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <sched.h>
#include <sys/resource.h>
#include <inttypes.h>

#include "timing.h"
#include "rsa.h"

#define SECRET_KEY       0xDEADBEEFCAFEBABEULL
#define K_SAMPLES        5000
#define K_SAMPLES_RETRY  (K_SAMPLES * 2)
#define T_WEAK           2.5
#define WARMUP           5000
#define OUTLIER_MAX      9000ULL
#define OUTLIER_MIN      1000ULL
#define MAX_PAIR_DIFF    1000ULL
#define TRIM_PCT         5

static uint64_t g_outlier_max = OUTLIER_MAX;
static uint64_t g_cal_median = 0, g_cal_iqr = 0;
#define SCRAMBLER_COUNT  3
#define NUM_KEY_BITS     64
#define OUTPUT_FILE      "key_reconstruction.csv"

static uint64_t prng_state;
static inline void prng_seed(uint64_t s) { prng_state = s ? s : 0xCAFEBABEULL; }
static inline uint64_t prng_next(void) {
    uint64_t x = prng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return (prng_state = x);
}

static inline uint64_t measure_one(uint64_t base, uint64_t exp) {
    volatile uint64_t result;
    uint32_t cpu_id;
    COMPILER_BARRIER();
    uint64_t ts = tsc_start();
    COMPILER_BARRIER();
    result = mod_exp_vulnerable(base, exp, RSA_MODULUS, EXP_BITS);
    COMPILER_BARRIER();
    uint64_t te = tsc_end_with_cpu(&cpu_id);
    COMPILER_BARRIER();
    DO_NOT_OPTIMIZE(result);
    if (cpu_id != 0) return 0;
    return te - ts;
}

static void pin_to_core(int cpu) {
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(cpu, &cs);
    if (sched_setaffinity(0, sizeof(cs), &cs) == 0)
        printf("[OK] Prikovano na CPU %d\n", cpu);
    else
        fprintf(stderr, "[UPOZORENJE] CPU pinning nije uspio\n");
}

static void print_bits(uint64_t val, int nbits) {
    for (int i = nbits - 1; i >= 0; i--) {
        printf("%c", ((val >> i) & 1) ? '1' : '0');
        if (i > 0 && i % 4 == 0) printf(" ");
    }
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* odbaci donji i gornji trim_pct% uzoraka */
static double trimmed_mean(uint64_t *arr, int n, int trim_pct) {
    if (n <= 0) return 0.0;
    qsort(arr, n, sizeof(uint64_t), cmp_u64);
    int trim = n * trim_pct / 100;
    double sum = 0.0;
    int cnt = 0;
    for (int i = trim; i < n - trim; i++) {
        sum += (double)arr[i];
        cnt++;
    }
    return cnt > 0 ? sum / cnt : 0.0;
}

/* dinamički outlier prag: median + 5*IQR iz baseline mjerenja */
static uint64_t calibrate_outlier_threshold(void) {
    const int CAL_N = 1000;
    uint64_t *samples = (uint64_t *)malloc(sizeof(uint64_t) * CAL_N);
    if (!samples) return OUTLIER_MAX;

    for (int i = 0; i < CAL_N; i++) {
        uint64_t b = (prng_next() % (RSA_MODULUS - 2)) + 2;
        uint64_t e = prng_next();
        samples[i] = measure_one(b, e);
    }

    qsort(samples, CAL_N, sizeof(uint64_t), cmp_u64);
    uint64_t median = samples[CAL_N / 2];
    uint64_t q1     = samples[CAL_N / 4];
    uint64_t q3     = samples[3 * CAL_N / 4];
    uint64_t iqr    = (q3 > q1) ? (q3 - q1) : 0;
    uint64_t thresh = median + 5 * iqr;
    if (thresh < 5000) thresh = 5000;

    printf("[CAL] Kalibracija: median=%llu Q1=%llu Q3=%llu IQR=%llu\n",
           (unsigned long long)median, (unsigned long long)q1,
           (unsigned long long)q3,    (unsigned long long)iqr);
    printf("[CAL] Dinamički outlier threshold: %llu ciklusa (median+5*IQR)\n",
           (unsigned long long)thresh);

    g_cal_median = median;
    g_cal_iqr    = iqr;

    free(samples);
    return thresh;
}

/* prikuplja uparena mjerenja za zadani bit; koristi scrambler i paired-delta t-test */
static void collect_interleaved(int bit_pos, int n_target,
                                 double *out_mean_secret,
                                 double *out_mean_flipped,
                                 double *out_tstat,
                                 int *out_pairs_used,
                                 int *out_pairs_skipped)
{
    uint64_t exp_secret  = SECRET_KEY;
    uint64_t exp_flipped = SECRET_KEY ^ (1ULL << bit_pos);

    uint64_t *ts_arr = (uint64_t *)malloc(sizeof(uint64_t) * n_target);
    uint64_t *tf_arr = (uint64_t *)malloc(sizeof(uint64_t) * n_target);
    int64_t  *deltas = (int64_t  *)malloc(sizeof(int64_t)  * n_target);
    int n = 0, skipped = 0;
    int max_iters = n_target * 20;

    for (int iter = 0; iter < max_iters && n < n_target; iter++) {
        /* scrambler resetuje branch predictor */
        for (int s = 0; s < SCRAMBLER_COUNT; s++) {
            uint64_t re = prng_next();
            uint64_t rb = (prng_next() % (RSA_MODULUS - 2)) + 2;
            volatile uint64_t d = measure_one(rb, re); (void)d;
        }

        uint64_t base = (prng_next() % (RSA_MODULUS - 2)) + 2;
        int swap = (int)(prng_next() & 1);

        uint64_t t_a, t_b;
        if (swap) {
            t_a = measure_one(base, exp_flipped);
            t_b = measure_one(base, exp_secret);
        } else {
            t_a = measure_one(base, exp_secret);
            t_b = measure_one(base, exp_flipped);
        }

        uint64_t t_s = swap ? t_b : t_a;
        uint64_t t_f = swap ? t_a : t_b;

        if (t_s < OUTLIER_MIN || t_s > g_outlier_max ||
            t_f < OUTLIER_MIN || t_f > g_outlier_max) {
            skipped++;
            continue;
        }

        /* par-level filter: context switch koji je pogodio samo jedno mjerenje */
        uint64_t pair_diff = (t_s > t_f) ? (t_s - t_f) : (t_f - t_s);
        if (pair_diff > MAX_PAIR_DIFF) {
            skipped++;
            continue;
        }

        ts_arr[n] = t_s;
        tf_arr[n] = t_f;
        deltas[n] = (int64_t)t_s - (int64_t)t_f;
        n++;
    }

    if (n < n_target)
        fprintf(stderr, "[WARN] Bit %d: max iterations dostignut, sakupljeno %d/%d parova\n",
                bit_pos, n, n_target);

    *out_pairs_used    = n;
    *out_pairs_skipped = skipped;

    *out_mean_secret  = trimmed_mean(ts_arr, n, TRIM_PCT);
    *out_mean_flipped = trimmed_mean(tf_arr, n, TRIM_PCT);

    /* paired-delta t-statistika */
    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += (double)deltas[i];
    double mean_d = (n > 0) ? sum / n : 0.0;

    double sum_sq = 0.0;
    for (int i = 0; i < n; i++) {
        double d = (double)deltas[i] - mean_d;
        sum_sq += d * d;
    }
    double std_d = (n > 1) ? sqrt(sum_sq / (n - 1)) : 1.0;
    *out_tstat = (n > 1 && std_d > 0.0) ? mean_d / (std_d / sqrt((double)n)) : 0.0;

    free(ts_arr); free(tf_arr); free(deltas);
}

int main(int argc, char *argv[]) {
    printf("================================================================\n");
    printf("  RSA Timing Side-Channel — Rekonstrukcija Kljuca\n");
    printf("  Tajni kljuc: 0x%016llX\n", (unsigned long long)SECRET_KEY);
    printf("  Binarno:     ");
    print_bits(SECRET_KEY, NUM_KEY_BITS);
    printf("\n");
    printf("  K=%d  Retry=%d  Scramblers=%d  OutlierMax=%llu  PairDiffMax=%llu  T_weak=%.1f\n",
           K_SAMPLES, K_SAMPLES_RETRY, SCRAMBLER_COUNT,
           (unsigned long long)OUTLIER_MAX,
           (unsigned long long)MAX_PAIR_DIFF,
           T_WEAK);
    printf("================================================================\n\n");

    pin_to_core(0);
    if (setpriority(PRIO_PROCESS, 0, -20) == 0)
        printf("[OK] Visok prioritet\n");

    uint64_t seed;
    if (argc > 1) {
        seed = strtoull(argv[1], NULL, 0);
        printf("[OK] PRNG seed (from CLI): 0x%016" PRIX64 "\n", seed);
    } else {
        seed = 0xFACEB00CULL ^ (uint64_t)time(NULL);
        printf("[OK] PRNG seed (time-based): 0x%016" PRIX64 "\n", seed);
        printf("     (pass seed as argument to reproduce: ./key_reconstruct 0x%016" PRIX64 ")\n", seed);
    }
    prng_seed(seed);

    printf("[INFO] Zagrijavanje (%d iteracija)...\n", WARMUP);
    for (int i = 0; i < WARMUP; i++) {
        uint64_t b = (prng_next() % (RSA_MODULUS - 2)) + 2;
        uint64_t e = prng_next();
        volatile uint64_t d = measure_one(b, e); (void)d;
    }
    printf("[OK] Cache zagrijan\n\n");
    g_outlier_max = calibrate_outlier_threshold();

    FILE *fp = fopen(OUTPUT_FILE, "w");
    if (!fp) { perror("fopen"); return 1; }
    fprintf(fp, "bit_position,mean_original,mean_flipped,delta_cycles,"
                "t_stat,inferred_bit,actual_bit,correct,direction\n");

    uint64_t reconstructed_key = 0;
    int correct_bits   = 0;
    int total_skipped  = 0;
    int total_retried  = 0;

    printf("  Bit  mean(sec)  mean(flip)   Delta   t_stat  Skip  Status\n");
    printf("  ───  ─────────  ─────────  ──────  ──────  ────  ──────\n");

    for (int b = NUM_KEY_BITS - 1; b >= 0; b--) {
        double ms, mf, tstat;
        int used, skipped;
        collect_interleaved(b, K_SAMPLES, &ms, &mf, &tstat, &used, &skipped);

        /* adaptivni retry: slab signal → uzmi više uzoraka */
        int retried = 0;
        if (fabs(tstat) < T_WEAK) {
            collect_interleaved(b, K_SAMPLES_RETRY, &ms, &mf, &tstat, &used, &skipped);
            retried = 1;
            total_retried++;
        }

        total_skipped += skipped;

        double delta     = ms - mf;
        int inferred_bit = (tstat > 0.0) ? 1 : 0;
        int actual_bit   = (int)((SECRET_KEY >> b) & 1);
        int correct      = (inferred_bit == actual_bit);

        if (correct) correct_bits++;
        reconstructed_key |= ((uint64_t)inferred_bit << b);

        printf("  %3d  %9.1f  %9.1f  %+6.1f  %+6.2f  %4d  %s%s\n",
               b, ms, mf, delta, tstat, skipped,
               correct ? "OK" : "GREŠKA",
               retried ? " [retry]" : "");

        fprintf(fp, "%d,%.2f,%.2f,%.2f,%.3f,%d,%d,%d,\"%s\"\n",
                b, ms, mf, delta, tstat,
                inferred_bit, actual_bit, correct,
                (tstat > 0.0) ? "secret sporiji (bit=1)" : "flipped sporiji (bit=0)");
        fflush(fp); fflush(stdout);
    }
    fclose(fp);

    printf("\n================================================================\n");
    printf("  REZULTAT REKONSTRUKCIJE\n");
    printf("================================================================\n\n");
    printf("  Tajni kljuc:    0x%016llX\n", (unsigned long long)SECRET_KEY);
    printf("  Rekonstruisani: 0x%016llX\n", (unsigned long long)reconstructed_key);
    printf("\n  Binarno (tajni): "); print_bits(SECRET_KEY, NUM_KEY_BITS);        printf("\n");
    printf("  Binarno (napad): "); print_bits(reconstructed_key, NUM_KEY_BITS);   printf("\n");
    printf("  Razlika (XOR):   ");
    print_bits(SECRET_KEY ^ reconstructed_key, NUM_KEY_BITS); printf("\n\n");
    printf("  Tacni biti:       %d / %d  (%.1f%%)\n",
           correct_bits, NUM_KEY_BITS,
           (double)correct_bits / NUM_KEY_BITS * 100.0);
    printf("  Ukupno skipovano: %d parova\n", total_skipped);
    printf("  Retried bita:     %d  (|t| < %.1f pri prvom prolazu)\n\n",
           total_retried, T_WEAK);

    if (reconstructed_key == SECRET_KEY) {
        printf("  NAPAD POTPUNO USJESAN — Kljuc identican!\n");
    } else {
        int wrong = NUM_KEY_BITS - correct_bits;
        printf("  %d gresnih bita. Pokusaj:\n", wrong);
        printf("    - Povecaj K_SAMPLES\n");
        printf("    - Smanji MAX_PAIR_DIFF\n");
        printf("    - Pokreni na mirnijoj masini\n");
    }
    printf("\n  Vizualizacija: python3 key_reconstruct_analysis.py\n");
    printf("================================================================\n");

    {
        FILE *jf = fopen("key_reconstruction_meta.json", "w");
        if (jf) {
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char ts[32];
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);
            fprintf(jf,
                "{\n"
                "  \"timestamp\": \"%s\",\n"
                "  \"secret_key\": \"0x%016llX\",\n"
                "  \"k_samples\": %d,\n"
                "  \"num_bits\": %d,\n"
                "  \"outlier_max\": %llu,\n"
                "  \"outlier_min\": %llu,\n"
                "  \"max_pair_diff\": %llu,\n"
                "  \"trim_pct\": %d,\n"
                "  \"scrambler_count\": %d,\n"
                "  \"calibration_median\": %llu,\n"
                "  \"calibration_iqr\": %llu,\n"
                "  \"dynamic_threshold\": %llu,\n"
                "  \"correct_bits\": %d,\n"
                "  \"total_bits\": %d,\n"
                "  \"total_skipped\": %d\n"
                "}\n",
                ts,
                (unsigned long long)SECRET_KEY,
                K_SAMPLES, NUM_KEY_BITS,
                (unsigned long long)OUTLIER_MAX,
                (unsigned long long)OUTLIER_MIN,
                (unsigned long long)MAX_PAIR_DIFF,
                TRIM_PCT, SCRAMBLER_COUNT,
                (unsigned long long)g_cal_median,
                (unsigned long long)g_cal_iqr,
                (unsigned long long)g_outlier_max,
                correct_bits, NUM_KEY_BITS,
                total_skipped
            );
            fclose(jf);
            printf("  Metapodaci: key_reconstruction_meta.json\n");
        }
    }

    return (reconstructed_key == SECRET_KEY) ? 0 : 2;
}
