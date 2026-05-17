/* key_reconstruct_blind.c — slijepa rekonstrukcija RSA ključa kroz oracle interfejs */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <sched.h>
#include <sys/resource.h>
#include <inttypes.h>

#include "rsa.h"
#include "oracle_blind.h"

#define K_SAMPLES        5000
#define K_SAMPLES_RETRY  (K_SAMPLES * 2)
#define T_WEAK           2.5
#define WARMUP           5000
#define OUTLIER_MIN      1000ULL
#define MAX_PAIR_DIFF    1000ULL
#define TRIM_PCT         5
#define SCRAMBLER_COUNT  3
#define NUM_KEY_BITS     64
#define OUTPUT_FILE      "key_reconstruction_blind.csv"

static uint64_t g_outlier_max = 9000ULL;

/* napadački PRNG — ne zna ništa o tajnom ključu */
static uint64_t prng_state;

static inline void prng_seed(uint64_t s) {
    prng_state = s ? s : 0xCAFEBABEULL;
}

static inline uint64_t prng_next(void) {
    uint64_t x = prng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return (prng_state = x);
}

static inline uint64_t random_base(void) {
    return (prng_next() % (RSA_MODULUS - 2)) + 2;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

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

static void setup_cpu(void) {
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(0, &cs);
    if (sched_setaffinity(0, sizeof(cs), &cs) == 0)
        printf("[OK] Prikovano na CPU 0 (P-core)\n");
    else
        fprintf(stderr, "[UPOZORENJE] CPU pinning nije uspio\n");

    if (setpriority(PRIO_PROCESS, 0, -20) == 0)
        printf("[OK] Visok prioritet procesa (nice=-20)\n");
    else
        fprintf(stderr, "[INFO] Nije moguće postaviti visok prioritet (potreban root)\n");
}

/* dinamički outlier prag iz N baseline mjerenja oracle-a */
static uint64_t calibrate_outlier_threshold(void) {
    const int CAL_N = 1000;
    uint64_t *samples = (uint64_t *)malloc(sizeof(uint64_t) * CAL_N);
    if (!samples) return 9000ULL;

    for (int i = 0; i < CAL_N; i++) {
        uint64_t b = random_base();
        samples[i] = oracle_secret_time(b);
        if (samples[i] == 0) samples[i] = 9000ULL;
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
    printf("[CAL] Dinamički outlier prag: %llu ciklusa (median+5×IQR)\n\n",
           (unsigned long long)thresh);

    free(samples);
    return thresh;
}

/* prikuplja uparena mjerenja kroz oracle interfejs
 * t_stat > 0 → bit=1 (tajni sporiji), t_stat < 0 → bit=0 */
static void collect_blind(
    int      bit_pos,
    uint64_t xor_mask,
    int      n_target,
    double  *out_mean_secret,
    double  *out_mean_perturbed,
    double  *out_tstat,
    int     *out_pairs_used,
    int     *out_pairs_skipped)
{
    uint64_t *ts_arr  = (uint64_t *)malloc(sizeof(uint64_t) * n_target);
    uint64_t *tp_arr  = (uint64_t *)malloc(sizeof(uint64_t) * n_target);
    int64_t  *deltas  = (int64_t  *)malloc(sizeof(int64_t)  * n_target);
    int n = 0, skipped = 0;
    int max_iters = n_target * 20;

    for (int iter = 0; iter < max_iters && n < n_target; iter++) {

        /* scrambler resetuje branch predictor */
        for (int s = 0; s < SCRAMBLER_COUNT; s++) {
            oracle_scramble(random_base(), prng_next());
        }

        uint64_t base = random_base();
        int swap = (int)(prng_next() & 1);

        uint64_t ta, tb;
        if (swap) {
            ta = oracle_perturbed_time(base, xor_mask);
            tb = oracle_secret_time(base);
        } else {
            ta = oracle_secret_time(base);
            tb = oracle_perturbed_time(base, xor_mask);
        }

        uint64_t t_s = swap ? tb : ta;
        uint64_t t_p = swap ? ta : tb;

        if (t_s == 0 || t_p == 0 ||
            t_s < OUTLIER_MIN || t_s > g_outlier_max ||
            t_p < OUTLIER_MIN || t_p > g_outlier_max) {
            skipped++;
            continue;
        }

        /* par-level filter: context switch koji je pogodio samo jedno mjerenje */
        uint64_t pair_diff = (t_s > t_p) ? (t_s - t_p) : (t_p - t_s);
        if (pair_diff > MAX_PAIR_DIFF) {
            skipped++;
            continue;
        }

        ts_arr[n] = t_s;
        tp_arr[n] = t_p;
        deltas[n] = (int64_t)t_s - (int64_t)t_p;
        n++;
    }

    if (n < n_target)
        fprintf(stderr,
                "[WARN] Bit %d: max iteracija dostignut, sakupljeno %d/%d parova\n",
                bit_pos, n, n_target);

    *out_pairs_used    = n;
    *out_pairs_skipped = skipped;

    *out_mean_secret    = trimmed_mean(ts_arr, n, TRIM_PCT);
    *out_mean_perturbed = trimmed_mean(tp_arr, n, TRIM_PCT);

    /* paired-delta t-statistika (računata iz deltas[] prije sortiranja) */
    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += (double)deltas[i];
    double mean_d = (n > 0) ? sum / n : 0.0;

    double sum_sq = 0.0;
    for (int i = 0; i < n; i++) {
        double d = (double)deltas[i] - mean_d;
        sum_sq += d * d;
    }
    double std_d = (n > 1) ? sqrt(sum_sq / (n - 1)) : 1.0;
    *out_tstat = (n > 1 && std_d > 0.0)
                 ? mean_d / (std_d / sqrt((double)n))
                 : 0.0;

    free(ts_arr);
    free(tp_arr);
    free(deltas);
}

static void print_bits(uint64_t val, int nbits) {
    for (int i = nbits - 1; i >= 0; i--) {
        printf("%c", ((val >> i) & 1) ? '1' : '0');
        if (i > 0 && i % 4 == 0) printf(" ");
    }
}

int main(int argc, char *argv[]) {
    printf("================================================================\n");
    printf("  RSA Timing Side-Channel — Slijepa Rekonstrukcija Kljuca\n");
    printf("  Oracle model: chosen-perturbation (napadac ne vidi kljuc)\n");
    printf("  K=%d  Retry=%d  Scramblers=%d  PairDiffMax=%llu  T_weak=%.1f\n",
           K_SAMPLES, K_SAMPLES_RETRY, SCRAMBLER_COUNT,
           (unsigned long long)MAX_PAIR_DIFF, T_WEAK);
    printf("================================================================\n\n");

    setup_cpu();

    uint64_t prng_seed_val;
    if (argc > 1) {
        prng_seed_val = strtoull(argv[1], NULL, 0);
        printf("[OK] PRNG seed (napadac): 0x%016" PRIX64 "\n", prng_seed_val);
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        prng_seed_val = (uint64_t)ts.tv_nsec ^ ((uint64_t)ts.tv_sec << 20);
        printf("[OK] PRNG seed (napadac, time-based): 0x%016" PRIX64 "\n", prng_seed_val);
        printf("     (pokreni s: ./key_reconstruct_blind 0x%016" PRIX64 " za reprodukciju)\n",
               prng_seed_val);
    }
    prng_seed(prng_seed_val);

    /* oracle_init(0) generise nasumičan ključ iz /dev/urandom */
    oracle_init(0);

    printf("[INFO] Zagrijavanje napadacevog koda (%d iteracija)...\n", WARMUP);
    for (int i = 0; i < WARMUP; i++) {
        uint64_t b = random_base();
        volatile uint64_t d = oracle_secret_time(b);
        (void)d;
    }
    printf("[OK] Cache zagrijan\n\n");

    g_outlier_max = calibrate_outlier_threshold();

    FILE *fp = fopen(OUTPUT_FILE, "w");
    if (!fp) { perror("fopen"); return 1; }
    fprintf(fp, "bit_position,mean_secret,mean_perturbed,delta_cycles,"
                "t_stat,inferred_bit,actual_bit,correct,direction\n");

    uint64_t reconstructed_key = 0;
    int correct_bits  = 0;
    int total_skipped = 0;
    int total_retried = 0;

    printf("  Bit  mean(S)    mean(S^m)   Delta   t_stat  Skip  Status\n");
    printf("  ───  ─────────  ─────────  ──────  ──────  ────  ──────\n");

    for (int b = NUM_KEY_BITS - 1; b >= 0; b--) {
        uint64_t xor_mask = 1ULL << b;

        double ms, mp, tstat;
        int used, skipped;
        collect_blind(b, xor_mask, K_SAMPLES, &ms, &mp, &tstat, &used, &skipped);

        int retried = 0;
        if (fabs(tstat) < T_WEAK) {
            collect_blind(b, xor_mask, K_SAMPLES_RETRY,
                          &ms, &mp, &tstat, &used, &skipped);
            retried = 1;
            total_retried++;
        }

        total_skipped += skipped;

        double delta      = ms - mp;
        int inferred_bit  = (tstat > 0.0) ? 1 : 0;

        if (inferred_bit)
            reconstructed_key |= ((uint64_t)1 << b);

        printf("  %3d  %9.1f  %9.1f  %+6.1f  %+6.2f  %4d  %-6s%s\n",
               b, ms, mp, delta, tstat, skipped,
               "?",
               retried ? " [retry]" : "");

        fprintf(fp, "%d,%.2f,%.2f,%.2f,%.3f,%d,?,?,\"%s\"\n",
                b, ms, mp, delta, tstat, inferred_bit,
                (tstat > 0.0) ? "secret sporiji (bit=1)"
                              : "perturbed sporiji (bit=0)");
        fflush(fp);
        fflush(stdout);
    }

    /* validacija: tajni ključ se otkriva tek ovdje, nakon kompletne rekonstrukcije */
    uint64_t actual_secret = oracle_reveal_secret();

    correct_bits = 0;
    for (int b = 0; b < NUM_KEY_BITS; b++) {
        int r = (reconstructed_key >> b) & 1;
        int a = (actual_secret     >> b) & 1;
        if (r == a) correct_bits++;
    }

    fprintf(fp, "\n# Validacija\n");
    fprintf(fp, "# Tajni kljuc:    0x%016llX\n", (unsigned long long)actual_secret);
    fprintf(fp, "# Rekonstruisan:  0x%016llX\n", (unsigned long long)reconstructed_key);
    fprintf(fp, "# Tacni biti:     %d / %d\n", correct_bits, NUM_KEY_BITS);
    fclose(fp);

    printf("\n================================================================\n");
    printf("  REZULTAT SLIJEPE REKONSTRUKCIJE\n");
    printf("================================================================\n\n");
    printf("  Tajni kljuc:    0x%016llX\n", (unsigned long long)actual_secret);
    printf("  Rekonstruisan:  0x%016llX\n", (unsigned long long)reconstructed_key);
    printf("\n  Binarno (tajni):     "); print_bits(actual_secret,     NUM_KEY_BITS); printf("\n");
    printf("  Binarno (napadac):   "); print_bits(reconstructed_key,  NUM_KEY_BITS); printf("\n");
    printf("  Razlika (XOR):       ");
    print_bits(actual_secret ^ reconstructed_key, NUM_KEY_BITS); printf("\n\n");
    printf("  Tacni biti:       %d / %d  (%.1f%%)\n",
           correct_bits, NUM_KEY_BITS,
           100.0 * correct_bits / NUM_KEY_BITS);
    printf("  Ukupno skipovano: %d parova\n", total_skipped);
    printf("  Retried bita:     %d  (|t| < %.1f pri prvom prolazu)\n\n",
           total_retried, T_WEAK);

    if (reconstructed_key == actual_secret) {
        printf("  NAPAD POTPUNO USJESAN — Slijepa rekonstrukcija 100%% tacna!\n");
    } else {
        int wrong = NUM_KEY_BITS - correct_bits;
        printf("  %d gresnih bita. Probaj:\n", wrong);
        printf("    - Povecaj K_SAMPLES\n");
        printf("    - Smanji MAX_PAIR_DIFF\n");
        printf("    - Pokreni na mirnijoj masini\n");
    }

    printf("\n  Izlazni fajl: %s\n", OUTPUT_FILE);
    printf("================================================================\n");

    {
        FILE *jf = fopen("key_reconstruction_blind_meta.json", "w");
        if (jf) {
            time_t now = time(NULL);
            struct tm *ti = localtime(&now);
            char ts[32];
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", ti);
            fprintf(jf,
                "{\n"
                "  \"timestamp\": \"%s\",\n"
                "  \"mode\": \"blind\",\n"
                "  \"secret_key\": \"0x%016llX\",\n"
                "  \"reconstructed_key\": \"0x%016llX\",\n"
                "  \"correct_bits\": %d,\n"
                "  \"total_bits\": %d,\n"
                "  \"k_samples\": %d,\n"
                "  \"k_retry\": %d,\n"
                "  \"total_skipped\": %d,\n"
                "  \"total_retried\": %d,\n"
                "  \"prng_seed\": \"0x%016llX\"\n"
                "}\n",
                ts,
                (unsigned long long)actual_secret,
                (unsigned long long)reconstructed_key,
                correct_bits, NUM_KEY_BITS,
                K_SAMPLES, K_SAMPLES_RETRY,
                total_skipped, total_retried,
                prng_seed_val
            );
            fclose(jf);
        }
    }

    return (reconstructed_key == actual_secret) ? 0 : 2;
}
