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

#define NUM_SAMPLES         500000
#define WARMUP_SAMPLES      10000
#define OUTLIER_THRESHOLD   50000
#define MIN_CYCLES          500

#define FILE_VULNERABLE     "vulnerable_timing.csv"
#define FILE_CONSTANT_TIME  "constant_time_timing.csv"

/* xorshift64 PRNG — deterministički, bez system call overhead */
static uint64_t prng_state;

static inline void prng_seed(uint64_t seed) {
    prng_state = seed ? seed : 0xDEADBEEFCAFEBABEULL;
}

static inline uint64_t prng_next(void) {
    uint64_t x = prng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return (prng_state = x);
}

/* pinuj proces na zadani CPU core */
static void pin_to_p_core(int cpu_num) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_num, &cpuset);

    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        fprintf(stderr, "[UPOZORENJE] Nije moguće pinirati na CPU %d\n", cpu_num);
        fprintf(stderr, "             Pokreni sa: taskset -c %d ./experiment\n", cpu_num);
    } else {
        printf("[OK] Prikovano na CPU %d (P-core)\n", cpu_num);
    }
}

static void set_high_priority(void) {
    if (setpriority(PRIO_PROCESS, 0, -20) != 0) {
        fprintf(stderr, "[INFO] Nije moguće postaviti visok prioritet (potreban root)\n");
    } else {
        printf("[OK] Visok prioritet procesa postavljen (nice=-20)\n");
    }
}

/* izmjeri TSC frekvenciju upoređujući s wall clock-om */
static void check_tsc(void) {
    struct timespec ts_start, ts_end;
    uint64_t tsc_s, tsc_e;

    tsc_s = tsc_start();
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    struct timespec sleep_time = {0, 100000000L};
    nanosleep(&sleep_time, NULL);

    tsc_e = tsc_end();
    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    uint64_t tsc_diff = tsc_e - tsc_s;
    double wall_ns = (ts_end.tv_sec - ts_start.tv_sec) * 1e9 +
                     (ts_end.tv_nsec - ts_start.tv_nsec);
    double tsc_freq_ghz = (double)tsc_diff / wall_ns;

    printf("[OK] Procjenjena TSC frekvencija: %.3f GHz\n", tsc_freq_ghz);
}

static inline uint64_t measure_vulnerable(uint64_t base, uint64_t exp, uint64_t mod) {
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

static inline uint64_t measure_constant_time(uint64_t base, uint64_t exp, uint64_t mod) {
    volatile uint64_t result;
    uint32_t cpu_id;

    COMPILER_BARRIER();
    uint64_t t_start = tsc_start();
    COMPILER_BARRIER();
    result = mod_exp_constant_time(base, exp, mod, EXP_BITS);
    COMPILER_BARRIER();
    uint64_t t_end = tsc_end_with_cpu(&cpu_id);
    COMPILER_BARRIER();

    DO_NOT_OPTIMIZE(result);
    if (cpu_id != 0) return 0;
    return t_end - t_start;
}

typedef uint64_t (*measure_fn_t)(uint64_t, uint64_t, uint64_t);

/* paired design: exp_0 i exp_1 dijele iste bite osim TARGET_BIT */
static void run_experiment(
    const char     *filename,
    measure_fn_t    measure_fn,
    const char     *label
) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "[GREŠKA] Nije moguće otvoriti: %s\n", filename);
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    fprintf(fp, "iteration,cycles,bit_position,bit_value\n");

    const uint64_t base = RSA_BASE % RSA_MODULUS;
    const uint64_t mod  = RSA_MODULUS;

    printf("[%s] Zagrijavanje cache-a (%d iteracija)...\n", label, WARMUP_SAMPLES);
    fflush(stdout);

    for (int i = 0; i < WARMUP_SAMPLES; i++) {
        uint64_t warm_exp = prng_next();
        volatile uint64_t dummy = measure_fn(base, warm_exp, mod);
        (void)dummy;
    }

    printf("[%s] Prikupljanje %d parova mjerenja...\n", label, NUM_SAMPLES);
    fflush(stdout);

    int valid_count   = 0;
    int skipped_count = 0;

    for (int iter = 0; iter < NUM_SAMPLES; iter++) {
        uint64_t base_exp = prng_next();

        uint64_t exp_0 = base_exp & ~(1ULL << TARGET_BIT);
        uint64_t exp_1 = base_exp |  (1ULL << TARGET_BIT);

        /* nasumični redosljed smanjuje sistematski bias */
        uint64_t do_swap = prng_next() & 1;
        if (do_swap) {
            uint64_t tmp = exp_0;
            exp_0 = exp_1;
            exp_1 = tmp;
        }

        uint64_t cycles_A = measure_fn(base, exp_0, mod);
        uint64_t cycles_B = measure_fn(base, exp_1, mod);

        uint64_t cycles_0 = do_swap ? cycles_B : cycles_A;
        uint64_t cycles_1 = do_swap ? cycles_A : cycles_B;

        /* odbaci mjerenja van razumnog opsega (context switch, overflow) */
        if (cycles_0 < MIN_CYCLES || cycles_0 > OUTLIER_THRESHOLD ||
            cycles_1 < MIN_CYCLES || cycles_1 > OUTLIER_THRESHOLD) {
            skipped_count++;
            continue;
        }

        fprintf(fp, "%d,%" PRIu64 ",%d,0\n", iter, cycles_0, TARGET_BIT);
        fprintf(fp, "%d,%" PRIu64 ",%d,1\n", iter, cycles_1, TARGET_BIT);
        valid_count++;

        if ((iter + 1) % 10000 == 0) {
            printf("[%s]   %d/%d (preskočeno: %d)\r",
                   label, iter + 1, NUM_SAMPLES, skipped_count);
            fflush(stdout);
        }
    }

    printf("[%s]   %d/%d završeno (preskočeno: %d)          \n",
           label, NUM_SAMPLES, NUM_SAMPLES, skipped_count);

    fclose(fp);

    printf("[%s] Sačuvano %d validnih parova u: %s\n\n",
           label, valid_count, filename);
}

int main(int argc, char *argv[]) {
    printf("================================================================\n");
    printf("  RSA Timing Side-Channel Eksperiment\n");
    printf("  Modulus: %" PRIu64 " (2^61 - 1, Mersenne prost)\n", (uint64_t)RSA_MODULUS);
    printf("  Baza:    %" PRIu64 "\n", (uint64_t)RSA_BASE);
    printf("  Bita eksponenta: %d\n", EXP_BITS);
    printf("  Ciljani bit:     %d\n", TARGET_BIT);
    printf("  Uzoraka:         %d parova po implementaciji\n", NUM_SAMPLES);
    printf("================================================================\n\n");

    pin_to_p_core(0);
    set_high_priority();
    check_tsc();
    printf("\n");

    uint64_t initial_seed;
    if (argc > 1) {
        initial_seed = strtoull(argv[1], NULL, 0);
        printf("[OK] PRNG seed (from CLI): 0x%" PRIX64 "\n", initial_seed);
    } else {
        initial_seed = 0xABCDEF1234567890ULL ^ (uint64_t)time(NULL);
        printf("[OK] PRNG seed (time-based): 0x%" PRIX64 "\n", initial_seed);
        printf("     (pass seed as argument to reproduce: ./experiment 0x%" PRIX64 ")\n", initial_seed);
    }
    prng_seed(initial_seed);

    printf("--- RANJIVA IMPLEMENTACIJA ---\n");
    run_experiment(FILE_VULNERABLE, measure_vulnerable, "VULNERABLE");

    prng_seed(initial_seed + 1ULL);

    printf("--- CONSTANT-TIME IMPLEMENTACIJA ---\n");
    run_experiment(FILE_CONSTANT_TIME, measure_constant_time, "CONSTANT-TIME");

    printf("================================================================\n");
    printf("  Eksperiment završen!\n");
    printf("  Fajlovi: %s, %s\n", FILE_VULNERABLE, FILE_CONSTANT_TIME);
    printf("\n  Pokreni analizu:\n");
    printf("    python3 analysis.py\n");
    printf("================================================================\n");

    {
        FILE *jf = fopen("experiment_meta.json", "w");
        if (jf) {
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char ts[32];
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);
            fprintf(jf,
                "{\n"
                "  \"timestamp\": \"%s\",\n"
                "  \"num_samples\": %d,\n"
                "  \"warmup_samples\": %d,\n"
                "  \"exp_bits\": %d,\n"
                "  \"target_bit\": %d,\n"
                "  \"rsa_modulus\": \"%" PRIu64 "\",\n"
                "  \"rsa_base\": \"%" PRIu64 "\",\n"
                "  \"outlier_threshold\": %d,\n"
                "  \"min_cycles\": %d,\n"
                "  \"prng_seed\": \"0x%016" PRIX64 "\"\n"
                "}\n",
                ts,
                NUM_SAMPLES, WARMUP_SAMPLES,
                EXP_BITS, TARGET_BIT,
                (uint64_t)RSA_MODULUS, (uint64_t)RSA_BASE,
                OUTLIER_THRESHOLD, MIN_CYCLES,
                initial_seed
            );
            fclose(jf);
            printf("  Metapodaci: experiment_meta.json\n");
        }
    }

    return EXIT_SUCCESS;
}
