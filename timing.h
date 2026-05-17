/*
 * timing.h — Precizno mjerenje CPU ciklusa sa TSC
 * ================================================
 *
 * Intel i5-1335U (Raptor Lake) — TSC karakteristike:
 *
 * 1. INVARIJANTAN TSC (constant_tsc):
 *    TSC raste fiksnom frekvencijom bez obzira na C-state ili Turbo Boost.
 *    Na i5-1335U, TSC frekvencija = nominalna frekvencija CPU-a (npr. 2.5 GHz base).
 *    Dakle: TSC ciklusi != stvarni CPU ciklusi ako je Turbo aktivan!
 *    → Zato isključujemo Turbo Boost u setup.sh.
 *
 * 2. RDTSC vs RDTSCP:
 *    - RDTSC: čita TSC, ALI nema garantovanu serijalizaciju instrukcija.
 *             CPU može reordering-om izvršiti instrukcije UNUTAR mjernog prozora.
 *    - RDTSCP: čita TSC + IA32_TSC_AUX (processor ID), serijalizira prethodni kod.
 *              Garantuje da sve prethodne instrukcije završe PRIJE čitanja.
 *    - CPUID: potpuno serijalizirajuća instrukcija — niti jedna instrukcija
 *             ne može biti premještena ni prije ni poslije CPUID.
 *
 * 3. PREPORUČENI PATTERN (Intel White Paper "How to Benchmark Code Execution"):
 *
 *    START:   CPUID → RDTSC        (CPUID serijalizira pipeline PRIJE čitanja)
 *    END:     RDTSCP → CPUID       (RDTSCP čita TSC, CPUID sprječava premještanje
 *                                   kasnijih instrukcija ISPRED RDTSCP)
 *
 * 4. SCHEDULER MIGRACIJA (P-core vs E-core):
 *    Problem: Linux scheduler može migrirati proces sa CPU 0 (P-core) na
 *    CPU 8 (E-core) između mjerenja. P-core i E-core imaju RAZLIČITE TSC
 *    rate! (Oba su invarijantni, ali E-core može imati drugačiju nominalnu
 *    frekvenciju ili skalirajuće ponašanje.)
 *    Rješenje: taskset -c 0 ili sched_setaffinity() — pin na jedan core.
 *
 * 5. RDTSCP i processor ID:
 *    RDTSCP puni ECX registar sa procesorskim ID-om (IA32_TSC_AUX).
 *    Ovo možemo koristiti za detekciju migracija između mjerenja.
 */
 
#ifndef TIMING_H
#define TIMING_H
 
#include <stdint.h>
 
/*
 * tsc_start() — Čita TSC SA serijalizacijom na početku mjerenja.
 *
 * Sekvenca:
 *   CPUID   : serializuje — sve prethodne instrukce završe prije CPUID
 *   RDTSC   : čita TSC u EDX:EAX
 *
 * CPUID troši ~100-200 ciklusa, ali to je KONSTANTAN overhead koji se
 * pojavljuje i za bit=0 i za bit=1, dakle ne utiče na RAZLIKU.
 */
static inline uint64_t tsc_start(void) {
    uint32_t lo, hi;
    __asm__ __volatile__ (
        "CPUID\n\t"                /* Serijalizuj pipeline */
        "RDTSC\n\t"                /* Čitaj TSC → EDX:EAX */
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        : "=r"(hi), "=r"(lo)
        :: "%rax", "%rbx", "%rcx", "%rdx"  /* Clobber lista */
    );
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}
 
/*
 * tsc_end() — Čita TSC SA serijalizacijom na kraju mjerenja.
 *
 * Sekvenca:
 *   RDTSCP  : čita TSC + procesorski ID; serijalizuje prethodni kod
 *   CPUID   : sprječava premještanje KASNIJEG koda ispred RDTSCP
 *
 * RDTSCP je bolji od RDTSC za kraj mjerenja jer je sam po sebi
 * djelimično serijalizujući za prethodni kod.
 */
static inline uint64_t tsc_end(void) {
    uint32_t lo, hi;
    __asm__ __volatile__ (
        "RDTSCP\n\t"               /* Čitaj TSC (serijalizuje prethodni kod) */
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "CPUID\n\t"                /* Sprječava premještanje narednih instrukcija */
        : "=r"(hi), "=r"(lo)
        :: "%rax", "%rbx", "%rcx", "%rdx"
    );
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}
 
/*
 * tsc_end_with_cpu() — Kao tsc_end(), ali vraća i ID procesora.
 *
 * Koristi se za detekciju migracija između P-core i E-core:
 * Ako se cpu_id promijeni između dva mjerenja, bio je scheduler prekinuo proces.
 */
static inline uint64_t tsc_end_with_cpu(uint32_t *cpu_id) {
    uint32_t lo, hi, aux;
    __asm__ __volatile__ (
        "RDTSCP\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "mov %%ecx, %2\n\t"        /* ECX = IA32_TSC_AUX (processor ID) */
        "CPUID\n\t"
        : "=r"(hi), "=r"(lo), "=r"(aux)
        :: "%rax", "%rbx", "%rcx", "%rdx"
    );
    if (cpu_id) *cpu_id = aux;
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}
 
/*
 * COMPILER_BARRIER — Sprječava compiler da premješta instrukcije
 * oko mjernih tačaka. Ovo je RAZLIČITO od CPU memory barrier.
 * Compiler barijera ne generiše nikakve instrukcije — samo govori
 * compiler-u da sve varijable u memoriji treba tretirati kao
 * "potencijalno promijenjene" na toj tački.
 */
#define COMPILER_BARRIER() __asm__ __volatile__ ("" ::: "memory")
 
/*
 * DO_NOT_OPTIMIZE — Sprječava dead code elimination.
 * Bez ovoga, compiler može ukloniti cijeli poziv mod_exp ako
 * smatra da rezultat nikad nije korišten.
 */
#define DO_NOT_OPTIMIZE(x) __asm__ __volatile__ ("" : : "r,m"(x) : "memory")
 
#endif /* TIMING_H */
 
