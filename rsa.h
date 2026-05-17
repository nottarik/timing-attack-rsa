/*
 * rsa.h — Deklaracije RSA modularnog eksponenciranja
 * ===================================================
 *
 * Implementiramo DEMO RSA operaciju: result = base^exp mod n
 *
 * Za ovaj eksperiment:
 *   n  = RSA_MODULUS = 2^61 - 1 (Mersenne prosti broj, garantovano prost)
 *   base = "poruka" ili "šifrat" (javno poznato)
 *   exp  = PRIVATNI EKSPONENT (tajna — eksponent čije bite pokušavamo otkriti)
 *
 * Koristimo 64-bitni privatni eksponent za:
 *   - Razumno kratko trajanje eksperimenta
 *   - Vidljivu timing razliku (svaki bit dodaje 0 ili 1 mulmod operaciju)
 *   - Dovoljan broj bita za statističku analizu (64 pozicija)
 *
 * MULMOD: koristimo __uint128_t da spriječimo overflow pri množenju.
 * Za a,b < 2^61, produkt a*b < 2^122 — staje u __uint128_t (128 bita).
 */
 
#ifndef RSA_H
#define RSA_H
 
#include <stdint.h>
 
/* -------------------------------------------------------------------------
 * Parametri eksperimenta
 * ------------------------------------------------------------------------- */
 
/* 2^61 - 1 = 2305843009213693951 — 61-bitni Mersenne prosti broj (M61) */
#define RSA_MODULUS  2305843009213693951ULL
 
/* Baza (= "šifrat" koji dekriptujemo) — konstantna za sve mjerenja */
#define RSA_BASE     1234567890123456789ULL
 
/* Broj bita privatnog eksponenta */
#define EXP_BITS     64
 
/* Bit pozicija koju targetiramo u napadu */
#define TARGET_BIT   16
 
/* -------------------------------------------------------------------------
 * Inline helper: modularna multiplikacija bez overflow-a
 *
 * Koristi GCC __uint128_t ekstenziju:
 *   a * b može biti do (2^61)^2 = 2^122 — ne staje u uint64_t
 *   __uint128_t drži do 2^128 — siguran
 *
 * Kompajler na x86-64 prevodi ovo u MULQ instrukciju (jednu!).
 * Zatim DIV ili DIVQ za modulo — ukupno ~5-20 ciklusa.
 * ------------------------------------------------------------------------- */
static inline uint64_t mulmod(uint64_t a, uint64_t b, uint64_t m) {
    return (uint64_t)(((__uint128_t)a * (__uint128_t)b) % (__uint128_t)m);
}
 
/* -------------------------------------------------------------------------
 * Inline helper: constant-time selekcija (bez grananja)
 *
 * ct_select(1, a, b) → vraća a
 * ct_select(0, a, b) → vraća b
 *
 * Princip:
 *   mask = -(cond & 1)
 *   Ako cond=1: mask = -1 = 0xFFFF...FFFF (svi biti 1)
 *   Ako cond=0: mask = -0 = 0x0000...0000 (svi biti 0)
 *
 * Rezultat: (a AND mask) OR (b AND NOT mask)
 *           = a ako mask = 0xFFF...F
 *           = b ako mask = 0x000...0
 *
 * Nema skokova → nema timing side-channel!
 * Kompajler ne smije ovo pretvoriti u branch (u -O0 režimu sigurno neće).
 * ------------------------------------------------------------------------- */
static inline uint64_t ct_select(uint64_t cond, uint64_t a, uint64_t b) {
    uint64_t mask = -(uint64_t)(cond & 1);
    return (a & mask) | (b & ~mask);
}
 
/* -------------------------------------------------------------------------
 * RANJIVA implementacija: square-and-multiply sa eksplicitnim grananjem
 *
 * TIMING SIDE-CHANNEL:
 *   Bit eksponenta = 0 → samo kvadriranje
 *   Bit eksponenta = 1 → kvadriranje + množenje (sporije!)
 *
 *   Razlika u vremenu ≈ 1 × mulmod ≈ 10-50 ciklusa po bitu
 *   Sa 100,000 mjerenja i t-testom, ovo je statistički detektabilno.
 *
 * NAPOMENA: Eksperiment 5 potvrdio da GCC (13.x) NE generise CMOV
 * za ovaj code pattern ni na jednom nivou optimizacije (O0-O3).
 * Atribut je zadrzan kao mjera opreza jer ponasanje kompajlera
 * nije garantovano izmedju verzija.
 * ------------------------------------------------------------------------- */
uint64_t mod_exp_vulnerable(uint64_t base, uint64_t exp, uint64_t mod, int num_bits);
 
/* -------------------------------------------------------------------------
 * CONSTANT-TIME implementacija: uvijek isti broj operacija
 *
 * Uvijek se izvršava:
 *   1. kvadriranje
 *   2. množenje (čak i kad je bit = 0!)
 *   3. ct_select odabira koji rezultat koristiti
 *
 * Nema grananja na bitu → nema timing leaka.
 * Timing razlika između bit=0 i bit=1 ≈ 0 (samo šum mjerenja).
 * ------------------------------------------------------------------------- */
uint64_t mod_exp_constant_time(uint64_t base, uint64_t exp, uint64_t mod, int num_bits);

/* -------------------------------------------------------------------------
 * MONTGOMERY LADDER implementacija: constant-time algoritamskom simetrijom
 *
 * Svaka iteracija izvrsava TACNO 2 mulmod operacije bez obzira na bit:
 *   bit=0: R1 = R0*R1 mod n;  R0 = R0^2 mod n
 *   bit=1: R0 = R0*R1 mod n;  R1 = R1^2 mod n
 *
 * ct_select bira koji registar prima koji rezultat - bez grananja.
 * Constant-time kroz algoritamsku simetriju, ne kroz masking.
 * ------------------------------------------------------------------------- */
uint64_t mod_exp_montgomery_ladder(uint64_t base, uint64_t exp, uint64_t mod, int num_bits);

/* -------------------------------------------------------------------------
 * RSA BLINDING kao countermeasure
 *
 * Randomizuje ulaz u eksponencijaciju:
 *   r  = nasumican broj
 *   m' = base * r mod n     (blinding)
 *   s' = mod_exp_vulnerable(m', exp, mod)
 *   s  = s' * r^(-1) mod n  (approx. unblinding)
 *
 * NAPOMENA: U nasoj 64-bit implementaciji blinding NE eliminise timing
 * leak jer je leak branch-based (eksponent-zavisan), ne operand-zavisan.
 * U realnom RSA sa big-number aritmetikom, blinding BI pomogao.
 * prng_state_ptr: pokazivac na PRNG state za generisanje r.
 * ------------------------------------------------------------------------- */
uint64_t mod_exp_blinded(uint64_t base, uint64_t exp, uint64_t mod, int num_bits,
                         uint64_t *prng_state_ptr);

/* Helper: modular inverse (extended Euclidean algorithm) */
uint64_t modinv(uint64_t a, uint64_t m);

#endif /* RSA_H */
