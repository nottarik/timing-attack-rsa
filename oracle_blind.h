/*
 * oracle_blind.h — Interfejs oracle modula za slijepu rekonstrukciju ključa
 * ==========================================================================
 *
 * KLJUČNA OSOBINA: tajni ključ je pohranjen isključivo u oracle_blind.c kao
 * static varijabla. Napadački kod (key_reconstruct_blind.c) kompajlira se
 * sa ovim headerom i nikada ne može direktno pročitati vrijednost tajnog ključa.
 *
 * ORACLE MODEL (chosen-perturbation oracle):
 *   Napadač može pozvati oracle sa XOR perturbacijom ključa:
 *     oracle_perturbed_time(base, 1ULL << i) → T(SECRET_KEY ^ (1<<i))
 *
 *   Analogija s realnim RSA: napadač šalje odabrane šifrate koji kroz
 *   multiplicativnu strukturu RSA efektivno testiraju pojedine bite
 *   privatnog eksponenta (Kocher 1996, sekcija "Timing Attack on RSA").
 *
 *   NAPOMENA: Ova ranjivost postoji jer mulmod implementacija ima
 *   grananje zavisno od eksponenta (ne od baze). U realnom RSA s
 *   big-number aritmetikom, Kocher-ov napad koristi korelaciju
 *   međuvrijednosti s porukama — identičan princip, drugačiji mehanizam.
 */

#ifndef ORACLE_BLIND_H
#define ORACLE_BLIND_H

#include <stdint.h>

/*
 * oracle_init() — Inicijalizuj oracle i generiši tajni ključ.
 *
 * key_override == 0: generiši nasumičan ključ iz /dev/urandom (pravi blind mod)
 * key_override != 0: koristi datu vrijednost (SAMO za validaciju/poređenje s v5)
 *
 * Pozovi ovo JEDNOM pri startu, PRIJE svih ostalih oracle poziva.
 */
void oracle_init(uint64_t key_override);

/*
 * oracle_secret_time() — Izmjeri T(mod_exp(base, SECRET_KEY, MOD))
 *
 * Napadač bira bazu (base), ali ne vidi niti utiče na SECRET_KEY.
 * U ovoj implementaciji, trajanje ne zavisi od baze (zavisi od
 * bitova eksponenta), ali baza se randomizuje za generalnost.
 *
 * Vraća: broj CPU ciklusa; 0 ako je detektovana migracija jezgre.
 */
uint64_t oracle_secret_time(uint64_t base);

/*
 * oracle_perturbed_time() — Izmjeri T(mod_exp(base, SECRET_KEY ^ xor_mask, MOD))
 *
 * Napadač bira xor_mask da testira specifičan bit SECRET_KEY-a:
 *   xor_mask = (1ULL << i) → flipuje bit i SECRET_KEY-a
 *   xor_mask = 0           → ekvivalentno oracle_secret_time(base)
 *
 * TAJNI KLJUČ SE NIKAD NE EKSPONIRA: perturbacija se primjenjuje
 * UNUTAR oracle-a na skrivenu vrijednost g_secret_key.
 *
 * Vraća: broj CPU ciklusa; 0 ako je detektovana migracija jezgre.
 */
uint64_t oracle_perturbed_time(uint64_t base, uint64_t xor_mask);

/*
 * oracle_scramble() — Pokrenuti mod_exp sa NASUMIČNIM (ne tajnim) eksponentom.
 *
 * Svrha: resetovati stanje branch prediktora između parova mjerenja
 * da bi se eliminisao sistematski bias od naučenog obrasca.
 * Ova funkcija NE koristi SECRET_KEY.
 */
void oracle_scramble(uint64_t rand_base, uint64_t rand_exp);

/*
 * oracle_reveal_secret() — Otkrij tajni ključ za post-hoc validaciju.
 *
 * POZIVAJ OVO SAMO NAKON ZAVRŠENE REKONSTRUKCIJE.
 * U produkcijskom scenariju ovaj poziv ne bi postojao — ovdje služi
 * isključivo za verifikaciju da je napad uspio.
 */
uint64_t oracle_reveal_secret(void);

#endif /* ORACLE_BLIND_H */
