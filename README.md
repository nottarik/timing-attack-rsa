# RSA Timing Side-Channel Attack

Eksperimentalna analiza timing i cache side-channel napada na RSA kriptosistem. Implementirano kao završni rad prvog ciklusa studija na Elektrotehničkom fakultetu Univerziteta u Sarajevu.

## Pregled

Rad demonstrira da naivna implementacija RSA-a kroz algoritam square-and-multiply otkriva informacije o privatnom ključu kroz mjerljive razlike u vremenu izvršavanja. Provedeno je sedam eksperimenata:

| # | Eksperiment | Ključni nalaz |
|---|---|---|
| 1 | Detekcija vremenskog curenja | +75,90 CPU ciklusa razlike po bitu (p < 10⁻⁵⁰) |
| 2 | Napad usrednjavanjem | 100% tačnost za K ≥ 2000 mjerenja po bitu |
| 3 | Slijepa rekonstrukcija 64-bitnog ključa | 64/64 bita tačno, napadač nikada ne vidi ključ |
| 4 | Analiza svih 64 bit-pozicija | Curenje prisutno na svakoj poziciji (p < 10⁻⁹) |
| 5 | Utjecaj kompajlerskih optimizacija | GCC -O0 do -O3 ne eliminišu ranjivost |
| 6 | RSA blinding | Ne štiti od branch-zavisnog curenja |
| 7 | Flush+Reload cache napad | 341,5-ciklusna separacija, klasifikacija iz jednog mjerenja |

## Zahtjevi

**Platforma:** Linux (testirano na Ubuntu 24.04 LTS, x86\_64)

**Alati:**
```bash
# Kompajler
gcc --version   # GCC 13+

# Python zavisnosti
pip install -r requirements.txt   # numpy, pandas, scipy, matplotlib
```

**Preporučeni hardver:** Intel Core procesor s invarijantnim TSC (constant_tsc, nonstop_tsc)

## Podešavanje hardvera

Za pouzdana mjerenja, potrebno je isključiti dinamičko skaliranje frekvencije:

```bash
# Isključi Intel Turbo Boost
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# Postavi performance governor
sudo cpupower frequency-set -g performance
```

Detaljne upute su u Prilogu A teze i skripti `setup.sh`.

## Kompajliranje i pokretanje

```bash
# Kompajliranje svega
make all

# ── Eksperiment 1 & 2: Detekcija curenja i napad usrednjavanjem ──
make run           # Pokretanje (pinuje na CPU 0)
make analyze       # Statistička analiza → reports/analysis_latest.md

# ── Eksperiment 3: Slijepa rekonstrukcija ključa ──
make run-blind-recon

# ── Eksperiment 4: Sweep svih 64 bit-pozicija ──
make run-sweep

# ── Eksperiment 5: Kompajlerske optimizacije ──
make compiler-experiment

# ── Eksperiment 6: RSA blinding ──
make run-blinding

# ── Eksperiment 7: Flush+Reload cache napad ──
# Pokrenuti u dva odvojena terminala:
make run-flush-reload   # pokreće victim i attacker procese

# ── Provjera assembly koda ──
make check_asm     # Verifikuje branch/cmov u generisanom kodu
```

## Struktura projekta

```
.
├── rsa.c / rsa.h                  # RSA implementacije (ranjiva, constant-time,
│                                  #   Montgomery ladder, blinding)
├── timing.h                       # RDTSCP/CPUID mjerenje CPU ciklusa
├── experiment.c                   # Eksp. 1 & 2: detekcija curenja, averaging napad
├── key_reconstruct_blind.c        # Eksp. 3: slijepa rekonstrukcija 64-bitnog ključa
├── oracle_blind.c / oracle_blind.h # Oracle interfejs (tajni ključ skrivena od napadača)
├── key_reconstruct.c              # Direktna rekonstrukcija (napadač zna ključ)
├── multi_bit_sweep.c              # Eksp. 4: sistematska analiza svih 64 pozicija
├── rsa_no_attr.c                  # Eksp. 5: kompajlerske varijante bez optimize atributa
├── blinding_experiment.c          # Eksp. 6: evaluacija RSA blinding kontramjere
├── victim_fr.c                    # Eksp. 7: Flush+Reload žrtva
├── attacker_fr.c                  # Eksp. 7: Flush+Reload napadač
├── librsa_shared.c                # Dijeljeni RSA kod za cache napad (.so biblioteka)
│
├── analysis.py                    # Statistička analiza: Welch t-test, Mann-Whitney U,
│                                  #   Cohen's d, bootstrap CI, power analysis
├── key_reconstruct_blind_analysis.py
├── sweep_analysis.py
├── blinding_analysis.py
├── compiler_analysis.py
├── flush_reload_analysis.py
├── report_utils.py                # Zajednički alati za generisanje Markdown reporta
│
├── Makefile                       # Build sistem sa svim eksperimentalnim targetima
├── setup.sh                       # Skripta za konfiguraciju hardverskog okruženja
├── requirements.txt               # Python zavisnosti
│
└── latex/                         # LaTeX izvorni kod teze i kompajlirani PDF
```

## Platforma

Eksperimenti su provedeni na:
- **Računar:** Lenovo ThinkPad T14 Gen 4
- **Procesor:** Intel Core i5-1335U (Raptor Lake, 13. gen., hibridna arhitektura)
- **OS:** Ubuntu Linux 24.04 LTS, kernel 6.17.0-19
- **Kompajler:** GCC 13.3

Konkretne vrijednosti (75,90 ciklusa razlike, σ ≈ 567 ciklusa, K = 2000 za 100% tačnost) specifične su za ovu arhitekturu. Fundamentalni mehanizam curenja primjenjiv je na sve x86 platforme s naivnim square-and-multiply implementacijama.

## Napomena o podacima

Eksperimentalni podaci (CSV fajlovi, ~190 MB) nisu uključeni u repozitorij. Pokretanjem `make run` generiše se novi skup podataka na vašoj platformi.
