#!/usr/bin/env python3
# Analiza rezultata Flush+Reload napada iz flush_reload.csv

import sys, os, json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

from report_utils import MarkdownReport, get_metadata

FILE_IN = "flush_reload.csv"

plt.rcParams.update({
    'figure.dpi': 150, 'font.size': 10, 'axes.titlesize': 12,
    'axes.labelsize': 11, 'axes.grid': True, 'grid.alpha': 0.3,
})

if not os.path.exists(FILE_IN):
    print(f"[GREŠKA] {FILE_IN} nije pronađen.")
    print("         Pokreni: ./victim_fr & && sleep 0.5 && taskset -c 0 ./attacker_fr")
    sys.exit(1)

df = pd.read_csv(FILE_IN)
print(f"Učitano {len(df):,} mjerenja")

latencies = df['reload_latency'].values
valid = latencies < 1e9
latencies_valid = latencies[valid]

hits = df[df['cache_hit'] == 1]['reload_latency'].values
misses = df[df['cache_hit'] == 0]['reload_latency'].values

hit_rate = 100 * len(hits) / len(df) if len(df) > 0 else 0
miss_rate = 100 * len(misses) / len(df) if len(df) > 0 else 0

print(f"\nCache hits:   {len(hits):,} ({hit_rate:.1f}%)")
print(f"Cache misses: {len(misses):,} ({miss_rate:.1f}%)")

has_bimodal = len(hits) > 0 and len(misses) > 0
if has_bimodal:
    hit_mean = np.mean(hits[hits < 10000])
    miss_mean = np.mean(misses[misses < 10000])
    separation = miss_mean - hit_mean
    print(f"\nMean reload latency (hit):  {hit_mean:.1f} cik  (std={np.std(hits[hits<10000]):.1f})")
    print(f"Mean reload latency (miss): {miss_mean:.1f} cik  (std={np.std(misses[misses<10000]):.1f})")
    print(f"Separacija (miss - hit):    {separation:.1f} cik")
    print(f"Separacija distribucija:    {'DOBRA ✓' if separation > 50 else 'SLABA ✗'}")
elif len(misses) > 0:
    miss_mean = np.mean(misses[misses < 10000])
    print(f"\nMean reload latency (miss): {miss_mean:.1f} cik")
    separation = 0
else:
    separation = 0

fig, axes = plt.subplots(1, 3, figsize=(17, 5))
fig.suptitle("Flush+Reload Attack: Cache Side-Channel Analysis\n"
             "Target: rsa_multiply_step() (conditional multiply in modexp)",
             fontsize=13, fontweight='bold')

ax = axes[0]
lats_clean = latencies_valid[latencies_valid < 2000]
if len(lats_clean) > 0:
    bins = np.linspace(0, np.percentile(lats_clean, 99) * 1.2, 80)
    if has_bimodal:
        hits_clean = hits[hits < 2000]
        misses_clean = misses[misses < 2000]
        if len(hits_clean) > 0:
            ax.hist(hits_clean, bins=bins, density=True, alpha=0.7,
                    color='#4CAF50', label=f'Cache Hit (n={len(hits):,})')
        if len(misses_clean) > 0:
            ax.hist(misses_clean, bins=bins, density=True, alpha=0.7,
                    color='#F44336', label=f'Cache Miss (n={len(misses):,})')
    else:
        ax.hist(lats_clean, bins=bins, density=True, alpha=0.7, color='#2196F3')
ax.set_xlabel('Reload latencija [ciklusi]')
ax.set_ylabel('Gustoća')
bimodal_str = 'Bimodalna ✓' if has_bimodal else 'Unimodalna ✗'
ax.set_title(f'Distribucija reload latencije\n{bimodal_str}')
ax.legend(fontsize=9)

ax = axes[1]
n_show = min(1000, len(df))
hit_mask = df['cache_hit'][:n_show].values == 1
ax.scatter(range(n_show), latencies[:n_show],
           c=['#4CAF50' if h else '#F44336' for h in hit_mask],
           alpha=0.5, s=8)
ax.set_xlabel('Indeks observacije')
ax.set_ylabel('Reload latencija [ciklusi]')
ax.set_title(f'Vremenska sekvenca prvih {n_show} mjerenja\n(zeleno=hit, crveno=miss)')
if len(latencies_valid) > 0:
    ax.set_ylim(0, min(np.percentile(latencies_valid, 99) * 1.5, 2000))

ax = axes[2]
window = 100
if len(df) >= window:
    hit_rate_rolling = df['cache_hit'].rolling(window).mean().values
    ax.plot(range(len(hit_rate_rolling)), hit_rate_rolling * 100,
            color='#9C27B0', lw=1.5, label=f'Hit rate (rolling {window})')
    ax.axhline(50, color='gray', ls='--', lw=1.5, label='50% (random)')
ax.set_xlabel('Observacija')
ax.set_ylabel('Stopa cache pogodaka (%)')
ax.set_title(f'Rolling hit rate (window={window})\nReflektuje aktivnost victim procesa')
ax.legend()
ax.set_ylim(0, 105)

plt.tight_layout()
plt.savefig('plot_flush_reload.png', bbox_inches='tight')
plt.close()
print("\n→ Grafik: plot_flush_reload.png")

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
sys_meta = get_metadata()

report = MarkdownReport("Flush+Reload Attack — Analiza Rezultata")
report.add_heading(2, "Metapodaci")
report.add_stat_line("Generisano", sys_meta['timestamp'])
report.add_stat_line("Platforma", sys_meta['platform'])
report.add_stat_line("Broj observacija", f"{len(df):,}")
report.add_stat_line("Target funkcija", "rsa_multiply_step() (conditional multiply)")

report.add_heading(2, "Rezultati")
report.add_stat_line("Cache hits (bit=1)", f"{len(hits):,} ({hit_rate:.1f}%)")
report.add_stat_line("Cache misses (bit=0)", f"{len(misses):,} ({miss_rate:.1f}%)")
if has_bimodal:
    report.add_stat_line("Mean reload latency (hit)", f"{hit_mean:.1f} cik")
    report.add_stat_line("Mean reload latency (miss)", f"{miss_mean:.1f} cik")
    report.add_stat_line("Separacija (miss - hit)", f"{separation:.1f} cik")
    report.add_verdict(separation > 50,
                      f"Bimodalna distribucija ({separation:.1f} cik separacija) — "
                      f"Flush+Reload USPJEŠAN"
                      if separation > 50
                      else f"Slaba separacija ({separation:.1f} cik) — Signal nedovoljan")
elif len(misses) > 0 and len(hits) == 0:
    report.add_stat_line("Mean reload latency (miss)", f"{miss_mean:.1f} cik")
    report.add_verdict(False,
                      "Nema cache hitova — victim proces vjerovatno nije bio aktivan.")

report.add_heading(2, "Opis napada")
report.add_paragraph(
    "Flush+Reload napad koristi dijeljenu memoriju između victim i attacker procesa. "
    "Attacker cilja rsa_multiply_step() — funkciju koja se poziva samo kad je bit eksponenta = 1. "
    "Attacker eviktuje (clflush) cache liniju te funkcije, čeka da victim izvrši dekriptovanje, "
    "a zatim mjeri latenciju ponovnog učitavanja. "
    "Kratka latencija indicira cache hit (bit=1), duga latencija indicira miss (bit=0)."
)
report.add_stat_line("Grafik", "`plot_flush_reload.png`")

os.makedirs("reports", exist_ok=True)
report.save(f"reports/flush_reload_{ts}.md")
report.save("reports/flush_reload_latest.md")
print(f"→ Izvještaj: reports/flush_reload_{ts}.md")
print(f"→ Izvještaj: reports/flush_reload_latest.md")
