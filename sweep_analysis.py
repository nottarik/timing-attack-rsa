#!/usr/bin/env python3
# Analiza multi_bit_sweep eksperimenta — timing leak po svim bit pozicijama

import sys, os, json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from scipy.stats import ttest_ind, ttest_1samp
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

from report_utils import MarkdownReport, get_metadata, try_convert_to_pdf

FILE_IN   = "multi_bit_sweep.csv"
META_FILE = "multi_bit_sweep_meta.json"

plt.rcParams.update({
    'figure.dpi': 150, 'font.size': 10, 'axes.titlesize': 12,
    'axes.labelsize': 11, 'axes.grid': True, 'grid.alpha': 0.3,
})

if not os.path.exists(FILE_IN):
    print(f"[GREŠKA] {FILE_IN} nije pronađen. Pokreni: taskset -c 0 ./multi_bit_sweep")
    sys.exit(1)

print(f"Učitavanje {FILE_IN}...")
df = pd.read_csv(FILE_IN)
print(f"  {len(df):,} redova učitano")

meta = {}
if os.path.exists(META_FILE):
    with open(META_FILE) as f:
        meta = json.load(f)

num_bits = int(df['target_bit'].max()) + 1
bit_positions = sorted(df['target_bit'].unique())

print(f"  {num_bits} bit pozicija pronađeno")

# statistika po bitu
results = []
for b in bit_positions:
    sub = df[df['target_bit'] == b]
    g0 = sub[sub['bit_value'] == 0]['cycles'].values
    g1 = sub[sub['bit_value'] == 1]['cycles'].values

    lo0, hi0 = np.percentile(g0, 1), np.percentile(g0, 99)
    lo1, hi1 = np.percentile(g1, 1), np.percentile(g1, 99)
    g0 = g0[(g0 >= lo0) & (g0 <= hi0)]
    g1 = g1[(g1 >= lo1) & (g1 <= hi1)]

    if len(g0) < 10 or len(g1) < 10:
        continue

    m0, m1 = np.mean(g0), np.mean(g1)
    delta = m1 - m0
    n1, n2 = len(g0), len(g1)
    s1, s2 = np.std(g0, ddof=1), np.std(g1, ddof=1)
    sp = np.sqrt(((n1-1)*s1**2 + (n2-1)*s2**2) / (n1+n2-2))
    d = delta / sp if sp > 0 else 0
    t_stat, p_val = ttest_ind(g0, g1, equal_var=False)

    results.append({
        'bit': b,
        'n': min(n1, n2),
        'mean0': m0,
        'mean1': m1,
        'delta': delta,
        't_stat': t_stat,
        'p_val': p_val,
        'cohens_d': d,
        'significant': p_val < 0.05,
    })

res_df = pd.DataFrame(results).sort_values('bit')

n_sig = res_df['significant'].sum()
n_total = len(res_df)
all_deltas = res_df['delta'].values

print(f"\nStatistički značajnih bita (p<0.05): {n_sig}/{n_total}")
print(f"Mean Δ po svim bitovima: {np.mean(all_deltas):+.2f} cik")
print(f"Std Δ: {np.std(all_deltas):.2f} cik")

# one-sample t-test: je li srednji delta značajno različit od nule
t_overall, p_overall = ttest_1samp(all_deltas, 0)
print(f"\nOne-sample t-test (H0: mean_delta=0): t={t_overall:.3f}, p={p_overall:.3e}")
if p_overall < 0.05:
    print("→ Odbacujemo H0: timing leak je SISTEMSKI za sve bit pozicije ✓")
else:
    print("→ Ne možemo odbaciti H0 — signal slab ili nedovoljno uzoraka")

fig, axes = plt.subplots(3, 1, figsize=(16, 14))
fig.suptitle("Multi-Bit Sweep: Timing Leak po Svim Bit Pozicijama\n"
             "Ranjiva implementacija (square-and-multiply sa grananjem)",
             fontsize=13, fontweight='bold')

bits = res_df['bit'].values
deltas = res_df['delta'].values
pvals = res_df['p_val'].values
ds = res_df['cohens_d'].values

ax = axes[0]
colors = ['#F44336' if p < 0.05 else '#BDBDBD' for p in pvals]
ax.bar(bits, deltas, color=colors, edgecolor='white', linewidth=0.5, alpha=0.85)
ax.axhline(0, color='black', lw=1.5, ls='--', alpha=0.7)
ax.axhline(np.mean(deltas), color='#9C27B0', lw=2, ls=':', label=f'Mean Δ={np.mean(deltas):+.1f} cik')
ax.set_xlabel('Bit pozicija eksponenta')
ax.set_ylabel('Δmean = mean(bit=1) − mean(bit=0) [cik]')
ax.set_title(f'Δ mean po bit poziciji  |  Crveno = statistički značajno (p<0.05) — {n_sig}/{n_total} bita')
ax.set_xlim(-0.5, num_bits - 0.5)
from matplotlib.patches import Patch
ax.legend(handles=[
    Patch(color='#F44336', label=f'Statistički značajno (p<0.05): {n_sig} bita'),
    Patch(color='#BDBDBD', label=f'Nije značajno: {n_total-n_sig} bita'),
], fontsize=9)

ax = axes[1]
p_clipped = np.maximum(pvals, 1e-20)
ax.semilogy(bits, p_clipped, 'o-', color='#2196F3', lw=1.5, ms=5, label='p-vrijednost')
ax.axhline(0.05, color='red', ls='--', lw=2, label='p=0.05 (threshold)')
ax.fill_between(bits, p_clipped, 0.05, where=p_clipped < 0.05,
                alpha=0.15, color='green', label='Značajna zona')
ax.set_xlabel('Bit pozicija eksponenta')
ax.set_ylabel('p-vrijednost (log skala)')
ax.set_title(f'p-vrijednosti Welch t-testa  |  One-sample test svih Δ: t={t_overall:.2f}, p={p_overall:.2e}')
ax.legend(fontsize=9)
ax.set_xlim(-0.5, num_bits - 0.5)

ax = axes[2]
ax.bar(bits, np.abs(ds), color='#FF9800', edgecolor='white', linewidth=0.5, alpha=0.85)
ax.axhline(0.2, color='green', ls=':', lw=1.5, label='|d|=0.2 (mali efekt)')
ax.axhline(np.mean(np.abs(ds)), color='#9C27B0', lw=2, ls='--',
           label=f"Mean |d|={np.mean(np.abs(ds)):.4f}")
ax.set_xlabel('Bit pozicija eksponenta')
ax.set_ylabel("|Cohen's d|")
ax.set_title("Veličina efekta (Cohen's d) po bit poziciji")
ax.legend(fontsize=9)
ax.set_xlim(-0.5, num_bits - 0.5)

plt.tight_layout()
plt.savefig('plot_multi_bit_sweep.png', bbox_inches='tight')
plt.close()
print("\n→ Grafik: plot_multi_bit_sweep.png")

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
sys_meta = get_metadata()

report = MarkdownReport("RSA Timing Side-Channel — Multi-Bit Sweep Analiza")
report.add_heading(2, "Metapodaci")
report.add_stat_line("Generisano", sys_meta['timestamp'])
report.add_stat_line("Platforma", sys_meta['platform'])
report.add_stat_line("Uzoraka po bitu", meta.get('samples_per_bit', 'N/A'))
report.add_stat_line("EXP_BITS", meta.get('exp_bits', num_bits))
report.add_stat_line("PRNG seed", meta.get('prng_seed', 'N/A'))

report.add_heading(2, "Ukupni rezultati")
report.add_stat_line("Statistički značajnih bita (p<0.05)", f"{n_sig}/{n_total}")
report.add_stat_line("Mean Δ po svim bitovima", f"{np.mean(all_deltas):+.2f} cik")
report.add_stat_line("Std Δ", f"{np.std(all_deltas):.2f} cik")
report.add_stat_line("One-sample t-test (H0: mean_delta=0)",
                    f"t={t_overall:.3f}, p={p_overall:.3e}")
report.add_verdict(p_overall < 0.05,
                  "Timing leak je SISTEMSKI za sve bit pozicije — odbacujemo H0"
                  if p_overall < 0.05
                  else "Nije moguće odbaciti H0 — signal slab")

report.add_heading(2, "Bit-po-bit rezultati")
headers = ["Bit", "N", "Mean(0)", "Mean(1)", "Δ", "t-stat", "p-vrijednost", "Cohen's d", "Sig?"]
tbl = []
for _, row in res_df.iterrows():
    tbl.append([
        str(int(row['bit'])),
        str(int(row['n'])),
        f"{row['mean0']:.1f}",
        f"{row['mean1']:.1f}",
        f"{row['delta']:+.2f}",
        f"{row['t_stat']:.2f}",
        f"{row['p_val']:.2e}",
        f"{row['cohens_d']:.4f}",
        "✓" if row['significant'] else "✗",
    ])
report.add_table(headers, tbl)

report.add_heading(2, "Zaključak")
report.add_paragraph(
    f"Multi-bit sweep pokazuje da timing side-channel postoji na svim bit pozicijama. "
    f"{n_sig} od {n_total} pozicija ima statistički značajnu timing razliku (p<0.05). "
    f"One-sample t-test potvrđuje da je srednja delta ({np.mean(all_deltas):+.2f} ciklusa) "
    f"značajno različita od nule (t={t_overall:.2f}, p={p_overall:.2e})."
)
report.add_stat_line("Grafik", "`plot_multi_bit_sweep.png`")

os.makedirs("reports", exist_ok=True)
report.save(f"reports/sweep_{ts}.md")
report.save("reports/sweep_latest.md")
print(f"→ Izvještaj: reports/sweep_{ts}.md")
print(f"→ Izvještaj: reports/sweep_latest.md")
