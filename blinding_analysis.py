#!/usr/bin/env python3
# Evaluacija RSA blinding kontramjere — upoređuje blinded vs unblinded timing

import sys, os, json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from scipy.stats import ttest_ind
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

from report_utils import MarkdownReport, get_metadata, try_convert_to_pdf

BLINDED_FILE   = "blinded_timing.csv"
UNBLINDED_FILE = "unblinded_timing.csv"

plt.rcParams.update({
    'figure.dpi': 150, 'font.size': 10, 'axes.titlesize': 12,
    'axes.labelsize': 11, 'axes.grid': True, 'grid.alpha': 0.3,
})

def load_and_stats(filepath, label):
    if not os.path.exists(filepath):
        print(f"[SKIP] {filepath} nije pronađen")
        return None, None, {}
    df = pd.read_csv(filepath)
    g0 = df[df['bit_value'] == 0]['cycles'].values
    g1 = df[df['bit_value'] == 1]['cycles'].values
    lo0, hi0 = np.percentile(g0, 1), np.percentile(g0, 99)
    lo1, hi1 = np.percentile(g1, 1), np.percentile(g1, 99)
    g0 = g0[(g0 >= lo0) & (g0 <= hi0)]
    g1 = g1[(g1 >= lo1) & (g1 <= hi1)]

    delta = np.mean(g1) - np.mean(g0)
    t_stat, p_val = ttest_ind(g0, g1, equal_var=False)
    n1, n2 = len(g0), len(g1)
    s1, s2 = np.std(g0, ddof=1), np.std(g1, ddof=1)
    sp = np.sqrt(((n1-1)*s1**2 + (n2-1)*s2**2) / (n1+n2-2))
    d = delta / sp if sp > 0 else 0

    print(f"\n[{label}]")
    print(f"  N: {n1:,} (bit=0)  {n2:,} (bit=1)")
    print(f"  Mean(0)={np.mean(g0):.1f}  Mean(1)={np.mean(g1):.1f}  Δ={delta:+.2f}")
    print(f"  t={t_stat:.3f}  p={p_val:.3e}  Cohen's d={d:.5f}")
    if p_val > 0.05:
        print(f"  → Nema statistički značajne razlike (p={p_val:.3f} > 0.05) ✓")
    else:
        print(f"  → Statistički značajna razlika (p={p_val:.3e}) ✗")

    return g0, g1, {
        'label': label, 'delta': delta, 't_stat': t_stat, 'p_val': p_val, 'cohens_d': d,
        'mean0': np.mean(g0), 'mean1': np.mean(g1), 'n': min(n1, n2),
    }

print("=" * 62)
print("  RSA Blinding Countermeasure Evaluation")
print("=" * 62)

g0_b, g1_b, stats_b = load_and_stats(BLINDED_FILE, "BLINDED (sa zaštitom)")
g0_u, g1_u, stats_u = load_and_stats(UNBLINDED_FILE, "UNBLINDED (bez zaštite)")

if g0_b is None and g0_u is None:
    print(f"\n[GREŠKA] Nema CSV fajlova. Pokreni: taskset -c 0 ./blinding_experiment")
    sys.exit(1)

fig, axes = plt.subplots(1, 2, figsize=(14, 6))
fig.suptitle("RSA Blinding Countermeasure: Blinded vs Unblinded Timing",
             fontsize=13, fontweight='bold')

def paired_diff(df):
    d0 = df[df['bit_value']==0][['iteration','cycles']].rename(columns={'cycles':'c0'})
    d1 = df[df['bit_value']==1][['iteration','cycles']].rename(columns={'cycles':'c1'})
    m = pd.merge(d0, d1, on='iteration')
    return (m['c1'] - m['c0']).values

for ax, (filepath, label, color, g0, g1) in zip(axes, [
    (BLINDED_FILE,   "Blinded",   '#4CAF50', g0_b, g1_b),
    (UNBLINDED_FILE, "Unblinded", '#F44336', g0_u, g1_u),
]):
    if g0 is None:
        ax.text(0.5, 0.5, 'Nema podataka', ha='center', va='center',
                transform=ax.transAxes, fontsize=14)
        continue

    df = pd.read_csv(filepath)
    diffs = paired_diff(df)
    lo, hi = np.percentile(diffs, 1), np.percentile(diffs, 99)
    bins = np.linspace(lo, hi, 60)

    ax.hist(diffs, bins=bins, density=True, alpha=0.7, color=color, label=label)
    ax.axvline(0, color='black', lw=2, ls='--', label='Δ=0 (nema razlike)')
    ax.axvline(np.mean(diffs), color=color, lw=2, ls=':',
               label=f"Mean Δ={np.mean(diffs):+.1f}")
    ax.set_xlabel('ciklusi(bit=1) - ciklusi(bit=0)')
    ax.set_ylabel('Gustoća')
    stats = stats_b if label == "Blinded" else stats_u
    status = "✓ ZAŠTIĆENO (p>0.05)" if stats.get('p_val', 0) > 0.05 else "✗ RANJIVO (p<0.05)"
    ax.set_title(f'{label} Implementation\np={stats.get("p_val", 0):.3e}  Δ={stats.get("delta", 0):+.2f} cik\n{status}')
    ax.legend(fontsize=9)

plt.tight_layout()
plt.savefig('plot_blinding.png', bbox_inches='tight')
plt.close()
print("\n→ Grafik: plot_blinding.png")

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
sys_meta = get_metadata()

meta = {}
if os.path.exists("blinded_meta.json"):
    with open("blinded_meta.json") as f:
        meta = json.load(f)

report = MarkdownReport("RSA Blinding Countermeasure — Evaluacija")
report.add_heading(2, "Metapodaci")
report.add_stat_line("Generisano", sys_meta['timestamp'])
report.add_stat_line("Platforma", sys_meta['platform'])
report.add_stat_line("Broj uzoraka", meta.get('num_samples', 'N/A'))
report.add_stat_line("Ciljani bit", meta.get('target_bit', 'N/A'))

report.add_heading(2, "Rezultati")
headers = ["Varijanta", "N", "Mean(0)", "Mean(1)", "Δ", "t-stat", "p-vrijednost", "Cohen's d", "Zaštita?"]
tbl = []
for stats in [stats_b, stats_u]:
    if not stats:
        continue
    tbl.append([
        stats['label'],
        f"{stats['n']:,}",
        f"{stats['mean0']:.1f}",
        f"{stats['mean1']:.1f}",
        f"{stats['delta']:+.2f}",
        f"{stats['t_stat']:.3f}",
        f"{stats['p_val']:.3e}",
        f"{stats['cohens_d']:.5f}",
        "✓ DA" if stats['p_val'] > 0.05 else "✗ NE",
    ])
report.add_table(headers, tbl)

report.add_heading(2, "Zaključak")
if stats_b:
    report.add_verdict(stats_b['p_val'] > 0.05,
                      "Blinding USPJEŠNO eliminise timing signal (p > 0.05)"
                      if stats_b['p_val'] > 0.05
                      else "Blinding NE eliminise signal u potpunosti")
if stats_u:
    report.add_verdict(stats_u['p_val'] < 0.05,
                      "Bez blindinga napad je moguć (p << 0.05, kontrolna provjera)")

if stats_b and stats_b['p_val'] <= 0.05:
    report.add_paragraph(
        "U 64-bitnoj implementaciji, blinding ne eliminira timing leak jer "
        "leak potiče isključivo od grananja (bit=1 → extra mulmod). "
        "Blinding mijenja bazu, ali ne mijenja eksponent — branch pattern ostaje isti."
    )
else:
    report.add_paragraph(
        "RSA blinding uspješno eliminira timing signal randomizacijom ulaza."
    )
report.add_stat_line("Grafik", "`plot_blinding.png`")

os.makedirs("reports", exist_ok=True)
report.save(f"reports/blinding_{ts}.md")
report.save("reports/blinding_latest.md")
print(f"→ Izvještaj: reports/blinding_{ts}.md")
print(f"→ Izvještaj: reports/blinding_latest.md")
