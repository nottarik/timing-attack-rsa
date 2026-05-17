#!/usr/bin/env python3
# Analiza efekata compiler optimizacija na timing side-channel

import sys, os, json, subprocess
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

VARIANTS = [
    ('O0',       'vulnerable_O0.csv',       '-O0', False,
     'Bez opt. (baseline)'),
    ('O1',       'vulnerable_O1.csv',       '-O1', False,
     'Bazična optimizacija'),
    ('O2',       'vulnerable_O2.csv',       '-O2', False,
     'Standardna optimizacija'),
    ('O3',       'vulnerable_O3.csv',       '-O3', False,
     'Agresivna optimizacija'),
    ('O2_attr',  'vulnerable_O2_attr.csv',  '-O2', True,
     '-O2 + __attribute__((optimize("O0"))) (trenutni setup)'),
]

plt.rcParams.update({
    'figure.dpi': 150, 'font.size': 10, 'axes.titlesize': 12,
    'axes.labelsize': 11, 'axes.grid': True, 'grid.alpha': 0.3,
})

def load_variant(csv_path, label):
    if not os.path.exists(csv_path):
        print(f"  [SKIP] {csv_path} nije pronađen")
        return None, None
    df = pd.read_csv(csv_path)
    g0 = df[df['bit_value'] == 0]['cycles'].values
    g1 = df[df['bit_value'] == 1]['cycles'].values
    lo0, hi0 = np.percentile(g0, 1), np.percentile(g0, 99)
    lo1, hi1 = np.percentile(g1, 1), np.percentile(g1, 99)
    g0 = g0[(g0 >= lo0) & (g0 <= hi0)]
    g1 = g1[(g1 >= lo1) & (g1 <= hi1)]
    print(f"  [{label}] n={min(len(g0),len(g1)):,}  "
          f"mean0={np.mean(g0):.1f}  mean1={np.mean(g1):.1f}  "
          f"Δ={np.mean(g1)-np.mean(g0):+.2f}")
    return g0, g1

def detect_cmov(binary_name, func_name='mod_exp_vulnerable'):
    # provjeri koristi li funkcija cmov ili conditional jump
    try:
        result = subprocess.run(
            ['objdump', '-d', binary_name],
            capture_output=True, text=True, timeout=30
        )
        in_func = False
        has_cmov = False
        has_jmp = False
        for line in result.stdout.split('\n'):
            if f'<{func_name}>:' in line:
                in_func = True
            elif in_func and line.strip() and line.strip()[0] not in '0123456789abcdef':
                in_func = False
            if in_func:
                if any(x in line for x in ['cmove', 'cmovne', 'cmovl', 'cmovg', 'cmovz', 'cmovnz']):
                    has_cmov = True
                if any(x in line for x in ['je ', 'jne ', 'jz ', 'jnz ', 'jl ', 'jg ']):
                    has_jmp = True
        if has_cmov and not has_jmp:
            return 'cmov (constant-time)'
        elif has_jmp:
            return 'branch (leaky)'
        else:
            return 'unknown'
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return 'N/A'

print("=" * 62)
print("  Compiler Optimization Effects on RSA Timing Side-Channel")
print("=" * 62)

all_results = []
for name, csv_file, opt_level, has_attr, description in VARIANTS:
    print(f"\n[{name}] {description}")
    g0, g1 = load_variant(csv_file, name)
    if g0 is None:
        continue

    delta = np.mean(g1) - np.mean(g0)
    t_stat, p_val = ttest_ind(g0, g1, equal_var=False)
    n1, n2 = len(g0), len(g1)
    s1, s2 = np.std(g0, ddof=1), np.std(g1, ddof=1)
    sp = np.sqrt(((n1-1)*s1**2 + (n2-1)*s2**2) / (n1+n2-2))
    cohens_d = delta / sp if sp > 0 else 0

    binary_map = {
        'O0': 'experiment_O0',
        'O1': 'experiment_O1',
        'O2': 'experiment_O2',
        'O3': 'experiment_O3',
        'O2_attr': 'experiment_O2_attr',
    }
    asm_type = detect_cmov(binary_map.get(name, ''))

    leak_present = p_val < 0.05 and abs(delta) > 2
    print(f"  Δ={delta:+.2f} cik  t={t_stat:.2f}  p={p_val:.2e}  "
          f"d={cohens_d:.4f}  asm={asm_type}  leak={'DA ✓' if leak_present else 'NE ✗'}")

    all_results.append({
        'name': name,
        'description': description,
        'opt_level': opt_level,
        'has_attr': has_attr,
        'delta': delta,
        't_stat': t_stat,
        'p_val': p_val,
        'cohens_d': cohens_d,
        'asm_type': asm_type,
        'leak_present': leak_present,
        'g0': g0,
        'g1': g1,
        'mean0': np.mean(g0),
        'mean1': np.mean(g1),
    })

if not all_results:
    print("\n[GREŠKA] Nema CSV fajlova. Pokreni: make compiler-experiment")
    sys.exit(1)

fig, axes = plt.subplots(1, 3, figsize=(18, 6))
fig.suptitle("Efekat Compiler Optimizacije na RSA Timing Side-Channel",
             fontsize=13, fontweight='bold')

names = [r['name'] for r in all_results]
deltas = [r['delta'] for r in all_results]
colors = ['#F44336' if r['leak_present'] else '#4CAF50' for r in all_results]

ax = axes[0]
ax.bar(range(len(names)), deltas, color=colors, edgecolor='white',
       linewidth=0.5, alpha=0.85)
ax.axhline(0, color='black', lw=1.5, ls='--')
ax.set_xticks(range(len(names)))
ax.set_xticklabels(names, rotation=20, ha='right')
ax.set_ylabel('Δmean = mean(bit=1) − mean(bit=0) [cik]')
ax.set_title('Delta po optimization nivou\n(crveno=leak, zeleno=sigurno)')
from matplotlib.patches import Patch
ax.legend(handles=[
    Patch(color='#F44336', label='Leak prisutan'),
    Patch(color='#4CAF50', label='Leak eliminisan'),
], fontsize=9)

ax = axes[1]
pvals = [max(r['p_val'], 1e-20) for r in all_results]
ax.bar(range(len(names)), [-np.log10(p) for p in pvals],
       color=colors, edgecolor='white', linewidth=0.5, alpha=0.85)
ax.axhline(-np.log10(0.05), color='red', ls='--', lw=1.5, label='p=0.05')
ax.set_xticks(range(len(names)))
ax.set_xticklabels(names, rotation=20, ha='right')
ax.set_ylabel('-log10(p-vrijednost)')
ax.set_title('Statistička značajnost\n(veće = jači dokaz leaka)')
ax.legend()

ax = axes[2]
for i, r in enumerate(all_results):
    lo = np.percentile(r['g0'], 5)
    hi = np.percentile(np.concatenate([r['g0'], r['g1']]), 95)
    bins = np.linspace(lo, hi, 40)
    ax.hist(r['g0'], bins=bins, density=True, alpha=0.3, label=f"{r['name']} bit=0")
ax.set_xlabel('CPU Ciklusi')
ax.set_ylabel('Gustoća')
ax.set_title('Distribucije bit=0 po opt. nivou')
ax.legend(fontsize=7)

plt.tight_layout()
plt.savefig('plot_compiler_effects.png', bbox_inches='tight')
plt.close()
print("\n→ Grafik: plot_compiler_effects.png")

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
sys_meta = get_metadata()

report = MarkdownReport("RSA Timing Side-Channel — Compiler Optimization Analiza")
report.add_heading(2, "Metapodaci")
report.add_stat_line("Generisano", sys_meta['timestamp'])
report.add_stat_line("Platforma", sys_meta['platform'])

report.add_heading(2, "Rezultati po optimization nivou")
headers = ["Varijanta", "Opt. nivo", "Attr?", "Δ mean [cik]",
           "p-vrijednost", "Cohen's d", "Assembly tip", "Leak?"]
tbl = []
for r in all_results:
    tbl.append([
        r['name'],
        r['opt_level'],
        "DA" if r['has_attr'] else "NE",
        f"{r['delta']:+.2f}",
        f"{r['p_val']:.2e}",
        f"{r['cohens_d']:.4f}",
        r['asm_type'],
        "DA ✗" if r['leak_present'] else "NE ✓",
    ])
report.add_table(headers, tbl)

report.add_heading(2, "Zaključak")
leaky = [r['name'] for r in all_results if r['leak_present']]
safe = [r['name'] for r in all_results if not r['leak_present']]
report.add_paragraph(
    f"Varijante sa leakom: {leaky}. "
    f"Varijante bez leaka (cmov generisan): {safe}. "
    "Compiler optimizacije ne mogu se smatrati sigurnosnom mjerom."
)
report.add_stat_line("Grafik", "`plot_compiler_effects.png`")

os.makedirs("reports", exist_ok=True)
report.save(f"reports/compiler_{ts}.md")
report.save("reports/compiler_latest.md")
print(f"→ Izvještaj: reports/compiler_{ts}.md")
print(f"→ Izvještaj: reports/compiler_latest.md")
