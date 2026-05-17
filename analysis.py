#!/usr/bin/env python3
# Statistička analiza RSA timing side-channel podataka

import sys, os, json
from typing import Optional
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from scipy.stats import ttest_ind, ttest_rel, mannwhitneyu, pearsonr, pointbiserialr
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

from report_utils import MarkdownReport, get_metadata, try_convert_to_pdf

FILE_VULNERABLE   = "vulnerable_timing.csv"
FILE_CONSTANT     = "constant_time_timing.csv"
TARGET_BIT        = 16

plt.rcParams.update({
    'figure.dpi': 150, 'font.size': 10, 'axes.titlesize': 12,
    'axes.labelsize': 11, 'axes.grid': True, 'grid.alpha': 0.3,
})
COLORS = {'bit0': '#2196F3', 'bit1': '#F44336', 'ct': '#4CAF50'}

_report: Optional[MarkdownReport] = None

def load_and_filter(filepath, label):
    if not os.path.exists(filepath):
        print(f"[GREŠKA] Fajl nije pronađen: {filepath}")
        print("         Pokreni: taskset -c 0 ./experiment")
        sys.exit(1)
    df = pd.read_csv(filepath)
    n_before = len(df)
    filtered = []
    for bit_val in df['bit_value'].unique():
        grp = df[df['bit_value'] == bit_val]
        lo = np.percentile(grp['cycles'], 1)
        hi = np.percentile(grp['cycles'], 99)
        filtered.append(grp[(grp['cycles'] >= lo) & (grp['cycles'] <= hi)])
    df = pd.concat(filtered).copy()
    n_after = len(df)
    print(f"[{label}] {n_before:,} → {n_after:,} redova (1-99 percentil po grupi)")
    if _report is not None:
        _report.add_stat_line(f"{label} — redova učitano", f"{n_before:,}")
        _report.add_stat_line(f"{label} — redova nakon filtriranja", f"{n_after:,}")
        _report.add_stat_line(f"{label} — odbačeno", f"{n_before - n_after:,} ({100*(n_before-n_after)/n_before:.1f}%)")
    return df


def cohens_d(g1, g2):
    n1, n2 = len(g1), len(g2)
    s1, s2 = np.std(g1, ddof=1), np.std(g2, ddof=1)
    sp = np.sqrt(((n1-1)*s1**2 + (n2-1)*s2**2) / (n1+n2-2))
    return (np.mean(g1) - np.mean(g2)) / sp if sp > 0 else 0.0


def power_analysis(delta_mean, pooled_std, alpha=0.05, power=0.80):
    # minimalan N po grupi za zadanu veličinu efekta
    from scipy.stats import norm as sp_norm
    if pooled_std == 0 or delta_mean == 0:
        return float('inf')
    d = abs(delta_mean) / pooled_std
    z_a = sp_norm.ppf(1 - alpha / 2)
    z_b = sp_norm.ppf(power)
    return int(np.ceil(((z_a + z_b) / d) ** 2))


def descriptive_stats(g0, g1, label):
    print(f"\n{'='*62}")
    print(f"  DESKRIPTIVNA STATISTIKA — {label}")
    print(f"{'='*62}")
    print(f"  {'Metrika':<22} {'bit=0':>14} {'bit=1':>14} {'Razlika':>10}")
    print(f"  {'-'*62}")
    rows = [
        ('N uzoraka',        len(g0),             len(g1)),
        ('Mean (ciklusi)',    np.mean(g0),          np.mean(g1)),
        ('Median',           np.median(g0),        np.median(g1)),
        ('Std Dev',          np.std(g0, ddof=1),   np.std(g1, ddof=1)),
        ('P25',              np.percentile(g0,25), np.percentile(g1,25)),
        ('P75',              np.percentile(g0,75), np.percentile(g1,75)),
    ]
    for name, v0, v1 in rows:
        if name == 'N uzoraka':
            print(f"  {name:<22} {int(v0):>14,} {int(v1):>14,} {'N/A':>10}")
        else:
            print(f"  {name:<22} {v0:>14.2f} {v1:>14.2f} {v1-v0:>+10.2f}")

    if _report is not None:
        _report.add_heading(3, f"Deskriptivna statistika — {label}")
        headers = ["Metrika", "bit=0", "bit=1", "Razlika"]
        tbl = []
        for name, v0, v1 in rows:
            if name == 'N uzoraka':
                tbl.append([name, f"{int(v0):,}", f"{int(v1):,}", "N/A"])
            else:
                tbl.append([name, f"{v0:.2f}", f"{v1:.2f}", f"{v1-v0:+.2f}"])
        _report.add_table(headers, tbl)


def bootstrap_ci_mean_diff(g0, g1, n_boot=10000, ci=0.95, seed=42):
    # bootstrap interval pouzdanosti za razliku sredina
    rng = np.random.default_rng(seed)
    diffs = np.empty(n_boot)
    for i in range(n_boot):
        s0 = rng.choice(g0, size=len(g0), replace=True)
        s1 = rng.choice(g1, size=len(g1), replace=True)
        diffs[i] = np.mean(s1) - np.mean(s0)
    alpha = (1 - ci) / 2
    return np.percentile(diffs, 100 * alpha), np.percentile(diffs, 100 * (1 - alpha))


def statistical_tests(g0, g1, label, df=None):
    print(f"\n{'='*62}")
    print(f"  STATISTIČKI TESTOVI — {label}")
    print(f"{'='*62}")

    t_stat, p_t = ttest_ind(g0, g1, equal_var=False)
    u_stat, p_mw = mannwhitneyu(g0, g1, alternative='two-sided')
    d = cohens_d(g1, g0)
    all_c = np.concatenate([g0, g1])
    all_b = np.concatenate([np.zeros(len(g0)), np.ones(len(g1))])
    r_pb, p_pb = pointbiserialr(all_b, all_c)

    paired_t_stat, paired_p = float('nan'), float('nan')
    if df is not None:
        d0 = df[df['bit_value']==0][['iteration','cycles']].rename(columns={'cycles':'c0'})
        d1 = df[df['bit_value']==1][['iteration','cycles']].rename(columns={'cycles':'c1'})
        merged = pd.merge(d0, d1, on='iteration')
        if len(merged) > 1:
            paired_t_stat, paired_p = ttest_rel(merged['c0'].values, merged['c1'].values)

    def interp_p(p):
        if p < 1e-50: return "EKSTREMNO značajno (p < 1e-50) ✓✓"
        if p < 1e-10: return "Izuzetno značajno (p < 1e-10) ✓"
        if p < 0.001: return "Visoko značajno (p < 0.001) ✓"
        if p < 0.05:  return "Značajno (p < 0.05) ✓"
        return f"NIJE značajno (p = {p:.4f}) ✗"

    def interp_d(d):
        ad = abs(d)
        if ad < 0.05: return "zanemarljiv"
        if ad < 0.2:  return "mali"
        if ad < 0.5:  return "srednji"
        return "veliki"

    print(f"\n  [1] Welch's t-test:        t={t_stat:.4f},  p={p_t:.3e}")
    print(f"      → {interp_p(p_t)}")
    if not np.isnan(paired_t_stat):
        print(f"\n  [1b] Paired t-test:        t={paired_t_stat:.4f},  p={paired_p:.3e}")
        print(f"       → {interp_p(paired_p)}")
    print(f"\n  [2] Mann-Whitney U test:   U={u_stat:.0f},  p={p_mw:.3e}")
    print(f"      → {interp_p(p_mw)}")
    print(f"\n  [3] Cohen's d (effect size): d={d:.5f}  [{interp_d(d)} efekt]")
    print(f"\n  [4] Point-Biserial r (cycles~bit): r={r_pb:.5f},  p={p_pb:.3e}")
    print(f"      r² = {r_pb**2:.6f}  ({100*r_pb**2:.4f}% varijanse objašnjeno bitom)")

    ci_lo, ci_hi = bootstrap_ci_mean_diff(g0, g1)
    print(f"\n  [5] Bootstrap 95% CI za Δmean: [{ci_lo:+.2f}, {ci_hi:+.2f}] ciklusa")

    n1, n2 = len(g0), len(g1)
    s1_v, s2_v = np.std(g0, ddof=1), np.std(g1, ddof=1)
    sp_v = np.sqrt(((n1-1)*s1_v**2 + (n2-1)*s2_v**2) / (n1+n2-2))
    n_req = power_analysis(abs(np.mean(g1) - np.mean(g0)), sp_v)
    print(f"\n  [6] Power analiza (α=0.05, snaga=80%):")
    print(f"      Minimalan N po grupi: {n_req:,}  |  Trenutni: {min(n1,n2):,}")
    if min(n1, n2) >= n_req:
        print(f"      → Uzorak DOVOLJAN ✓")
    else:
        print(f"      → Potrebno još {n_req - min(n1,n2):,} uzoraka ✗")

    if _report is not None:
        _report.add_heading(3, f"Statistički testovi — {label}")
        headers = ["Test", "Statistika", "p-vrijednost", "Interpretacija"]
        tbl = [
            ["Welch's t-test", f"t={t_stat:.4f}", f"{p_t:.3e}", interp_p(p_t)],
            ["Paired t-test",
             f"t={paired_t_stat:.4f}" if not np.isnan(paired_t_stat) else "N/A",
             f"{paired_p:.3e}" if not np.isnan(paired_p) else "N/A",
             interp_p(paired_p) if not np.isnan(paired_p) else "N/A"],
            ["Mann-Whitney U", f"U={u_stat:.0f}", f"{p_mw:.3e}", interp_p(p_mw)],
            ["Cohen's d", f"{d:.5f}", "—", f"{interp_d(d)} efekt"],
            ["Point-Biserial r", f"r={r_pb:.5f}, r²={r_pb**2:.6f}", f"{p_pb:.3e}",
             f"{100*r_pb**2:.4f}% varijanse"],
            ["Bootstrap 95% CI (Δmean)", f"[{ci_lo:+.2f}, {ci_hi:+.2f}] cik.", "—", ""],
            ["Power analiza N_min", f"{n_req:,}", "—",
             "DOVOLJAN ✓" if min(n1,n2) >= n_req else f"Potrebno +{n_req-min(n1,n2):,} ✗"],
        ]
        _report.add_table(headers, tbl)

    return {'t_stat': t_stat, 'p_ttest': p_t, 'cohens_d': d,
            'paired_t_stat': paired_t_stat, 'paired_p': paired_p,
            'point_biserial_r': r_pb, 'p_point_biserial': p_pb,
            'ci_lo': ci_lo, 'ci_hi': ci_hi,
            'mw_u': u_stat, 'p_mw': p_mw}


def bit_inference_attack(g0, g1, label=""):
    # simulacija timing napada: procijeni threshold, testiraj usrednjavanjem K mjerenja
    print(f"\n{'='*62}")
    print(f"  INFERENCIJA BITA — TIMING NAPAD  {label}")
    print(f"{'='*62}")

    m0, m1 = np.mean(g0), np.mean(g1)
    s0, s1 = np.std(g0, ddof=1), np.std(g1, ddof=1)
    n0, n1 = len(g0), len(g1)
    sp = np.sqrt(((n0-1)*s0**2 + (n1-1)*s1**2) / (n0+n1-2))
    print(f"\n  Mean(bit=0): {m0:.2f} cik   std: {s0:.2f}")
    print(f"  Mean(bit=1): {m1:.2f} cik   std: {s1:.2f}")
    print(f"  Δmean: {m1-m0:+.2f} ciklusa  |  SNR per uzorak: {abs(m1-m0)/sp:.4f}")

    rng_split = np.random.default_rng(123)
    g0_shuffled = rng_split.permutation(g0)
    g1_shuffled = rng_split.permutation(g1)
    n_half = min(len(g0_shuffled), len(g1_shuffled)) // 2
    train0, test0 = g0_shuffled[:n_half], g0_shuffled[n_half:]
    train1, test1 = g1_shuffled[:n_half], g1_shuffled[n_half:]
    std0_t = np.std(train0, ddof=1) + 1e-10
    std1_t = np.std(train1, ddof=1) + 1e-10
    w0, w1 = 1.0 / std0_t**2, 1.0 / std1_t**2
    threshold = (np.mean(train0) * w0 + np.mean(train1) * w1) / (w0 + w1)

    print(f"\n  Threshold (LDA-weighted):  {threshold:.2f} ciklusa")
    print()
    print(f"  {'K (avg)':>9} {'Tačnost':>9} {'CI95':>18} {'Mjerenja/bit':>13}")
    print(f"  {'-'*55}")

    rng = np.random.default_rng(42)
    results = {}
    K_values = [1, 10, 100, 500, 1000, 2000, 5000]
    best_k, best_acc = 1, 0.5
    tbl_rows = []

    for K in K_values:
        n_trials = min(2000, len(test0)//K, len(test1)//K)
        if n_trials < 20:
            continue
        c0 = c1 = 0
        for _ in range(n_trials):
            avg0 = np.mean(test0[rng.integers(0, len(test0), K)])
            avg1 = np.mean(test1[rng.integers(0, len(test1), K)])
            if avg0 <= threshold: c0 += 1
            if avg1 >  threshold: c1 += 1
        acc = (c0 + c1) / (2 * n_trials)
        results[K] = acc
        needed = K * 2
        z95 = 1.96
        n_tot = 2 * n_trials
        p_hat = acc
        denom = 1 + z95**2 / n_tot
        ci_c = (p_hat + z95**2 / (2 * n_tot)) / denom
        ci_m = z95 * np.sqrt(p_hat*(1-p_hat)/n_tot + z95**2/(4*n_tot**2)) / denom
        ci_lo_k = max(0.0, ci_c - ci_m)
        ci_hi_k = min(1.0, ci_c + ci_m)
        print(f"  {K:>9} {acc*100:>8.1f}%  [{ci_lo_k*100:.1f}%,{ci_hi_k*100:.1f}%]  {needed:>6}")
        tbl_rows.append([str(K), f"{acc*100:.1f}%",
                         f"[{ci_lo_k*100:.1f}%, {ci_hi_k*100:.1f}%]", str(needed)])
        if acc > best_acc:
            best_acc, best_k = acc, K

    print()
    snr_per = abs(m1-m0)/sp
    k_theory = 0
    if snr_per > 0:
        k_theory = int((2.0 / snr_per)**2)
        print(f"  Teorijski K_min (95% tačnost): {k_theory:,}")

    if best_acc > 0.90:
        verdict = f"NAPAD USPJEŠAN: {best_acc*100:.1f}% tačnost sa K={best_k}"
        print(f"\n  ✓ {verdict}")
    elif best_acc > 0.70:
        verdict = f"DJELIMIČAN NAPAD: {best_acc*100:.1f}% sa K={best_k}"
        print(f"\n  ~ {verdict}")
    else:
        verdict = "Signal prisutan statistički, ali usrednjavanje nedovoljno"
        print(f"\n  {verdict}")

    if _report is not None:
        _report.add_heading(3, f"Bit-inferencija (timing napad) — {label}")
        _report.add_stat_line("Mean(bit=0)", f"{m0:.2f} cik")
        _report.add_stat_line("Mean(bit=1)", f"{m1:.2f} cik")
        _report.add_stat_line("Δmean", f"{m1-m0:+.2f} cik")
        _report.add_stat_line("SNR po uzorku", f"{abs(m1-m0)/sp:.4f}")
        _report.add_stat_line("Threshold", f"{threshold:.2f} cik")
        _report.add_stat_line("Teorijski K_min (95%)", f"{k_theory:,}")
        _report.add_paragraph("")
        if tbl_rows:
            _report.add_table(["K (usrednjavanje)", "Tačnost", "CI 95%", "Mjerenja/bit"],
                              tbl_rows)
        _report.add_verdict(best_acc > 0.90, verdict)

    return {'threshold': threshold, 'overall_accuracy': best_acc,
            'best_k': best_k, 'mean_diff': m1 - m0, 'by_k': results,
            'snr_per': snr_per, 'k_theory': k_theory}


def sample_size_sensitivity(g0, g1):
    # p-vrijednost i tačnost u ovisnosti o veličini uzorka
    print(f"\n{'='*62}")
    print(f"  ANALIZA OSJETLJIVOSTI NA VELIČINU UZORKA")
    print(f"{'='*62}")

    N_values = [100, 500, 1000, 2000, 5000, 10000, 50000,
                min(100000, len(g0), len(g1))]
    N_values = sorted(set(N_values))

    rng = np.random.default_rng(77)
    tbl_rows = []
    crossings = []
    p_vals, accs, ns = [], [], []

    threshold = (np.mean(g0) + np.mean(g1)) / 2

    for N in N_values:
        if N > min(len(g0), len(g1)):
            break
        s0 = rng.choice(g0, size=N, replace=False)
        s1 = rng.choice(g1, size=N, replace=False)
        _, p = ttest_ind(s0, s1, equal_var=False)

        K = 100
        n_trials = min(500, N // K)
        acc = float('nan')
        if n_trials >= 5:
            c0 = c1 = 0
            for _ in range(n_trials):
                avg0 = np.mean(s0[rng.integers(0, N, K)])
                avg1 = np.mean(s1[rng.integers(0, N, K)])
                if avg0 <= threshold: c0 += 1
                if avg1 >  threshold: c1 += 1
            acc = (c0 + c1) / (2 * n_trials)

        p_vals.append(p)
        accs.append(acc)
        ns.append(N)
        p_str = f"{p:.2e}"
        acc_str = f"{acc*100:.1f}%" if not np.isnan(acc) else "N/A"
        sig = "✓" if p < 0.05 else "✗"
        print(f"  N={N:>7,}:  p={p_str}  {sig}  acc@K=100={acc_str}")
        tbl_rows.append([f"{N:,}", p_str, sig, acc_str])
        if p < 0.05 and not crossings:
            crossings.append(N)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("Osjetljivost na veličinu uzorka: p-vrijednost i tačnost vs N",
                 fontsize=12, fontweight='bold')

    valid_p = [(n, p) for n, p in zip(ns, p_vals) if p > 0]
    if valid_p:
        xp, yp = zip(*valid_p)
        ax1.loglog(xp, yp, 'o-', color='#9C27B0', lw=2, ms=7)
        ax1.axhline(0.05, color='red', ls='--', lw=1.5, label='p=0.05')
        ax1.set_xlabel("N uzoraka po grupi (log)")
        ax1.set_ylabel("p-vrijednost (log)")
        ax1.set_title("p-vrijednost vs N")
        ax1.legend()

    valid_a = [(n, a) for n, a in zip(ns, accs) if not np.isnan(a)]
    if valid_a:
        xa, ya = zip(*valid_a)
        ax2.semilogx(xa, [v*100 for v in ya], 's-', color='#FF5722', lw=2, ms=7,
                     label='Tačnost @K=100')
        ax2.axhline(90, color='green', ls=':', lw=1.5, label='Cilj 90%')
        ax2.axhline(50, color='gray', ls='--', lw=1.5, label='Slučajno 50%')
        ax2.set_xlabel("N uzoraka po grupi (log)")
        ax2.set_ylabel("Tačnost napada (%)")
        ax2.set_title("Tačnost @K=100 vs N")
        ax2.set_ylim(40, 105)
        ax2.legend()

    plt.tight_layout()
    plt.savefig('plot_sample_sensitivity.png', bbox_inches='tight')
    plt.close()
    print("  → plot_sample_sensitivity.png")

    if _report is not None:
        _report.add_heading(3, "Osjetljivost na veličinu uzorka")
        _report.add_table(["N uzoraka", "p-vrijednost", "Significantno?", "Tačnost @K=100"],
                         tbl_rows)
        if crossings:
            _report.add_stat_line("Najmanji N za p<0.05", f"{crossings[0]:,}")
        _report.add_stat_line("Plot", "`plot_sample_sensitivity.png`")

    return {'p_values': dict(zip(ns, p_vals)), 'accuracies': dict(zip(ns, accs))}


def plot_all(g0_v, g1_v, g0_c, g1_c, df_vuln, df_ct, sv, sc, iv):
    # distribucije ranjive implementacije
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(f'RSA Timing Side-Channel — Ranjiva Implementacija\n'
                 f'(Ciljani bit={TARGET_BIT}, N={len(g0_v)+len(g1_v):,})',
                 fontsize=13, fontweight='bold')

    ax = axes[0,0]
    bins = min(100, int(np.sqrt(min(len(g0_v), len(g1_v)))))
    ax.hist(g0_v, bins=bins, density=True, alpha=0.6, color=COLORS['bit0'], label='bit=0')
    ax.hist(g1_v, bins=bins, density=True, alpha=0.6, color=COLORS['bit1'], label='bit=1')
    ax.axvline(np.mean(g0_v), color=COLORS['bit0'], ls='--', lw=2,
               label=f"Mean(0)={np.mean(g0_v):.0f}")
    ax.axvline(np.mean(g1_v), color=COLORS['bit1'], ls='--', lw=2,
               label=f"Mean(1)={np.mean(g1_v):.0f}")
    ax.set_xlabel('CPU Ciklusi')
    ax.set_ylabel('Gustoća')
    ax.set_title('Histogram: bit=0 vs bit=1')
    ax.legend(fontsize=9)

    ax = axes[0,1]
    bp = ax.boxplot([g0_v, g1_v], patch_artist=True, labels=['bit=0','bit=1'],
                    medianprops={'color':'black','lw':2},
                    flierprops={'marker':'.','ms':2,'alpha':0.2}, notch=True)
    bp['boxes'][0].set(facecolor=COLORS['bit0'], alpha=0.7)
    bp['boxes'][1].set(facecolor=COLORS['bit1'], alpha=0.7)
    ax.set_ylabel('CPU Ciklusi')
    ax.set_title(f"Boxplot  (Δmean={np.mean(g1_v)-np.mean(g0_v):+.1f} cik.)")

    ax = axes[1,0]
    for grp, col, lbl in [(g0_v,COLORS['bit0'],'bit=0'),(g1_v,COLORS['bit1'],'bit=1')]:
        s = np.sort(grp)
        ax.plot(s, np.arange(1,len(s)+1)/len(s), color=col, label=lbl, lw=1.5)
    ax.axhline(0.5, color='gray', ls=':', alpha=0.6, label='Medijana 50%')
    ax.set_xlabel('CPU Ciklusi')
    ax.set_ylabel('Kumulativna vjerovatnoća')
    ax.set_title('CDF: horizontalni pomak = timing leak')
    ax.legend(fontsize=9)

    ax = axes[1,1]
    ax.axis('off')
    lines = [
        "STATISTIČKI SAŽETAK",
        "─" * 28,
        f"Welch t    : {sv['t_stat']:.2f}",
        f"p (t-test) : {sv['p_ttest']:.2e}",
        f"p (M-W U)  : {sv['p_mw']:.2e}",
        f"Cohen's d  : {sv['cohens_d']:.5f}",
        f"PB-r       : {sv['point_biserial_r']:.5f}",
        "",
        f"Mean(bit=0): {np.mean(g0_v):.1f} cik.",
        f"Mean(bit=1): {np.mean(g1_v):.1f} cik.",
        f"Δmean      : {np.mean(g1_v)-np.mean(g0_v):+.2f} cik.",
        "",
        "→ LEAK DOKAZAN" if sv['p_mw'] < 1e-10 else "→ Signal slab",
    ]
    ax.text(0.05, 0.95, "\n".join(lines), transform=ax.transAxes, fontsize=10,
            va='top', fontfamily='monospace',
            bbox=dict(boxstyle='round', facecolor='#FFFDE7', alpha=0.9))

    plt.tight_layout()
    plt.savefig('plot_vulnerable_analysis.png', bbox_inches='tight')
    plt.close()
    print("  → plot_vulnerable_analysis.png")

    # distribucija parnih razlika: ranjiva vs constant-time
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('Dokaz eliminacije timing side-channel-a:\n'
                 'Ranjiva vs Constant-Time implementacija', fontsize=13, fontweight='bold')

    def paired_diff(df):
        d0 = df[df['bit_value']==0][['iteration','cycles']].rename(columns={'cycles':'c0'})
        d1 = df[df['bit_value']==1][['iteration','cycles']].rename(columns={'cycles':'c1'})
        m = pd.merge(d0, d1, on='iteration')
        return (m['c1'] - m['c0']).values

    dv = paired_diff(df_vuln)
    dc = paired_diff(df_ct)

    lo = np.percentile(np.concatenate([dv,dc]), 2)
    hi = np.percentile(np.concatenate([dv,dc]), 98)
    bins = np.linspace(lo, hi, 80)

    ax = axes[0]
    ax.hist(dv, bins=bins, density=True, alpha=0.7, color=COLORS['bit1'], label='Ranjiva')
    ax.hist(dc, bins=bins, density=True, alpha=0.7, color=COLORS['ct'],   label='Constant-Time')
    ax.axvline(0, color='black', lw=2, label='Nula (nema razlike)')
    ax.axvline(np.mean(dv), color=COLORS['bit1'], ls='--', lw=2,
               label=f"Mean(vuln)={np.mean(dv):+.1f}")
    ax.axvline(np.mean(dc), color=COLORS['ct'], ls='--', lw=2,
               label=f"Mean(CT)={np.mean(dc):+.1f}")
    ax.set_xlabel('ciklusi(bit=1) - ciklusi(bit=0)')
    ax.set_ylabel('Gustoća')
    ax.set_title('Distribucija parnih razlika\nLeak: distribucija nije na nuli')
    ax.legend(fontsize=9)

    ax = axes[1]
    bp = ax.boxplot([dv, dc], patch_artist=True, notch=True,
                    labels=['Ranjiva\n(ima leak)', 'Constant-Time\n(nema leaka)'],
                    medianprops={'color':'black','lw':2.5},
                    flierprops={'marker':'.','ms':2,'alpha':0.15})
    bp['boxes'][0].set(facecolor=COLORS['bit1'], alpha=0.7)
    bp['boxes'][1].set(facecolor=COLORS['ct'], alpha=0.7)
    ax.axhline(0, color='black', ls='--', lw=1.5, label='Nula = bez razlike')
    ax.set_ylabel('ciklusi(bit=1) - ciklusi(bit=0)')
    ax.set_title('Boxplot: median pomak\nRanjiva≠0, CT≈0 → eliminacija dokazana')
    ax.legend(fontsize=9)

    for i, (data, xpos) in enumerate([(dv,1),(dc,2)]):
        med = np.median(data)
        ax.annotate(f'Med={med:+.0f}', xy=(xpos, med), xytext=(xpos+0.3, med),
                    fontsize=9, arrowprops=dict(arrowstyle='->', color='black'),
                    bbox=dict(boxstyle='round', fc='white', alpha=0.8))

    plt.tight_layout()
    plt.savefig('plot_comparison.png', bbox_inches='tight')
    plt.close()
    print("  → plot_comparison.png")

    # tačnost napada u ovisnosti o broju usrednjenih mjerenja
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('Timing Napad: Tačnost raste sa usrednjavanjem mjerenja',
                 fontsize=13, fontweight='bold')

    ax = axes[0]
    n_show = min(3000, len(g0_v), len(g1_v))
    ax.scatter(range(n_show), g0_v[:n_show], c=COLORS['bit0'], alpha=0.2, s=3, label='bit=0')
    ax.scatter(range(n_show), g1_v[:n_show], c=COLORS['bit1'], alpha=0.2, s=3, label='bit=1')
    thr = iv.get('threshold', (np.mean(g0_v)+np.mean(g1_v))/2)
    ax.axhline(thr, color='black', ls='--', lw=2, label=f'Threshold={thr:.0f}')
    ax.axhline(np.mean(g0_v), color=COLORS['bit0'], ls=':', lw=1.5)
    ax.axhline(np.mean(g1_v), color=COLORS['bit1'], ls=':', lw=1.5)
    ax.set_xlabel('Indeks uzorka')
    ax.set_ylabel('CPU Ciklusi')
    ax.set_title(f'Scatter: prvih {n_show} mjerenja')
    ax.legend(fontsize=8, markerscale=5)

    ax = axes[1]
    by_k = iv.get('by_k', {})
    if by_k:
        ks = sorted(by_k.keys())
        accs = [by_k[k]*100 for k in ks]
        ax.semilogx(ks, accs, 'o-', color='#9C27B0', lw=2.5, ms=8, label='Tačnost napada')
        ax.axhline(50, color='gray', ls='--', lw=1.5, label='Slučajno (50%)')
        ax.axhline(90, color='green', ls=':', lw=1.5, label='Cilj: 90%')
        for k, acc in zip(ks, accs):
            ax.annotate(f'{acc:.0f}%', (k, acc), textcoords='offset points',
                        xytext=(0, 8), ha='center', fontsize=9)
    ax.set_xlabel('K (broj usrednjenih mjerenja po klasifikaciji)')
    ax.set_ylabel('Tačnost napada (%)')
    ax.set_title('Averaging napad: tačnost vs K')
    ax.set_ylim(40, 105)
    ax.legend(fontsize=9)

    plt.tight_layout()
    plt.savefig('plot_inference_attack.png', bbox_inches='tight')
    plt.close()
    print("  → plot_inference_attack.png")

    if _report is not None:
        _report.add_heading(3, "Generisani grafici")
        _report.add_paragraph("- `plot_vulnerable_analysis.png`")
        _report.add_paragraph("- `plot_comparison.png`")
        _report.add_paragraph("- `plot_inference_attack.png`")
        _report.add_paragraph("- `plot_sample_sensitivity.png`")


def validation_summary(sv, sc, iv, ic):
    print(f"\n{'='*62}")
    print(f"  VALIDACIJA EKSPERIMENTA")
    print(f"{'='*62}")
    checks = [
        ("Timing leak postoji (p_MW < 1e-10)",      sv['p_mw'] < 1e-10),
        ("T-test statistički značajan (p < 0.01)",   sv['p_ttest'] < 0.01),
        ("Efekt mjerljiv (|Cohen's d| > 0.01)",      abs(sv['cohens_d']) > 0.01),
        ("Napad uspješan sa avg (acc > 70%)",        iv['overall_accuracy'] > 0.70),
        ("CT eliminiše leak (p_MW > 0.05)",          sc['p_mw'] > 0.05),
        ("CT bez efekta (|d| < 0.05)",               abs(sc['cohens_d']) < 0.05),
        ("CT napad neuspješan (acc < 60%)",          ic['overall_accuracy'] < 0.60),
    ]
    all_ok = True
    for name, result in checks:
        print(f"  {'✓' if result else '✗'}  {name}")
        if not result: all_ok = False
    print()
    if all_ok:
        print("  ✓✓ SVI KRITERIJUMI ISPUNJENI — Eksperiment VALIDAN")
    else:
        print("  Napomena: neke provjere nisu prošle.")

    if _report is not None:
        _report.add_heading(3, "Validacija eksperimenta")
        for name, result in checks:
            _report.add_verdict(result, name)
        _report.add_paragraph("")
        _report.add_verdict(all_ok,
                           "SVI KRITERIJUMI ISPUNJENI — Eksperiment VALIDAN" if all_ok
                           else "Neki kriterijumi nisu ispunjeni")


def main():
    global _report

    print("=" * 62)
    print("  RSA Timing Side-Channel — Statistička Analiza")
    print("=" * 62)

    meta = {}
    if os.path.exists("experiment_meta.json"):
        with open("experiment_meta.json") as f:
            meta = json.load(f)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    _report = MarkdownReport("RSA Timing Side-Channel — Analiza Rezultata")
    sys_meta = get_metadata()

    _report.add_heading(2, "Metapodaci")
    _report.add_stat_line("Generisano", sys_meta['timestamp'])
    _report.add_stat_line("Platforma", sys_meta['platform'])
    _report.add_stat_line("Python", sys_meta['python'])
    _report.add_stat_line("Ciljani bit (TARGET_BIT)",
                         meta.get('target_bit', TARGET_BIT))
    _report.add_stat_line("Eksponent bita (EXP_BITS)", meta.get('exp_bits', 64))
    _report.add_stat_line("Broj uzoraka (NUM_SAMPLES)", meta.get('num_samples', 'N/A'))
    if 'prng_seed' in meta:
        _report.add_stat_line("PRNG seed", meta['prng_seed'])

    print("\n[1] Učitavanje i filtriranje podataka...")
    _report.add_heading(2, "Učitavanje podataka")
    df_vuln = load_and_filter(FILE_VULNERABLE, "VULNERABLE")
    df_ct   = load_and_filter(FILE_CONSTANT,   "CONSTANT-TIME")

    g0_v = df_vuln[df_vuln['bit_value']==0]['cycles'].values
    g1_v = df_vuln[df_vuln['bit_value']==1]['cycles'].values
    g0_c = df_ct[df_ct['bit_value']==0]['cycles'].values
    g1_c = df_ct[df_ct['bit_value']==1]['cycles'].values

    print("\n[2] Deskriptivna statistika...")
    _report.add_heading(2, "Deskriptivna statistika")
    descriptive_stats(g0_v, g1_v, "RANJIVA IMPLEMENTACIJA")
    descriptive_stats(g0_c, g1_c, "CONSTANT-TIME IMPLEMENTACIJA")

    print("\n[3] Statistički testovi...")
    _report.add_heading(2, "Statistički testovi")
    sv = statistical_tests(g0_v, g1_v, "RANJIVA", df=df_vuln)
    sc = statistical_tests(g0_c, g1_c, "CONSTANT-TIME", df=df_ct)

    print("\n[4] Inferencija bita (napad)...")
    _report.add_heading(2, "Timing napad — bit inferencija")
    iv = bit_inference_attack(g0_v, g1_v, "— Ranjiva")
    ic = bit_inference_attack(g0_c, g1_c, "— Constant-Time (kontrola)")

    print("\n[5] Osjetljivost na veličinu uzorka...")
    _report.add_heading(2, "Osjetljivost na veličinu uzorka")
    sample_size_sensitivity(g0_v, g1_v)

    print("\n[6] Generisanje grafika...")
    _report.add_heading(2, "Grafici")
    plot_all(g0_v, g1_v, g0_c, g1_c, df_vuln, df_ct, sv, sc, iv)

    _report.add_heading(2, "Validacija")
    validation_summary(sv, sc, iv, ic)

    os.makedirs("reports", exist_ok=True)
    report_path = f"reports/analysis_{ts}.md"
    latest_path = "reports/analysis_latest.md"
    _report.save(report_path)
    _report.save(latest_path)
    print(f"\n  → Izvještaj: {report_path}")
    print(f"  → Izvještaj: {latest_path}")

    pdf = try_convert_to_pdf(report_path)
    if pdf:
        print(f"  → PDF: {pdf}")

    print(f"\n{'='*62}")
    print("  Grafici: plot_vulnerable_analysis.png")
    print("           plot_comparison.png")
    print("           plot_inference_attack.png")
    print("           plot_sample_sensitivity.png")
    print(f"{'='*62}")

if __name__ == '__main__':
    main()
