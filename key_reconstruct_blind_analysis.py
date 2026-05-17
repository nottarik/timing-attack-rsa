#!/usr/bin/env python3
# Vizualizacija slijepe rekonstrukcije RSA ključa iz key_reconstruction_blind.csv

import sys, os, json, re
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import matplotlib.patches as mpatches
from matplotlib.colors import ListedColormap
from datetime import datetime

from report_utils import MarkdownReport, get_metadata, try_convert_to_pdf

FILE_IN  = "key_reconstruction_blind.csv"
META_IN  = "key_reconstruction_blind_meta.json"
NUM_BITS = 64
K_SAMPLES = 5000

plt.rcParams.update({
    'figure.dpi': 150, 'font.size': 10,
    'axes.titlesize': 12, 'axes.labelsize': 11,
    'axes.grid': True, 'grid.alpha': 0.3,
})

if not os.path.exists(FILE_IN):
    print(f"[GREŠKA] Fajl {FILE_IN} nije pronađen.")
    print("         Pokreni: taskset -c 0 ./key_reconstruct_blind")
    sys.exit(1)

# izvlači tajni ključ iz validacijskog bloka na kraju CSV-a
actual_secret = None
reconstructed_from_comment = None

with open(FILE_IN, encoding='utf-8') as fh:
    for line in fh:
        line = line.strip()
        m = re.match(r'#\s*Tajni kljuc:\s*(0x[0-9A-Fa-f]+)', line)
        if m:
            actual_secret = int(m.group(1), 16)
        m = re.match(r'#\s*Rekonstruisan:\s*(0x[0-9A-Fa-f]+)', line)
        if m:
            reconstructed_from_comment = int(m.group(1), 16)

if actual_secret is None:
    print(f"[GREŠKA] Validacijski blok nije pronađen u {FILE_IN}.")
    sys.exit(1)

df = pd.read_csv(FILE_IN, comment='#')
df = df.sort_values('bit_position', ascending=False).reset_index(drop=True)

bit_positions  = df['bit_position'].values.astype(int)
inferred_bits  = df['inferred_bit'].values.astype(int)
deltas         = df['delta_cycles'].values.astype(float)
t_stats        = df['t_stat'].values.astype(float)
mean_secret_v  = df['mean_secret'].values.astype(float)
mean_perturbed = df['mean_perturbed'].values.astype(float)

# post-hoc: actual_bit i correct računaju se tek ovdje
actual_bits = np.array([(actual_secret >> int(b)) & 1 for b in bit_positions], dtype=int)
correct     = (inferred_bits == actual_bits)

reconstructed_key = 0
for i, b in enumerate(bit_positions):
    reconstructed_key |= (int(inferred_bits[i]) << int(b))

correct_count = int(correct.sum())
total_bits    = len(df)
accuracy      = correct_count / total_bits * 100

meta = {}
if os.path.exists(META_IN):
    with open(META_IN) as fh:
        meta = json.load(fh)
    K_SAMPLES = meta.get('k_samples', K_SAMPLES)

print(f"Tajni ključ:     0x{actual_secret:016X}")
print(f"Rekonstruisani:  0x{reconstructed_key:016X}")
print(f"Tačnost:         {correct_count}/{total_bits} bita ({accuracy:.1f}%)")

fig = plt.figure(figsize=(16, 14))
fig.patch.set_facecolor('#FAFAFA')
gs = gridspec.GridSpec(3, 2, figure=fig, hspace=0.45, wspace=0.35)

CORRECT_COLOR = '#388E3C'
WRONG_COLOR   = '#D32F2F'

# delta ciklusi po bitu
ax1 = fig.add_subplot(gs[0, :])

colors_bar = [CORRECT_COLOR if c else WRONG_COLOR for c in correct]
ax1.bar(range(total_bits), deltas, color=colors_bar, edgecolor='white',
        linewidth=0.5, alpha=0.85)

ax1.axhline(0, color='black', linewidth=1.5, linestyle='--', alpha=0.7,
            label='Nula (nema razlike)')

for i, (b, d, c) in enumerate(zip(bit_positions, deltas, correct)):
    if not c:
        ax1.annotate(f'b{int(b)}\n✗', xy=(i, d),
                     xytext=(i, d + (20 if d > 0 else -40)),
                     ha='center', fontsize=7, color=WRONG_COLOR, fontweight='bold')

ax1.set_xticks(range(total_bits))
ax1.set_xticklabels([str(int(b)) for b in bit_positions], fontsize=7, rotation=45)
ax1.set_xlabel('Bit pozicija eksponenta (MSB → LSB)')
ax1.set_ylabel('Δ ciklusa (T(S) − T(S ⊕ mask))')
ax1.set_title(
    f'Slijepi napad — signal po bitu: Δ = mean(T_tajni) − mean(T_perturbiran)\n'
    f'Δ > 0 → bit=1  |  Δ < 0 → bit=0  |  '
    f'Tačnost (post-hoc): {correct_count}/{total_bits} = {accuracy:.0f}%',
    fontsize=11
)
patch_ok    = mpatches.Patch(color=CORRECT_COLOR, label=f'Tačno ({correct_count} bita)')
patch_wrong = mpatches.Patch(color=WRONG_COLOR,   label=f'Pogrešno ({total_bits - correct_count} bita)')
ax1.legend(handles=[patch_ok, patch_wrong], loc='upper right', fontsize=9)
ax1.set_xlim(-0.5, total_bits - 0.5)

# bit-po-bit heatmap (post-hoc)
ax2 = fig.add_subplot(gs[1, :])

status_colors = np.zeros(total_bits)
for i in range(total_bits):
    if correct[i]:
        status_colors[i] = inferred_bits[i]
    else:
        status_colors[i] = 2 + inferred_bits[i]

combined = np.vstack([actual_bits, inferred_bits, status_colors])
cmap4 = ListedColormap(['#BBDEFB', '#A5D6A7', '#FFF176', '#FFCDD2'])
ax2.imshow(combined, aspect='auto', cmap=cmap4, vmin=0, vmax=3, interpolation='nearest')

ax2.set_yticks([0, 1, 2])
ax2.set_yticklabels(['Tajni ključ\n(post-hoc)', 'Rekonstruisani\n(napad)', 'Status'], fontsize=9)
ax2.set_xticks(range(total_bits))
ax2.set_xticklabels([str(int(b)) for b in bit_positions], fontsize=7, rotation=45)
ax2.set_xlabel('Bit pozicija')
ax2.set_title(
    f'Bit-po-bit usporedba (post-hoc validacija)\n'
    f'Tajni: 0x{actual_secret:016X}  |  Rekonstruisan: 0x{reconstructed_key:016X}',
    fontsize=11
)

for col in range(total_bits):
    for row in [0, 1]:
        val = int(combined[row, col])
        ax2.text(col, row, str(val), ha='center', va='center',
                 fontsize=7, fontweight='bold', color='black')

legend_patches = [
    mpatches.Patch(color='#BBDEFB', label='bit=0, tačno'),
    mpatches.Patch(color='#A5D6A7', label='bit=1, tačno'),
    mpatches.Patch(color='#FFF176', label='bit=0, pogrešno'),
    mpatches.Patch(color='#FFCDD2', label='bit=1, pogrešno'),
]
ax2.legend(handles=legend_patches, loc='upper right',
           bbox_to_anchor=(1.0, -0.25), ncol=4, fontsize=8)

# distribucija delta vrijednosti po stvarnoj vrijednosti bita
ax3 = fig.add_subplot(gs[2, 0])

delta_ones  = deltas[actual_bits == 1]
delta_zeros = deltas[actual_bits == 0]

bins = np.linspace(deltas.min() - 10, deltas.max() + 10, 25)
ax3.hist(delta_zeros, bins=bins, alpha=0.7, color='#2196F3',
         label=f'bit=0 pozicije (n={len(delta_zeros)})', density=True)
ax3.hist(delta_ones,  bins=bins, alpha=0.7, color='#F44336',
         label=f'bit=1 pozicije (n={len(delta_ones)})', density=True)
ax3.axvline(0, color='black', lw=2, ls='--', label='Δ=0 (threshold)')
ax3.axvline(np.mean(delta_zeros), color='#2196F3', lw=1.5, ls=':',
            label=f'Mean(Δ|bit=0)={np.mean(delta_zeros):.1f}')
ax3.axvline(np.mean(delta_ones),  color='#F44336', lw=1.5, ls=':',
            label=f'Mean(Δ|bit=1)={np.mean(delta_ones):.1f}')
ax3.set_xlabel('Δ ciklusa (T_tajni − T_perturbiran)')
ax3.set_ylabel('Gustoća')
ax3.set_title('Distribucija Δ signala po stvarnoj vrijednosti bita\n(post-hoc)')
ax3.legend(fontsize=8)

# sažetak
ax4 = fig.add_subplot(gs[2, 1])
ax4.axis('off')

key_match = (reconstructed_key == actual_secret)

summary_lines = [
    "=== SAZETAK SLIJEPOG NAPADA ==========",
    "",
    f"  Tajni kljuc:   0x{actual_secret:016X}",
    f"  Rekonstruisan: 0x{reconstructed_key:016X}",
    f"  XOR razlika:   0x{actual_secret ^ reconstructed_key:016X}",
    "",
    f"  Tacni biti:  {correct_count:2d} / {total_bits}",
    f"  Tacnost:     {accuracy:.1f}%",
    f"  K po bitu:   {K_SAMPLES} mjerenja",
    "",
    f"  D mean (bit=1 poz.): {np.mean(delta_ones):+.1f} cik",
    f"  D mean (bit=0 poz.): {np.mean(delta_zeros):+.1f} cik",
    f"  Mean |D|:            {np.mean(np.abs(deltas)):.1f} cik",
    "",
    "  =======================================",
    f"  {'SLIJEP NAPAD USPIO -- kljuc rekonstruisan!' if key_match else '~ Djelimican uspjeh'}",
    "",
    "  Model: chosen-perturbation oracle",
]

edge_col = '#1B5E20' if key_match else '#B71C1C'
ax4.text(0.03, 0.97, "\n".join(summary_lines), transform=ax4.transAxes,
         fontsize=9, va='top', fontfamily='monospace', color='black',
         bbox=dict(boxstyle='round',
                   facecolor='#F1F8E9' if key_match else '#FFEBEE',
                   edgecolor=edge_col, alpha=0.95, linewidth=2))

fig.suptitle(
    f'RSA Timing Side-Channel — Slijepa rekonstrukcija {NUM_BITS}-bitnog privatnog ključa\n'
    f'Tajni ključ: 0x{actual_secret:016X}  |  Rekonstruisan: 0x{reconstructed_key:016X}  |  '
    f'Tačnost: {correct_count}/{total_bits} bita ({accuracy:.0f}%)',
    fontsize=13, fontweight='bold', y=0.98
)

plt.savefig('plot_key_reconstruction_blind.png', bbox_inches='tight', facecolor='#FAFAFA')
plt.close()

print("\n→ Grafik sačuvan: plot_key_reconstruction_blind.png")
print(f"\nRezultat: {'POTPUNA SLIJEPA REKONSTRUKCIJA' if key_match else f'Djelimicno: {correct_count}/{total_bits} bita'}")

ts_str   = datetime.now().strftime("%Y%m%d_%H%M%S")
sys_meta = get_metadata()

report = MarkdownReport(
    f"RSA Timing Side-Channel — Slijepa rekonstrukcija {NUM_BITS}-bitnog ključa"
)

report.add_heading(2, "Metapodaci")
report.add_stat_line("Generisano", sys_meta['timestamp'])
report.add_stat_line("Platforma", sys_meta['platform'])
report.add_stat_line("Mod napada", "Slijepi (chosen-perturbation oracle)")
report.add_stat_line("Tajni ključ (post-hoc)", f"0x{actual_secret:016X}")
report.add_stat_line("Rekonstruisani ključ", f"0x{reconstructed_key:016X}")
report.add_stat_line("XOR razlika", f"0x{actual_secret ^ reconstructed_key:016X}")
report.add_stat_line("Broj bita (NUM_BITS)", NUM_BITS)
report.add_stat_line("K uzoraka po bitu", meta.get('k_samples', K_SAMPLES))
if 'prng_seed' in meta:
    report.add_stat_line("PRNG seed (napadač)", meta['prng_seed'])
if 'total_skipped' in meta:
    report.add_stat_line("Ukupno skipovano parova", meta['total_skipped'])
if 'total_retried' in meta:
    report.add_stat_line("Retried bita (|t| < 2.5)", meta['total_retried'])

report.add_heading(2, "Bit-po-bit rezultati (post-hoc)")
headers = ["Bit poz.", "Inferred bit", "Actual bit", "Δ ciklusa", "t-stat", "Tačno?", "|Δ|"]
tbl = []
for i in range(total_bits):
    bp  = int(bit_positions[i])
    ib  = int(inferred_bits[i])
    ab  = int(actual_bits[i])
    d   = float(deltas[i])
    ts_ = float(t_stats[i])
    c   = bool(correct[i])
    tbl.append([str(bp), str(ib), str(ab),
                f"{d:+.2f}", f"{ts_:+.3f}",
                "✓" if c else "✗",
                f"{abs(d):.2f}"])
report.add_table(headers, tbl)

report.add_heading(2, "Statistički sažetak")
report.add_stat_line("Tačnih bita", f"{correct_count}/{total_bits} ({accuracy:.1f}%)")
report.add_stat_line("Mean |Δ| (sve pozicije)", f"{np.mean(np.abs(deltas)):.1f} cik")
report.add_stat_line("Mean Δ (bit=1 poz.)", f"{np.mean(delta_ones):+.1f} cik")
report.add_stat_line("Mean Δ (bit=0 poz.)", f"{np.mean(delta_zeros):+.1f} cik")

abs_d = np.abs(deltas)
min_idx = int(np.argmin(abs_d))
max_idx = int(np.argmax(abs_d))
report.add_stat_line("Min |Δ|",
                     f"{abs_d[min_idx]:.1f} cik (bit {bit_positions[min_idx]}, "
                     f"t={t_stats[min_idx]:+.3f})")
report.add_stat_line("Max |Δ|",
                     f"{abs_d[max_idx]:.1f} cik (bit {bit_positions[max_idx]}, "
                     f"t={t_stats[max_idx]:+.3f})")

wrong_bits = [int(bit_positions[i]) for i in range(total_bits) if not correct[i]]
if wrong_bits:
    report.add_heading(3, "Analiza grešaka")
    report.add_paragraph(f"Pogrešno klasifikovani biti: {wrong_bits}")
    for wp in wrong_bits:
        idx = list(bit_positions).index(wp)
        report.add_stat_line(f"  Bit {wp}",
                             f"Δ={deltas[idx]:+.2f} cik, t={t_stats[idx]:+.3f}")

report.add_heading(2, "Zaključak")
if key_match:
    report.add_verdict(True,
        "POTPUNA SLIJEPA REKONSTRUKCIJA — svih 64 bita tačno rekonstruisano")
    report.add_paragraph(
        "Napadački kod nikada nije pristupio vrijednosti tajnog ključa. "
        "Rekonstrukcija je izvedena isključivo iz timing razlika."
    )
elif accuracy >= 90:
    report.add_verdict(False, f"DJELIMIČNA REKONSTRUKCIJA — {accuracy:.1f}% tačnost")
else:
    report.add_verdict(False, f"NEUSPJEŠNA REKONSTRUKCIJA — {accuracy:.1f}% tačnost")

report.add_heading(2, "Generisani grafici")
report.add_paragraph("- `plot_key_reconstruction_blind.png`")

os.makedirs("reports", exist_ok=True)
report_path = f"reports/key_reconstruction_blind_{ts_str}.md"
latest_path = "reports/key_reconstruction_blind_latest.md"
report.save(report_path)
report.save(latest_path)
print(f"\n→ Izvještaj: {report_path}")
print(f"→ Izvještaj: {latest_path}")

pdf = try_convert_to_pdf(report_path)
if pdf:
    print(f"→ PDF: {pdf}")
