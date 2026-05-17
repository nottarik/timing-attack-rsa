#!/usr/bin/env python3
# Vizualizacija rekonstrukcije RSA privatnog ključa iz key_reconstruction.csv

import sys, os, json
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

FILE_IN    = "key_reconstruction.csv"
SECRET_KEY = 0xDEADBEEFCAFEBABE
NUM_BITS   = 64
K_SAMPLES  = 5000

plt.rcParams.update({
    'figure.dpi': 150, 'font.size': 10,
    'axes.titlesize': 12, 'axes.labelsize': 11,
    'axes.grid': True, 'grid.alpha': 0.3,
})

if not os.path.exists(FILE_IN):
    print(f"[GREŠKA] Fajl {FILE_IN} nije pronađen.")
    print("         Pokreni: taskset -c 0 ./key_reconstruct")
    sys.exit(1)

df = pd.read_csv(FILE_IN)
df = df.sort_values('bit_position', ascending=False).reset_index(drop=True)

actual_bits     = df['actual_bit'].values
inferred_bits   = df['inferred_bit'].values
deltas          = df['delta_cycles'].values
correct         = df['correct'].values
bit_positions   = df['bit_position'].values

reconstructed_key = 0
for i, b in enumerate(bit_positions):
    reconstructed_key |= (int(inferred_bits[i]) << int(b))

correct_count = int(correct.sum())
total_bits    = len(df)
accuracy      = correct_count / total_bits * 100

print(f"Tajni ključ:     0x{SECRET_KEY:016X}")
print(f"Rekonstruisani:  0x{reconstructed_key:016X}")
print(f"Tačnost:         {correct_count}/{total_bits} bita ({accuracy:.1f}%)")

fig = plt.figure(figsize=(16, 14))
fig.patch.set_facecolor('#FAFAFA')
gs = gridspec.GridSpec(3, 2, figure=fig, hspace=0.45, wspace=0.35)

CORRECT_COLOR = '#388E3C'
WRONG_COLOR   = '#D32F2F'
ZERO_COLOR    = '#90CAF9'
ONE_COLOR     = '#EF9A9A'

# delta ciklusi po bitu
ax1 = fig.add_subplot(gs[0, :])

colors_bar = [CORRECT_COLOR if c else WRONG_COLOR for c in correct]
bars = ax1.bar(range(total_bits), deltas, color=colors_bar, edgecolor='white',
               linewidth=0.5, alpha=0.85)

ax1.axhline(0, color='black', linewidth=1.5, linestyle='--', alpha=0.7,
            label='Nula (nema razlike)')
ax1.axhline(+30, color='orange', linewidth=1, linestyle=':', alpha=0.6)
ax1.axhline(-30, color='orange', linewidth=1, linestyle=':', alpha=0.6)

for i, (b, d, c) in enumerate(zip(bit_positions, deltas, correct)):
    if not c:
        ax1.annotate(f'b{int(b)}\n✗', xy=(i, d),
                     xytext=(i, d + (20 if d > 0 else -40)),
                     ha='center', fontsize=7, color=WRONG_COLOR, fontweight='bold')

ax1.set_xticks(range(total_bits))
ax1.set_xticklabels([str(int(b)) for b in bit_positions], fontsize=7, rotation=45)
ax1.set_xlabel('Bit pozicija eksponenta (MSB → LSB)')
ax1.set_ylabel('Δ ciklusa (orig − flip)')
ax1.set_title(
    f'Signal napada po bitu: Δ = mean(timing_original) − mean(timing_flipped)\n'
    f'Δ > 0 → bit=1  |  Δ < 0 → bit=0  |  '
    f'Tačnost: {correct_count}/{total_bits} = {accuracy:.0f}%',
    fontsize=11
)
patch_ok    = mpatches.Patch(color=CORRECT_COLOR, label=f'Tačno ({correct_count} bita)')
patch_wrong = mpatches.Patch(color=WRONG_COLOR,   label=f'Pogrešno ({total_bits-correct_count} bita)')
ax1.legend(handles=[patch_ok, patch_wrong], loc='upper right', fontsize=9)
ax1.set_xlim(-0.5, total_bits - 0.5)

# bit-po-bit heatmap
ax2 = fig.add_subplot(gs[1, :])

data_secret  = np.array([int((SECRET_KEY >> int(b)) & 1) for b in bit_positions])
data_inferred = inferred_bits.astype(int)
data_correct  = correct.astype(int)

status_colors = np.zeros(total_bits)
for i in range(total_bits):
    if data_correct[i]:
        status_colors[i] = data_inferred[i]
    else:
        status_colors[i] = 2 + data_inferred[i]

combined = np.vstack([data_secret, data_inferred, status_colors])

cmap4 = ListedColormap(['#BBDEFB', '#A5D6A7', '#FFF176', '#FFCDD2'])

im = ax2.imshow(combined, aspect='auto', cmap=cmap4, vmin=0, vmax=3,
                interpolation='nearest')

ax2.set_yticks([0, 1, 2])
ax2.set_yticklabels(['Tajni ključ', 'Rekonstruisani', 'Status'], fontsize=10)
ax2.set_xticks(range(total_bits))
ax2.set_xticklabels([str(int(b)) for b in bit_positions], fontsize=7, rotation=45)
ax2.set_xlabel('Bit pozicija')
ax2.set_title(
    f'Bit-po-bit usporedba: tajni ključ vs rekonstruisani  '
    f'[0x{SECRET_KEY:016X} vs 0x{reconstructed_key:016X}]',
    fontsize=11
)

for col in range(total_bits):
    for row in [0, 1]:
        val = int(combined[row, col])
        ax2.text(col, row, str(val), ha='center', va='center',
                 fontsize=7, fontweight='bold',
                 color='black' if combined[row, col] in [0, 1] else 'red')

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
         label=f'Pozicije gdje actual=0 (n={len(delta_zeros)})', density=True)
ax3.hist(delta_ones,  bins=bins, alpha=0.7, color='#F44336',
         label=f'Pozicije gdje actual=1 (n={len(delta_ones)})', density=True)
ax3.axvline(0, color='black', lw=2, ls='--', label='Δ=0 (threshold)')
ax3.axvline(np.mean(delta_zeros), color='#2196F3', lw=1.5, ls=':',
            label=f'Mean(Δ | bit=0)={np.mean(delta_zeros):.1f}')
ax3.axvline(np.mean(delta_ones),  color='#F44336', lw=1.5, ls=':',
            label=f'Mean(Δ | bit=1)={np.mean(delta_ones):.1f}')
ax3.set_xlabel('Δ ciklusa (orig − flip)')
ax3.set_ylabel('Gustoća')
ax3.set_title('Distribucija Δ signala po stvarnoj vrijednosti bita')
ax3.legend(fontsize=8)

# sažetak
ax4 = fig.add_subplot(gs[2, 1])
ax4.axis('off')

key_match = (reconstructed_key == SECRET_KEY)

summary_lines = [
    "═══ SAŽETAK NAPADA ═══════════════════════",
    "",
    f"  Tajni ključ:     0x{SECRET_KEY:016X}",
    f"  Rekonstruisani:  0x{reconstructed_key:016X}",
    f"  XOR razlika:     0x{SECRET_KEY ^ reconstructed_key:016X}",
    "",
    f"  Tačni biti:  {correct_count:2d} / {total_bits}",
    f"  Tačnost:     {accuracy:.1f}%",
    f"  K po bitu:   {K_SAMPLES} mjerenja",
    "",
    f"  Δ mean (bit=1 pozicije): {np.mean(delta_ones):+.1f} cik",
    f"  Δ mean (bit=0 pozicije): {np.mean(delta_zeros):+.1f} cik",
    "",
    "  ═══════════════════════════════════════",
    f"  {'✓✓ NAPAD USPJEŠAN — ključ rekonstruisan!' if key_match else '~ Djelimičan uspjeh — povećaj K'}",
]

col = '#1B5E20' if key_match else '#B71C1C'
ax4.text(0.03, 0.97, "\n".join(summary_lines), transform=ax4.transAxes,
         fontsize=9, va='top', fontfamily='monospace',
         color='black',
         bbox=dict(boxstyle='round', facecolor='#F1F8E9' if key_match else '#FFEBEE',
                   edgecolor=col, alpha=0.95, linewidth=2))

fig.suptitle(
    f'RSA Timing Side-Channel — Rekonstrukcija {NUM_BITS}-bitnog privatnog ključa\n'
    f'Tajni ključ: 0x{SECRET_KEY:016X}  |  Rekonstruisan: 0x{reconstructed_key:016X}  |  '
    f'Tačnost: {correct_count}/{total_bits} bita ({accuracy:.0f}%)',
    fontsize=13, fontweight='bold', y=0.98
)

plt.savefig('plot_key_reconstruction.png', bbox_inches='tight', facecolor='#FAFAFA')
plt.close()

print("\n→ Grafik sačuvan: plot_key_reconstruction.png")
print(f"\nRezultat: {'POTPUNA REKONSTRUKCIJA KLJUČA ✓✓' if key_match else f'Djelimično: {correct_count}/{total_bits} bita'}")

meta = {}
if os.path.exists("key_reconstruction_meta.json"):
    with open("key_reconstruction_meta.json") as f:
        meta = json.load(f)

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
sys_meta = get_metadata()

report = MarkdownReport(f"RSA Timing Side-Channel — Rekonstrukcija {NUM_BITS}-bitnog ključa")

report.add_heading(2, "Metapodaci")
report.add_stat_line("Generisano", sys_meta['timestamp'])
report.add_stat_line("Platforma", sys_meta['platform'])
report.add_stat_line("Tajni ključ", f"0x{SECRET_KEY:016X}")
report.add_stat_line("Rekonstruisani ključ", f"0x{reconstructed_key:016X}")
report.add_stat_line("XOR razlika", f"0x{SECRET_KEY ^ reconstructed_key:016X}")
report.add_stat_line("Broj bita (NUM_BITS)", NUM_BITS)
report.add_stat_line("K uzoraka po bitu (K_SAMPLES)",
                    meta.get('k_samples', K_SAMPLES))
if 'calibration_median' in meta:
    report.add_stat_line("Kalibracija — medijana", f"{meta['calibration_median']:.1f} cik")
    report.add_stat_line("Kalibracija — IQR", f"{meta.get('calibration_iqr', 'N/A'):.1f} cik")
    report.add_stat_line("Dinamički prag (outlier)", meta.get('dynamic_threshold', 'N/A'))
if 'prng_seed' in meta:
    report.add_stat_line("PRNG seed", meta['prng_seed'])

report.add_heading(2, "Bit-po-bit rezultati")
headers = ["Bit pozicija", "Stvarni bit", "Inferred bit", "Δ ciklusa", "Tačno?", "|Δ| (signal)"]
tbl = []
for i in range(total_bits):
    bp = int(bit_positions[i])
    ab = int(actual_bits[i])
    ib = int(inferred_bits[i])
    d = float(deltas[i])
    c = bool(correct[i])
    tbl.append([str(bp), str(ab), str(ib), f"{d:+.1f}", "✓" if c else "✗", f"{abs(d):.1f}"])
report.add_table(headers, tbl)

report.add_heading(2, "Statistički sažetak")
report.add_stat_line("Tačnih bita", f"{correct_count}/{total_bits} ({accuracy:.1f}%)")
report.add_stat_line("Mean |Δ| za tačne bite",
                    f"{np.mean(np.abs(deltas[correct.astype(bool)])):.1f} cik"
                    if correct.sum() > 0 else "N/A")
report.add_stat_line("Mean |Δ| za pogrešne bite",
                    f"{np.mean(np.abs(deltas[~correct.astype(bool)])):.1f} cik"
                    if (~correct.astype(bool)).sum() > 0 else "N/A")
report.add_stat_line("Mean Δ za bit=1 pozicije", f"{np.mean(delta_ones):+.1f} cik")
report.add_stat_line("Mean Δ za bit=0 pozicije", f"{np.mean(delta_zeros):+.1f} cik")

wrong_bits = [int(bit_positions[i]) for i in range(total_bits) if not correct[i]]
if wrong_bits:
    report.add_heading(3, "Analiza grešaka")
    report.add_paragraph(f"Pogrešno klasifikovani biti: {wrong_bits}")
    for wp in wrong_bits:
        idx = list(bit_positions).index(wp)
        report.add_stat_line(f"  Bit {wp}", f"Δ={deltas[idx]:+.1f} cik, |Δ|={abs(deltas[idx]):.1f}")

report.add_heading(2, "Zaključak")
if key_match:
    report.add_verdict(True, "POTPUNA REKONSTRUKCIJA — svih 64 bita tačno rekonstruisano")
elif accuracy >= 90:
    report.add_verdict(False, f"DJELIMIČNA REKONSTRUKCIJA — {accuracy:.1f}% tačnost")
else:
    report.add_verdict(False, f"NEUSPJEŠNA REKONSTRUKCIJA — {accuracy:.1f}% tačnost")

report.add_heading(2, "Generisani grafici")
report.add_paragraph("- `plot_key_reconstruction.png`")

os.makedirs("reports", exist_ok=True)
report_path = f"reports/key_reconstruction_{ts}.md"
latest_path = "reports/key_reconstruction_latest.md"
report.save(report_path)
report.save(latest_path)
print(f"\n→ Izvještaj: {report_path}")
print(f"→ Izvještaj: {latest_path}")

pdf = try_convert_to_pdf(report_path)
if pdf:
    print(f"→ PDF: {pdf}")
