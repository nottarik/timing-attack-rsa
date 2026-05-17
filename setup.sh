#!/usr/bin/env bash
# =============================================================================
# setup.sh — Priprema okruženja za RSA timing side-channel eksperiment
#
# Pokretanje: sudo bash setup.sh
#
# Hardware target: Intel i5-1335U (Raptor Lake)
#   P-cores: CPU 0-7  (2 Performance cores + HT = 4 logical)
#   E-cores: CPU 8-11 (4 Efficient cores)
# =============================================================================
 
set -euo pipefail
 
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
 
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
 
echo "========================================================"
echo "  RSA Timing Side-Channel — Setup okruženja"
echo "========================================================"
echo ""
 
# --------------------------------------------------------------------------
# 1. CPU informacije
# --------------------------------------------------------------------------
info "CPU informacije:"
lscpu | grep -E "Model name|CPU\(s\):|Core\(s\) per|Thread|NUMA|Vendor" || true
echo ""
 
# Provjeri invarijantni TSC (obavezno za pouzdano RDTSC mjerenje)
info "Provjera invarijantnog TSC:"
if grep -q "constant_tsc" /proc/cpuinfo; then
    ok "constant_tsc: TSC radi na fiksnoj frekvenciji (invarijantan)"
else
    warn "constant_tsc nije detektiran — mjerenja mogu biti nestabilna"
fi
 
if grep -q "nonstop_tsc" /proc/cpuinfo; then
    ok "nonstop_tsc: TSC ne zaustavlja u C-state stanjima"
else
    warn "nonstop_tsc nije prisutan"
fi
 
if grep -q "rdtscp" /proc/cpuinfo; then
    ok "RDTSCP dostupan: koristimo ga za kraj mjerenja (uključuje processor ID)"
else
    warn "RDTSCP nije dostupan — kod koristi RDTSC sa CPUID barijero"
fi
echo ""
 
# --------------------------------------------------------------------------
# 2. Isključivanje Turbo Boost
#
# Zašto: Turbo Boost dinamički mijenja frekvenciju CPU-a.
# Primjer na i5-1335U: base 2.7 GHz, turbo do 4.6 GHz (P-core).
# Ako frekvencija skače tokom mjerenja → TSC ciklusi != isti posao.
# Isključivanjem turbo-a, frekvencija ostaje stabilna → TSC je proporcionalan
# realnom vremenu izvršavanja.
# --------------------------------------------------------------------------
info "Isključivanje Intel Turbo Boost:"
if [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
    echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
    TURBO_VAL=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)
    if [ "$TURBO_VAL" = "1" ]; then
        ok "Turbo Boost isključen (no_turbo=1)"
    else
        warn "Nije moguće isključiti turbo (no_turbo=$TURBO_VAL)"
    fi
elif [ -f /sys/devices/system/cpu/cpufreq/boost ]; then
    echo 0 > /sys/devices/system/cpu/cpufreq/boost
    ok "Turbo isključen via cpufreq/boost=0"
else
    warn "Turbo kontrola nije pronađena. Provjeri BIOS postavke."
fi
echo ""
 
# --------------------------------------------------------------------------
# 3. Performance governor
#
# Zašto: 'ondemand' ili 'powersave' governor dinamički skejluju frekvenciju
# na osnovu opterećenja. To znači da prve iteracije eksperimenta rade na
# niskoj frekvenciji, a kasnuije na višoj — sistematski bias u podacima.
# 'performance' governor drži CPU na maksimalnoj stabilnoj frekvenciji.
# --------------------------------------------------------------------------
info "Postavljanje 'performance' CPU governor-a:"
if command -v cpupower &>/dev/null; then
    cpupower frequency-set -g performance 2>/dev/null && \
        ok "Governor postavljen na 'performance'" || \
        warn "cpupower nije uspio — možda nemas pristup"
else
    warn "cpupower nije instaliran. Instalacija..."
    apt-get install -y linux-tools-generic linux-tools-common \
        linux-tools-"$(uname -r)" 2>/dev/null || \
    apt-get install -y cpufrequtils 2>/dev/null || \
        warn "Nije moguće instalirati cpupower"
    
    # Fallback: direktno pisanje u sysfs
    for gov_file in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo performance > "$gov_file" 2>/dev/null && true
    done
    ok "Governor postavljen direktno via sysfs"
fi
echo ""
 
# --------------------------------------------------------------------------
# 4. CPU pinning informacije
#
# Zašto: Intel i5-1335U ima P-core i E-core arhitekturu.
# - P-core (Raptor Cove): viša frekvencija, out-of-order execution
# - E-core (Gracemont): niža frekvencija, in-order, manje resursa
# Timing na P-core i E-core NISU isti za isti kod!
# Linux scheduler može migrirati proces između jezgri → artefakti u mjerenju.
# Rješenje: taskset -c 0 pinira proces na CPU 0 (P-core).
# --------------------------------------------------------------------------
info "Topologija jezgri (Intel i5-1335U identificirana):"
echo ""
echo "  i5-1335U topologija (12 logičkih CPU-a):"
echo "  +---------------------------------------------+"
echo "  | P-core 0  (HT):  CPU 0, CPU 1               |"
echo "  | P-core 1  (HT):  CPU 2, CPU 3               |"
echo "  | E-core 0  :      CPU 4                       |"
echo "  | E-core 1  :      CPU 5                       |"
echo "  | E-core 2  :      CPU 6                       |"
echo "  | E-core 3  :      CPU 7                       |"
echo "  | E-core 4  :      CPU 8                       |"
echo "  | E-core 5  :      CPU 9                       |"
echo "  | E-core 6  :      CPU 10                      |"
echo "  | E-core 7  :      CPU 11                      |"
echo "  +---------------------------------------------+"
echo "  -> Pinuj na CPU 0 (P-core)"
echo "  -> Za max izolaciju: onemogući SMT (sekcija 4b ispod)"
echo ""
 
# Prikaz trenutne frekvencije po jezgri
info "Trenutna frekvencija po jezgri:"
for cpu in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq; do
    cpu_id=$(echo "$cpu" | grep -oP 'cpu\d+')
    freq_khz=$(cat "$cpu" 2>/dev/null || echo "N/A")
    if [ "$freq_khz" != "N/A" ]; then
        freq_mhz=$(( freq_khz / 1000 ))
        printf "  %-8s %d MHz\n" "$cpu_id:" "$freq_mhz"
    fi
done
echo ""
 
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# 4b. Onemogućavanje SMT/Hyper-Threading
#
# Zašto: CPU 0 i CPU 1 dijele isti fizički P-core (HT par).
# Kod na CPU 1 koristi iste L1/L2 cache i execution porte,
# što može uticati na timing mjerenja na CPU 0.
# Rješenje: onemogući SMT tokom eksperimenta.
# --------------------------------------------------------------------------
info "SMT/Hyper-Threading:"
if [ -f /sys/devices/system/cpu/smt/control ]; then
    SMT_STATUS=$(cat /sys/devices/system/cpu/smt/control)
    if [ "$SMT_STATUS" = "off" ]; then
        ok "SMT već onemogućen (CPU 1 ne dijeli resurse sa CPU 0)"
    else
        echo off > /sys/devices/system/cpu/smt/control 2>/dev/null && \
            ok "SMT onemogućen — CPU 1 više ne dijeli resurse sa CPU 0" || \
            warn "Nije moguće onemogućiti SMT (nema root privilegija)"
    fi
else
    warn "SMT kontrola nije dostupna (/sys/devices/system/cpu/smt/control)"
fi
echo ""

# --------------------------------------------------------------------------
# 4c. Prebacivanje hardware IRQ na E-core (CPU 4)
#
# Zašto: hardware interrupts se po defaultu usmjeravaju na CPU 0.
# Svaki interrupt prekida naša mjerenja i dodaje šum.
# Premještanjem IRQ na CPU 4 (E-core), CPU 0 ostaje slobodan.
# Napomena: neki IRQ (lokalni APIC, IPI) su vezani za CPU i ne mogu se premjestiti.
# --------------------------------------------------------------------------
info "Premještanje IRQ afiniteta na CPU 4 (E-core, 0x10):"
MIGRATED=0; FAILED=0
for irq_aff in /proc/irq/*/smp_affinity; do
    echo 10 > "$irq_aff" 2>/dev/null && MIGRATED=$((MIGRATED+1)) || FAILED=$((FAILED+1))
done
ok "IRQ premješteni: $MIGRATED usješno, $FAILED vezanih/zaštićenih (lokalni APIC/IPI)"
echo "  → CPU 0 oslobođen od interrupt prekida tokom mjerenja"
echo ""

# 5. Provjera frekvencijskog skaliranja
# --------------------------------------------------------------------------
info "Stanje CPU scaling (provjera):"
cpupower frequency-info 2>/dev/null | grep -E "hardware l|current|governor|min|max" | head -8 || true
echo ""
 
# --------------------------------------------------------------------------
# 6. Izolacija CPUa (opcionalno, za maksimalnu preciznost)
#
# Za akademski eksperiment taskset je obično dovoljan.
# Za produkcijsku kriptografiju koristiti isolcpus= kernel parametar.
# --------------------------------------------------------------------------
info "Izolacija CPU (opcionalno):"
echo "  Za maksimalnu izolaciju, dodaj u /etc/default/grub:"
echo "  GRUB_CMDLINE_LINUX=\"isolcpus=0 nohz_full=0 rcu_nocbs=0\""
echo "  NAPOMENA: argumenti su LISTA CPU-a (ne boolean):"
echo "    isolcpus=0  — izoluj CPU 0 od Linux schedulera"
echo "    nohz_full=0 — isključi timer tickove na CPU 0 (smanjuje šum mjerenja)"
echo "    rcu_nocbs=0 — premjesti RCU callback-ove sa CPU 0"
echo "  (Preporučeno za istraživački rad, zahtijeva reboot)"
echo ""
 
# --------------------------------------------------------------------------
# 7. Provjera Python zavisnosti
# --------------------------------------------------------------------------
info "Provjera Python zavisnosti:"
PYTHON_DEPS="numpy pandas scipy matplotlib"
MISSING=""
for dep in $PYTHON_DEPS; do
    python3 -c "import $dep" 2>/dev/null && ok "$dep dostupan" || MISSING="$MISSING $dep"
done
if [ -n "$MISSING" ]; then
    warn "Nedostaju: $MISSING"
    info "Instalacija: pip3 install $MISSING"
    pip3 install $MISSING --quiet && ok "Zavisnosti instalirane"
fi
echo ""
 
# --------------------------------------------------------------------------
# 8. Kompilacija
# --------------------------------------------------------------------------
info "Kompilacija eksperimenta:"
if make -s 2>/dev/null; then
    ok "Kompilacija uspješna — './experiment' spreman"
else
    warn "Kompilacija nije pokrenuta (pokreni manuelno: make)"
fi
echo ""
 
echo "========================================================"
echo -e "${GREEN}  Setup završen!${NC}"
echo "========================================================"
echo ""
echo "  Pokretanje eksperimenta:"
echo "  +---------------------------------------------------+"
echo "  |  taskset -c 0 ./experiment                        |"
echo "  |  python3 analysis.py                              |"
echo "  +---------------------------------------------------+"
echo ""
echo "  Restore turbo (poslije eksperimenta):"
echo "    echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo"
echo ""
 
