CC      = gcc
# -O0  : Bez optimizacija — sprječava compiler da pretvori 'if(bit)' u cmov
#          Ovo je KLJUČNO: sa -O2, GCC može optimizovati branch koji otkriva
#          tajnu u cmov (conditional move) — time bi eliminisao timing leak!
# -Wall : Sve upozorenja
# -g    : Debug simboli (za perf/gdb analizu)
# -march=native : Koristi RDTSCP, ADX, i sve instrukce dostupne na ovom CPU-u
CFLAGS  = -O0 -Wall -Wextra -g -march=native -fno-omit-frame-pointer
 
# Za provjeru da li je GCC pretvorio branch u cmov (timing leak eliminisan):
# objdump -d experiment | grep -A5 "mod_exp_vulnerable"
# Tražimo 'jne' ili 'je' — to su skokovi (leakuju). 'cmov' = constant-time.
 
TARGET      = experiment
KEY_TARGET  = key_reconstruct
SRCS        = experiment.c rsa.c
OBJS        = $(SRCS:.c=.o)
KEY_OBJS    = key_reconstruct.o rsa.o

SWEEP_TARGET    = multi_bit_sweep
SWEEP_SRCS      = multi_bit_sweep.c rsa.c

BLINDING_TARGET     = blinding_experiment
BLIND_RECON_TARGET  = key_reconstruct_blind
BLIND_RECON_OBJS    = key_reconstruct_blind.o oracle_blind.o rsa.o

LIBRSA_SO       = librsa_shared.so
VICTIM_FR       = victim_fr
ATTACKER_FR     = attacker_fr

# Compiler experiment binaries (use rsa_no_attr.c = no optimize attribute)
EXP_O0          = experiment_O0
EXP_O1          = experiment_O1
EXP_O2          = experiment_O2
EXP_O3          = experiment_O3
EXP_O2_ATTR     = experiment_O2_attr

.PHONY: all clean distclean run analyze check_asm check_setup \
        run-sweep compiler-experiment check-asm-all \
        run-blinding run-flush-reload run-blind-recon

all: $(TARGET) $(KEY_TARGET) $(SWEEP_TARGET) $(BLINDING_TARGET) $(BLIND_RECON_TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^
	@echo ""
	@echo "Build uspješan: ./$(TARGET)"
	@echo "Pokreni: taskset -c 0 ./$(TARGET)"
	@echo ""

$(KEY_TARGET): $(KEY_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lm
	@echo "Build uspješan: ./$(KEY_TARGET)"

$(SWEEP_TARGET): multi_bit_sweep.o rsa.o
	$(CC) $(CFLAGS) -o $@ $^ -lm
	@echo "Build uspješan: ./$(SWEEP_TARGET)"

multi_bit_sweep.o: multi_bit_sweep.c rsa.h timing.h
	$(CC) $(CFLAGS) -c -o $@ $<

# ── Compiler experiment variants (rsa_no_attr.c = no optimize("O0") attribute) ──
$(EXP_O0): experiment.c rsa_no_attr.c
	$(CC) -O0 -Wall -g -march=native -fno-omit-frame-pointer \
	    -o $@ experiment.c rsa_no_attr.c -I.
	@echo "Build: ./$(EXP_O0)"

$(EXP_O1): experiment.c rsa_no_attr.c
	$(CC) -O1 -Wall -g -march=native \
	    -o $@ experiment.c rsa_no_attr.c -I.

$(EXP_O2): experiment.c rsa_no_attr.c
	$(CC) -O2 -Wall -g -march=native \
	    -o $@ experiment.c rsa_no_attr.c -I.

$(EXP_O3): experiment.c rsa_no_attr.c
	$(CC) -O3 -Wall -g -march=native \
	    -o $@ experiment.c rsa_no_attr.c -I.

$(EXP_O2_ATTR): experiment.c rsa.c
	$(CC) -O2 -Wall -g -march=native \
	    -o $@ experiment.c rsa.c -I.

compiler-experiment: $(EXP_O0) $(EXP_O1) $(EXP_O2) $(EXP_O3) $(EXP_O2_ATTR)
	@echo "Pokretanje compiler experiment varijanti..."
	@echo "--- O0 ---" && taskset -c 0 ./$(EXP_O0) | tail -5; \
	    cp vulnerable_timing.csv vulnerable_O0.csv 2>/dev/null || true
	@echo "--- O1 ---" && taskset -c 0 ./$(EXP_O1) | tail -5; \
	    cp vulnerable_timing.csv vulnerable_O1.csv 2>/dev/null || true
	@echo "--- O2 ---" && taskset -c 0 ./$(EXP_O2) | tail -5; \
	    cp vulnerable_timing.csv vulnerable_O2.csv 2>/dev/null || true
	@echo "--- O3 ---" && taskset -c 0 ./$(EXP_O3) | tail -5; \
	    cp vulnerable_timing.csv vulnerable_O3.csv 2>/dev/null || true
	@echo "--- O2_attr ---" && taskset -c 0 ./$(EXP_O2_ATTR) | tail -5; \
	    cp vulnerable_timing.csv vulnerable_O2_attr.csv 2>/dev/null || true

check-asm-all: $(EXP_O0) $(EXP_O1) $(EXP_O2) $(EXP_O3) $(EXP_O2_ATTR)
	@for bin in $(EXP_O0) $(EXP_O1) $(EXP_O2) $(EXP_O3) $(EXP_O2_ATTR); do \
	    echo "=== $$bin: mod_exp_vulnerable assembly ==="; \
	    objdump -d ./$$bin | awk '/mod_exp_vulnerable/,/^$$/' | \
	        grep -E "je |jne |jz |jnz |cmov" | head -5; \
	done

run-sweep: $(SWEEP_TARGET)
	@echo "Pokretanje multi-bit sweep (sve 64 bit pozicije)..."
	taskset -c 0 ./$(SWEEP_TARGET)

$(BLINDING_TARGET): blinding_experiment.o rsa.o
	$(CC) $(CFLAGS) -o $@ $^

blinding_experiment.o: blinding_experiment.c rsa.h timing.h
	$(CC) $(CFLAGS) -c -o $@ $<

run-blinding: $(BLINDING_TARGET)
	@echo "Pokretanje RSA blinding evaluacije..."
	taskset -c 0 ./$(BLINDING_TARGET)

$(LIBRSA_SO): librsa_shared.c
	$(CC) -O0 -shared -fPIC -march=native -o $@ $< -I.

$(VICTIM_FR): victim_fr.c $(LIBRSA_SO)
	$(CC) -O0 -Wall -g -march=native -o $@ victim_fr.c \
	    -L. -lrsa_shared -Wl,-rpath,. -I. -lpthread

$(ATTACKER_FR): attacker_fr.c $(LIBRSA_SO)
	$(CC) -O2 -Wall -g -march=native -o $@ attacker_fr.c \
	    -L. -lrsa_shared -Wl,-rpath,. -I. -ldl -lpthread

run-flush-reload: $(VICTIM_FR) $(ATTACKER_FR)
	@echo "Pokretanje Flush+Reload napada..."
	@echo "  Victim: CPU 2 (drugi fizicki P-core), Attacker: CPU 0"
	@rm -f flush_reload.csv
	taskset -c 2 ./$(VICTIM_FR) &
	@sleep 1
	taskset -c 0 ./$(ATTACKER_FR)

$(BLIND_RECON_TARGET): $(BLIND_RECON_OBJS)
	$(CC) -O2 -Wall -g -march=native -o $@ $^ -lm
	@echo "Build uspjesan: ./$(BLIND_RECON_TARGET)"
	@echo "Pokreni: taskset -c 0 ./$(BLIND_RECON_TARGET)"

key_reconstruct_blind.o: key_reconstruct_blind.c oracle_blind.h rsa.h timing.h
	$(CC) -O2 -Wall -g -march=native -c -o $@ $<

oracle_blind.o: oracle_blind.c oracle_blind.h rsa.h timing.h
	$(CC) $(CFLAGS) -c -o $@ $<

run-blind-recon: $(BLIND_RECON_TARGET)
	@echo "Pokretanje slijepe rekonstrukcije kljuca..."
	taskset -c 0 ./$(BLIND_RECON_TARGET)

# Explicit header dependencies
experiment.o: experiment.c rsa.h timing.h
rsa.o: rsa.c rsa.h
key_reconstruct.o: key_reconstruct.c rsa.h timing.h

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
 
# Pokreni eksperiment piniran na P-core 0
run: $(TARGET)
	@echo "Pinovanje na CPU 0 (P-core) i pokretanje..."
	taskset -c 0 ./$(TARGET)
 
# Statistička analiza
analyze:
	python3 analysis.py
 
# Provjeri assembly — da li je branch ostao branch (nije cmov)?
check_asm: $(TARGET)
	@echo "=== Assembly mod_exp_vulnerable (tražimo jne/je, ne cmov) ==="
	objdump -d ./$(TARGET) | awk '/mod_exp_vulnerable/,/mod_exp_constant/' | \
		grep -E "je |jne |jz |jnz |cmov|call" | head -30
	@echo ""
	@echo "=== Assembly mod_exp_constant_time ==="
	objdump -d ./$(TARGET) | awk '/mod_exp_constant_time/,/^$$/' | \
		grep -E "cmov|je |jne |call" | head -20
 
# Provjera hardware setup-a
check_setup:
	@echo "=== Turbo Boost status ==="
	@cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null && \
		echo "(1 = isključen ✓)" || echo "N/A"
	@echo ""
	@echo "=== CPU Governor ==="
	@cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "N/A"
	@echo ""
	@echo "=== TSC flags u /proc/cpuinfo ==="
	@grep -m1 "flags" /proc/cpuinfo | tr ' ' '\n' | \
		grep -E "tsc|rdtsc|constant_tsc|nonstop_tsc" || echo "N/A"
 
clean:
	rm -f $(TARGET) $(KEY_TARGET) $(SWEEP_TARGET) $(BLINDING_TARGET) \
	    $(BLIND_RECON_TARGET) \
	    $(EXP_O0) $(EXP_O1) $(EXP_O2) $(EXP_O3) $(EXP_O2_ATTR) \
	    $(LIBRSA_SO) $(VICTIM_FR) $(ATTACKER_FR) \
	    $(OBJS) key_reconstruct.o multi_bit_sweep.o rsa_no_attr.o \
	    blinding_experiment.o librsa_shared.o victim_fr.o attacker_fr.o \
	    key_reconstruct_blind.o oracle_blind.o \
	    perf.data perf.data.old

# Remove everything including experimental data and plots
distclean: clean
	@echo "WARNING: Removing experimental data and generated plots"
	rm -f *.csv *.png *_meta.json
	rm -rf reports/
