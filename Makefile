# Reverse-engineering hardening lab.
# Uses clang because `gcc` is shadowed by a shell function on this box.
CC      := clang
CFLAGS  := -O2 -fno-stack-protector -Wall
PY      := python3
B       := build

.PHONY: all clean view-baseline view-hardened diff

all: $(B)/baseline $(B)/baseline.strip $(B)/hardened $(B)/hardened.strip

# --- baseline: unprotected, with debug symbols (the easy target) ----------
$(B)/baseline: src/license.c
	$(CC) $(CFLAGS) -g -o $@ $<

# layer 1 alone: same code, symbols stripped
$(B)/baseline.strip: $(B)/baseline
	cp $< $@ && strip --strip-all $@

# --- hardened: layer 2 (encrypted secrets), symbols kept --------------
$(B)/secrets_enc.h: examples/demo_strings.txt src/gen_secrets.py
	$(PY) src/gen_secrets.py $< $@

$(B)/hardened: src/license_hardened.c $(B)/secrets_enc.h
	$(CC) $(CFLAGS) -I$(B) -o $@ $<

# layers 1 + 2: encrypted secrets AND symbols stripped (the hard target)
$(B)/hardened.strip: $(B)/hardened
	cp $< $@ && strip --strip-all $@

clean:
	rm -f $(B)/*

# convenience analyst views
view-baseline: $(B)/baseline
	./analyst-view.sh $(B)/baseline
view-hardened: $(B)/hardened.strip
	./analyst-view.sh $(B)/hardened.strip

# measurement harness: score every variant, worst-exposed first
scan: all
	@for b in baseline baseline.strip hardened hardened.strip; do \
	  python3 harness/reexpose.py build/$$b --quiet; \
	done | sort -rn

# post-build anchor denial on the unprotected baseline (no rebuild, no source)
reharden: $(B)/baseline
	python3 tools/reharden.py $(B)/baseline -o $(B)/baseline.reharden \
	  --run "ACME-PRO-2026-XK7Q"

# M1 full pipeline demo: strip metadata then encrypt .rodata strings (non-PIE)
harden-full: $(B)/demo_nopie
	python3 tools/reharden.py $(B)/demo_nopie -o $(B)/demo_nopie.rh >/dev/null
	python3 tools/encrypt_strings.py $(B)/demo_nopie.rh -o $(B)/demo_nopie.hard --all --verify "ACME-PRO-2026-XK7Q" --verify "wrong"

$(B)/demo_nopie: src/license.c
	$(CC) $(CFLAGS) -no-pie -o $@ $<

# validate the Ghidra readability axis: same function, clean vs flattened (-O0)
$(B)/clean_o0: src/license.c
	$(CC) -O0 -o $@ $<
$(B)/flat_o0: src/license_flattened.c
	$(CC) -O0 -o $@ $<
readability-demo: $(B)/clean_o0 $(B)/flat_o0
	@echo "== clean =="; python3 tools/ghidra_readability.py $(B)/clean_o0 --func check_license
	@echo "== flattened =="; python3 tools/ghidra_readability.py $(B)/flat_o0 --func check_license

# M3: reference-correct GTIRB round-trip (needs docker image grammatech/ddisasm)
m3-roundtrip: $(B)/demo_nopie
	python3 tools/m3_rewrite.py $(B)/demo_nopie -o $(B)/demo_nopie.m3 \
	  --verify "ACME-PRO-2026-XK7Q" --verify "wrong"

# agent summary-accuracy axis (needs Ollama serving REEXPOSE_MODEL)
agent-demo: $(B)/clean_o0 $(B)/flat_o0
	@echo "== clean =="; python3 tools/agent_summary.py $(B)/clean_o0 --func check_license
	@echo "== flattened =="; python3 tools/agent_summary.py $(B)/flat_o0 --func check_license

# M3: per-use string encryption via GTIRB (needs docker image grammatech/ddisasm)
m3-encrypt: $(B)/demo_nopie
	python3 tools/m3_rewrite.py $(B)/demo_nopie -o $(B)/demo_nopie.m3enc \
	  --encrypt-strings --verify "ACME-PRO-2026-XK7Q" --verify "wrong"

# Windows PE: build the lab license check as a PE and measure it. Needs the
# mingw sysroot (/usr/x86_64-w64-mingw32) + Wine; see tools/pe/README.md.
build/license.exe: src/license.c tools/pe/build-pe.sh tools/pe/chkstk.s
	./tools/pe/build-pe.sh src/license.c build/license.exe
pe-demo: build/license.exe
	-WINEDEBUG=-all wine64 build/license.exe ACME-PRO-2026-XK7Q
	python3 tools/reharden.py build/license.exe -o build/license.rh.exe --run "ACME-PRO-2026-XK7Q"
	python3 harness/reexpose.py build/license.exe
