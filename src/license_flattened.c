/*
 * Manually control-flow-flattened check_license, for validating the Ghidra
 * readability axis (stands in for a Tigress/ollvm --flatten pass, which is
 * license-gated). The original if/loop structure is replaced by a dispatch
 * loop over a state variable, plus one opaque-predicate dead branch. Behavior
 * is identical to src/license.c; it is just far less readable to a decompiler.
 *
 * Build at -O0 so the dispatcher survives to the binary (a real obfuscator
 * resists the optimizer; here we only need the structure present).
 */
#include <stdio.h>
#include <string.h>

int check_license(const char *key) {
    const char *valid = "ACME-PRO-2026-XK7Q";
    int state = 0, i = 0, ok = 1;
    unsigned x = 0;
    while (1) {
        switch (state) {
            case 0:
                x = (unsigned)(size_t)key;
                /* opaque predicate: x*x + x is always even -> always true */
                if (((x * x + x) & 1u) == 0u) state = 1; else state = 7;
                break;
            case 1:
                if (key[i] == '\0' && valid[i] != '\0') { ok = 0; state = 5; }
                else state = 2;
                break;
            case 2:
                if (valid[i] == '\0') state = 5; else state = 3;
                break;
            case 3:
                if (key[i] != valid[i]) { ok = 0; state = 5; } else state = 4;
                break;
            case 4:
                i++; state = 1;
                break;
            case 5:
                if (ok && key[i] != '\0') ok = 0;   /* reject longer keys */
                state = 6;
                break;
            case 6:
                return ok;
            case 7:
                return 0;                           /* dead opaque branch */
            default:
                return 0;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <key>\n", argv[0]);
        return 2;
    }
    if (check_license(argv[1])) {
        printf("License valid. Welcome.\n");
        return 0;
    }
    printf("Invalid license key.\n");
    return 1;
}
