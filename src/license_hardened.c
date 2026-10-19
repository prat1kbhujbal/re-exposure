/*
 * HARDENED target - layers 1 + 2 only (strip-ready + encrypted secrets).
 *
 * What changed vs license.c:
 *   - the valid key and both messages are XOR-obfuscated (secrets_enc.h),
 *     decrypted into a stack buffer only at point of use, then wiped.
 *   - no plaintext landmark survives in .rodata.
 *   - build the `.strip` variant to also delete the `check_license` symbol.
 *
 * This file deliberately stops at static-analysis layers. Runtime defenses
 * (anti-debug / anti-instrument / integrity) are described in the README but
 * NOT implemented here.
 */
#include <stdio.h>
#include <string.h>
#include "secrets_enc.h"

/* Decrypt secret `blob` of `len` bytes into `out` (must hold len+1),
 * NUL-terminate, and return out. Caller wipes after use. */
static char *reveal(const volatile unsigned char *blob, size_t len, char *out) {
    for (size_t i = 0; i < len; i++)
        out[i] = (char)(blob[i] ^ SEC_KEY[i % SEC_KEY_LEN]);
    out[len] = '\0';
    return out;
}

static void wipe(char *buf, size_t n) {
    /* volatile write so the compiler cannot elide the scrub */
    volatile char *p = (volatile char *)buf;
    while (n--) *p++ = 0;
}

int check_license(const char *key) {
    char valid[32];
    int ok;
    reveal(SEC_0, SEC_0_LEN, valid);     /* decrypted key built in RAM only */
    ok = (strcmp(key, valid) == 0);
    wipe(valid, sizeof valid);           /* no plaintext left on the stack */
    return ok;
}

int main(int argc, char **argv) {
    char msg[64];
    if (argc < 2) {
        printf("usage: %s <key>\n", argv[0]);
        return 2;
    }
    if (check_license(argv[1])) {
        reveal(SEC_2, SEC_2_LEN, msg);
        printf("%s\n", msg);
        wipe(msg, sizeof msg);
        return 0;
    }
    reveal(SEC_1, SEC_1_LEN, msg);
    printf("%s\n", msg);
    wipe(msg, sizeof msg);
    return 1;
}
