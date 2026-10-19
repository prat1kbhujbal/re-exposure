/*
 * BASELINE target - deliberately unprotected.
 * This is what an unhardened license check looks like to an analyst:
 *   - a named function `check_license`
 *   - the valid key sitting in .rodata as plaintext
 *   - error/success strings as landmarks with xrefs straight to the check
 *
 * Build it, then look at it with ../analyst-view.sh and note every
 * landmark. Those landmarks are your attack surface.
 */
#include <stdio.h>
#include <string.h>

int check_license(const char *key) {
    const char *valid = "ACME-PRO-2026-XK7Q";      /* plaintext secret in .rodata */
    if (strcmp(key, valid) == 0)
        return 1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <key>\n", argv[0]);
        return 2;
    }
    if (check_license(argv[1])) {
        printf("License valid. Welcome.\n");   /* obvious success landmark */
        return 0;
    }
    printf("Invalid license key.\n");          /* obvious failure landmark */
    return 1;
}
