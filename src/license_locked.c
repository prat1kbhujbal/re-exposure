/*
 * LOCKED target -- the key is a lock, not a gate.
 *
 * license.c and the encrypted builds GATE a feature: `if (valid) unlock()`.
 * That branch is one instruction to patch, and the compared key sits in memory,
 * so an agent recovers it (see tools/agent_attack.py). This build has no gate.
 * The protected asset ships as AES-256-GCM ciphertext (build/locked.h, produced
 * by tools/seal.c). The user's license key is run through the SAME PBKDF2 to
 * derive the AES key and decrypt it. A wrong key fails the GCM auth tag, so the
 * plaintext is never produced. There is nothing to bypass and nothing to read:
 * the asset is not in the binary, and the key is not in the binary.
 *
 * Honest boundary: a user with a VALID key decrypts the asset into their own
 * memory and can dump it from there. This stops an attacker WITHOUT a valid key
 * (the agent, the pirate who has not paid); stopping extraction by an
 * authorized user needs server-side execution or per-user keys (the online
 * layer). Brute force is bounded by key entropy; PBKDF2 raises the per-guess
 * cost but a guessable key is still guessable.
 *
 *   license_locked <license-key>     # prints the asset only for the right key
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "locked.h"

int check_license(const char *key) {
    unsigned char aes[32], pt[4096];
    int outl = 0, ok;

    if (CT_LEN > (int)sizeof(pt))
        return 0;
    if (!PKCS5_PBKDF2_HMAC(key, strlen(key), SEAL_SALT, sizeof(SEAL_SALT),
                           PBKDF2_ITERS, EVP_sha256(), 32, aes))
        return 0;

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, sizeof(SEAL_IV), NULL);
    EVP_DecryptInit_ex(c, NULL, NULL, aes, SEAL_IV);
    EVP_DecryptUpdate(c, pt, &outl, SEAL_CT, CT_LEN);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, sizeof(SEAL_TAG),
                        (void *)SEAL_TAG);
    int tmpl = 0;
    ok = EVP_DecryptFinal_ex(c, pt + outl, &tmpl);   /* <=0 on wrong key */
    EVP_CIPHER_CTX_free(c);

    if (ok <= 0)
        return 0;
    fwrite(pt, 1, outl + tmpl, stdout);     /* the unlocked asset */
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <key>\n", argv[0]);
        return 2;
    }
    if (check_license(argv[1]))
        return 0;
    printf("Invalid license key.\n");
    return 1;
}
