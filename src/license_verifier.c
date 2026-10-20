/*
 * VERIFIER target -- the key is NOT in the binary.
 *
 * license.c ships the key in plaintext; the hardened/encrypted builds ship it
 * encrypted plus the decryptor, so a debugger (or the agent-attack `run` tool)
 * reads it off the compare in memory. This build ships only SHA-256(key). It
 * hashes the user's input and compares digests, so:
 *   - `strings` shows no key (only the 32-byte digest, as non-text bytes),
 *   - running it under the compare-spy shows a memcmp of two digests, not the
 *     key -- the plaintext key never exists anywhere in the client.
 *
 * SHA-256 is preimage-resistant, so recovering the key from the stored digest
 * is a brute-force/guessing problem, not a read. That is the honest wall the
 * static transforms cannot reach: you cannot read out a secret the client does
 * not hold. The real product of a key is to decrypt the actual asset; here we
 * just gate, but the principle is the same -- keep the secret off the client.
 *
 * Interface and messages match license.c so an attacker's task is identical.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* SHA-256(key) -- the key itself appears nowhere in this source or binary. */
static const uint8_t STORED[32] = {
    0x72, 0x3a, 0xbe, 0xb7, 0xba, 0xa9, 0x77, 0x89,
    0x19, 0xa3, 0x4b, 0x88, 0x82, 0x65, 0xde, 0x8c,
    0x13, 0xe1, 0x38, 0xdb, 0x0e, 0xda, 0xf8, 0x30,
    0x0f, 0x53, 0x6a, 0x56, 0xd8, 0xef, 0x4b, 0x98,
};

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    size_t total = ((len + 8) / 64 + 1) * 64;
    uint8_t blk[256] = {0};                 /* keys are short; ample headroom */
    memcpy(blk, msg, len);
    blk[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        blk[total - 1 - i] = (uint8_t)(bits >> (8 * i));

    for (size_t off = 0; off < total; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (blk[off + 4 * i] << 24) | (blk[off + 4 * i + 1] << 16) |
                   (blk[off + 4 * i + 2] << 8) | blk[off + 4 * i + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8);
        out[4 * i + 3] = (uint8_t)h[i];
    }
}

int check_license(const char *key) {
    uint8_t digest[32];
    sha256((const uint8_t *)key, strlen(key), digest);
    return memcmp(digest, STORED, 32) == 0;   /* digests, never the key */
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
