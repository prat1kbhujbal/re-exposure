/*
 * ONLINE target -- server-issued key (the strongest tier this repo builds).
 *
 * license_locked.c takes the key from the user, so the key is off the binary
 * but a copy still reaches the client. This build goes further: the client
 * holds no key at all. It authenticates to a license server with an opaque
 * TOKEN, the server validates it and returns the key, and only then is the
 * asset decrypted. Extract the binary and you get ciphertext plus a token that
 * is useless without the server; the server decides, per request, whether to
 * release the key, and can revoke, rate-limit, or log.
 *
 * What this stops that offline protection cannot: offline cracking (server
 * down -> nothing), unlicensed or revoked clients (server declines), and
 * key persistence in the client (the key never lives in the file).
 *
 * Honest boundary: while the server is up and the token is valid, running this
 * client decrypts the asset into its own memory, so an authorized attacker can
 * still dump it. Defeating that needs server-side EXECUTION (secret logic runs
 * on the server, client gets only results). Also: this demo speaks plain HTTP
 * to localhost; production needs TLS, a signed/bound token, and short-lived
 * keys. The security property demonstrated is WHERE THE KEY LIVES, not the
 * transport.
 *
 *   REN_TOKEN and REN_PORT override the compiled-in demo defaults.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include "locked.h"

#define DEF_HOST "127.0.0.1"
#define DEF_PORT 8787
#define DEF_TOKEN "CUST-1042-ok"

/* Ask the license server for the key. Returns a pointer into a static buffer,
 * or NULL if the server is unreachable or declines (invalid/revoked token). */
static char *fetch_key(void) {
    const char *host = DEF_HOST;
    int port = getenv("REN_PORT") ? atoi(getenv("REN_PORT")) : DEF_PORT;
    const char *token = getenv("REN_TOKEN") ? getenv("REN_TOKEN") : DEF_TOKEN;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return NULL;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, host, &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) {
        close(fd);
        return NULL;                      /* server down -> no key, no asset */
    }

    char req[512];
    int n = snprintf(req, sizeof req,
                     "POST /key HTTP/1.0\r\nHost: %s\r\n"
                     "Content-Length: %zu\r\n\r\n%s",
                     host, strlen(token), token);
    if (write(fd, req, n) != n) {
        close(fd);
        return NULL;
    }

    static char buf[8192];
    int tot = 0, r;
    while ((r = read(fd, buf + tot, sizeof buf - 1 - tot)) > 0) {
        tot += r;
        if (tot >= (int)sizeof buf - 1)
            break;
    }
    close(fd);
    buf[tot] = 0;

    if (strncmp(buf, "HTTP/1.0 200", 12) && strncmp(buf, "HTTP/1.1 200", 12))
        return NULL;                      /* 403 revoked/unknown, etc. */
    char *body = strstr(buf, "\r\n\r\n");
    if (!body)
        return NULL;
    return body + 4;
}

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
    ok = EVP_DecryptFinal_ex(c, pt + outl, &tmpl);
    EVP_CIPHER_CTX_free(c);

    if (ok <= 0)
        return 0;
    fwrite(pt, 1, outl + tmpl, stdout);
    return 1;
}

int main(void) {
    char *key = fetch_key();
    if (!key) {
        printf("License check failed (server unreachable or declined).\n");
        return 1;
    }
    if (check_license(key))
        return 0;
    printf("License check failed (bad key material).\n");
    return 1;
}
