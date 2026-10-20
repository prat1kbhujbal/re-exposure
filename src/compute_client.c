/*
 * COMPUTE client -- server-side execution tier (the strongest).
 *
 * The protected IP is a pricing algorithm with secret coefficients. This client
 * does NOT contain them. It sends inputs (quantity, tier) with its token to the
 * compute server, which runs the secret model and returns only the price. The
 * algorithm never reaches the client, so reverse-engineering this binary (its
 * strings, its disassembly, running it) yields the request shape and the output
 * number, never the coefficients: there is simply nothing of the IP in here.
 *
 * Contrast with every earlier tier: plaintext/encrypted ship the secret;
 * key-as-lock and server-issued-key ship the asset as ciphertext and a key
 * reaches the client to decrypt it. Here the secret is never on the client at
 * all, up or down.
 *
 * Honest boundary: an authorized caller can still PROBE the oracle (many
 * inputs -> outputs) and try to approximate the model. The server rate-limits,
 * logs and can revoke; exact coefficients are not recoverable from the client.
 * This demo speaks plain HTTP to localhost; production needs TLS and a signed,
 * device-bound token.
 *
 *   compute_client <qty> <tier>     # e.g. compute_client 100 pro
 *   REN_TOKEN / REN_PORT override the demo defaults.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define DEF_HOST "127.0.0.1"
#define DEF_PORT 8788
#define DEF_TOKEN "CUST-1042-ok"

/* Ask the compute server to run the secret model on (qty, tier). Returns the
 * price text (into a static buffer) or NULL if the server is down or declines. */
static char *ask_price(const char *qty, const char *tier) {
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
        return NULL;
    }

    char body[256];
    int bn = snprintf(body, sizeof body, "%s %s %s", token, qty, tier);
    char req[512];
    int n = snprintf(req, sizeof req,
                     "POST /compute HTTP/1.0\r\nHost: %s\r\n"
                     "Content-Length: %d\r\n\r\n%s", host, bn, body);
    if (write(fd, req, n) != n) {
        close(fd);
        return NULL;
    }

    static char buf[4096];
    int tot = 0, r;
    while ((r = read(fd, buf + tot, sizeof buf - 1 - tot)) > 0) {
        tot += r;
        if (tot >= (int)sizeof buf - 1)
            break;
    }
    close(fd);
    buf[tot] = 0;

    if (strncmp(buf, "HTTP/1.0 200", 12) && strncmp(buf, "HTTP/1.1 200", 12))
        return NULL;
    char *resp = strstr(buf, "\r\n\r\n");
    return resp ? resp + 4 : NULL;
}

int main(int argc, char **argv) {
    const char *qty = argc > 1 ? argv[1] : "1";
    const char *tier = argc > 2 ? argv[2] : "basic";
    char *p = ask_price(qty, tier);
    if (!p) {
        printf("Quote unavailable (server unreachable or declined).\n");
        return 1;
    }
    printf("price(qty=%s, tier=%s) = %s\n", qty, tier, p);
    return 0;
}
