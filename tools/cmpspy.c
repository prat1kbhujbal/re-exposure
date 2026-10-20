/*
 * cmpspy -- LD_PRELOAD comparison spy for the agent-attack harness.
 *
 * Intercepts the libc string-comparison calls a license check lands on and
 * logs their operands before forwarding to the real implementation. Running a
 * target under this shim is the "debugger" step of a reverse-engineering agent:
 * whatever the program compares the user's key against is printed in the clear
 * at the moment of the call, even if it was XOR-encrypted on disk and decrypted
 * at load. It recovers nothing that the program does not itself reconstruct in
 * memory -- which is exactly why static string encryption does not stop it.
 *
 *   gcc -shared -fPIC -o cmpspy.so cmpspy.c -ldl
 *   LD_PRELOAD=./cmpspy.so ./target PROBE 2>&1 | grep CMPSPY
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static int (*real_strcmp)(const char *, const char *);
static int (*real_strncmp)(const char *, const char *, size_t);
static int (*real_strcasecmp)(const char *, const char *);
static int (*real_memcmp)(const void *, const void *, size_t);

static void logpair(const char *tag, const char *a, const char *b) {
    fprintf(stderr, "CMPSPY %s a=%s b=%s\n", tag, a ? a : "(null)",
            b ? b : "(null)");
}

int strcmp(const char *a, const char *b) {
    if (!real_strcmp) real_strcmp = dlsym(RTLD_NEXT, "strcmp");
    logpair("strcmp", a, b);
    return real_strcmp(a, b);
}

int strncmp(const char *a, const char *b, size_t n) {
    if (!real_strncmp) real_strncmp = dlsym(RTLD_NEXT, "strncmp");
    logpair("strncmp", a, b);
    return real_strncmp(a, b, n);
}

int strcasecmp(const char *a, const char *b) {
    if (!real_strcasecmp) real_strcasecmp = dlsym(RTLD_NEXT, "strcasecmp");
    logpair("strcasecmp", a, b);
    return real_strcasecmp(a, b);
}

int memcmp(const void *a, const void *b, size_t n) {
    if (!real_memcmp) real_memcmp = dlsym(RTLD_NEXT, "memcmp");
    logpair("memcmp", (const char *)a, (const char *)b);
    return real_memcmp(a, b, n);
}
