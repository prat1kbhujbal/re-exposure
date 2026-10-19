#include <stdio.h>
#include <stdlib.h>
/* string-pointer table -> compiler emits `.quad <label>` references,
   exercising m3_rewrite's load-time (constructor) path. */
static const char *const msgs[] = {
    "alpha-secret-token", "beta-secret-token", "gamma-secret-token",
};
int main(int argc, char **argv) {
    int i = argc > 1 ? atoi(argv[1]) : 0;
    puts(msgs[((i % 3) + 3) % 3]);
    return 0;
}
