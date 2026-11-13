#define _GNU_SOURCE
#include <dlfcn.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Test-only: one host name whose lookup hangs like an unreachable resolver. */
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    const char *host = getenv("SRTLA_TEST_SLOW_HOST");
    const char *ms = getenv("SRTLA_TEST_SLOW_MS");
    if (node && host && ms && !strcmp(node, host)) {
        unsigned long delay = strtoul(ms, NULL, 10);
        struct timespec left = {(time_t)(delay / 1000), (long)(delay % 1000) * 1000000L};
        while (nanosleep(&left, &left)) {}
        return EAI_AGAIN;
    }
    int (*next)(const char *, const char *, const struct addrinfo *, struct addrinfo **) =
        (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **))
            dlsym(RTLD_NEXT, "getaddrinfo");
    return next(node, service, hints, res);
}
