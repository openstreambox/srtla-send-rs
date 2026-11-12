#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

/* Test-only scheduler barrier after a sidecar read, before validation. */
static _Atomic uint64_t captured;
ssize_t read(int fd, void *buf, size_t count) {
    static _Atomic(void *) next_read;
    void *symbol = atomic_load(&next_read);
    if (!symbol) {
        symbol = dlsym(RTLD_NEXT, "read");
        atomic_store(&next_read, symbol);
    }
    ssize_t (*reader)(int, void *, size_t) = (ssize_t (*)(int, void *, size_t))symbol;
    ssize_t n = reader(fd, buf, count);
    const char *root = getenv("SRTLA_TEST_GATE");
    const char *generations = getenv("SRTLA_TEST_GENERATIONS");
    if (n <= 0 || !root || !generations) return n;
    char arm[PATH_MAX], path[PATH_MAX], target[PATH_MAX], expected[PATH_MAX];
    snprintf(arm, sizeof(arm), "%s/arm", root);
    if (access(arm, F_OK)) return n;
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(path, target, sizeof(target)-1);
    if (len <= 0) return n;
    target[len] = 0;
    snprintf(expected, sizeof(expected), "%s/map", root);
    if (strcmp(target, expected)) return n;
    const char key[] = "\"generation\":";
    char *value = memmem(buf, (size_t)n, key, sizeof(key)-1);
    if (!value) return n;
    unsigned long gen = strtoul(value + sizeof(key)-1, NULL, 10);
    if (gen >= 63) return n;
    char needle[32];
    snprintf(needle, sizeof(needle), ",%lu,", gen);
    if (!strstr(generations, needle)) return n;
    uint64_t bit = UINT64_C(1) << gen;
    if (atomic_fetch_or(&captured, bit) & bit) return n;
    snprintf(path, sizeof(path), "%s/captured-%lu", root, gen);
    int marker = open(path, O_CREAT|O_WRONLY, 0600);
    if (marker >= 0) close(marker);
    snprintf(path, sizeof(path), "%s/release-%lu", root, gen);
    while (access(path, F_OK)) usleep(1000);
    return n;
}
