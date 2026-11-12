#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static uint64_t sync_peak;
static uint64_t sync_journal;

static int cache_root(int fd, char *root, size_t capacity) {
    char link[40];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, root, capacity - 1);
    const char suffix[] = "/ssh/ssh-buffer.sqlite3";
    size_t tail = sizeof(suffix) - 1;
    if (length < 0 || (size_t)length <= tail || (size_t)length >= capacity - 1)
        return 0;
    root[length] = '\0';
    if (strcmp(root + length - tail, suffix) != 0)
        return 0;
    root[length - tail] = '\0';
    return 1;
}

static uint64_t blocks(const char *root, const char *name) {
    char path[PATH_MAX];
    struct stat st;
    int length = snprintf(path, sizeof(path), "%s/%s", root, name);
    if (length < 0 || length >= (int)sizeof(path) || stat(path, &st) != 0)
        return 0;
    return (uint64_t)st.st_blocks * 512;
}

static int fault_stage(const char *stage) {
    const char *requested = getenv("NODOMI_TEST_COMPACTION_CRASH");
    return requested && strcmp(requested, stage) == 0;
}

static int recovery_sync_fault(int fd) {
    char root[PATH_MAX], journal[PATH_MAX];
    struct stat st;
    if (!fault_stage("recovery-sync-fails") || !cache_root(fd, root, sizeof(root)))
        return 0;
    int length = snprintf(journal, sizeof(journal), "%s/ssh/ssh-buffer.sqlite3-journal", root);
    if (length < 0 || length >= (int)sizeof(journal) || lstat(journal, &st) == 0 || errno != ENOENT)
        return 0;
    fputs("injected recovery SSH main sync EIO\n", stderr);
    errno = EIO;
    return 1;
}

static void observe_sync(int fd) {
    char root[PATH_MAX];
    if (!cache_root(fd, root, sizeof(root)))
        return;
    uint64_t journal = blocks(root, "ssh/ssh-buffer.sqlite3-journal");
    if (journal == 0)
        return;
    sync_journal = journal;
    sync_peak = journal + blocks(root, "ssh/ssh-buffer.sqlite3") +
        blocks(root, "host") + blocks(root, "ssh") +
        blocks(root, "host/runtime.lock") + blocks(root, "host/runtime.json") +
        blocks(root, "host/runtime.next") + blocks(root, "ssh/ssh-buffer.owner");
    if (fault_stage("before-unlink"))
        _exit(76);
}

static void observe_truncate(int fd, off64_t previous) {
    char root[PATH_MAX];
    struct stat now;
    if (previous < 0 || !cache_root(fd, root, sizeof(root)) ||
        fstat(fd, &now) != 0 || now.st_size >= previous)
        return;
    uint64_t remaining_journal = blocks(root, "ssh/ssh-buffer.sqlite3-journal");
    if (fault_stage("after-truncate"))
        _exit(remaining_journal == 0 ? 77 : 78);
    if (sync_journal != 0)
        fprintf(stderr, "compact_pretruncate_combined=%" PRIu64
                " journal=%" PRIu64 " main_length_before=%jd main_length_after=%jd"
                " journal_after_truncate=%" PRIu64 "\n",
                sync_peak, sync_journal, (intmax_t)previous, (intmax_t)now.st_size,
                remaining_journal);
    sync_journal = 0;
}

int fsync(int fd) {
    if (recovery_sync_fault(fd)) return -1;
    int (*next)(int) = dlsym(RTLD_NEXT, "fsync");
    int result = next(fd);
    int saved = errno;
    if (result == 0) observe_sync(fd);
    errno = saved;
    return result;
}

int fdatasync(int fd) {
    if (recovery_sync_fault(fd)) return -1;
    int (*next)(int) = dlsym(RTLD_NEXT, "fdatasync");
    int result = next(fd);
    int saved = errno;
    if (result == 0) observe_sync(fd);
    errno = saved;
    return result;
}

int ftruncate(int fd, off_t length) {
    int (*next)(int, off_t) = dlsym(RTLD_NEXT, "ftruncate");
    struct stat old;
    off64_t before = fstat(fd, &old) == 0 ? old.st_size : -1;
    int result = next(fd, length);
    int saved = errno;
    if (result == 0) observe_truncate(fd, before);
    errno = saved;
    return result;
}

int ftruncate64(int fd, off64_t length) {
    int (*next)(int, off64_t) = dlsym(RTLD_NEXT, "ftruncate64");
    struct stat old;
    off64_t before = fstat(fd, &old) == 0 ? old.st_size : -1;
    int result = next(fd, length);
    int saved = errno;
    if (result == 0) observe_truncate(fd, before);
    errno = saved;
    return result;
}
