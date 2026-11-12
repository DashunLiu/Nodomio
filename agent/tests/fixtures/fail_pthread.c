#define _GNU_SOURCE
#include <pthread.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>
static _Atomic int calls;
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start)(void *), void *arg) {
    int n = atomic_fetch_add(&calls, 1) + 1;
    const char *at = getenv("NODOMI_FAIL_PTHREAD_AT");
    if (at && n == atoi(at)) { fprintf(stderr, "Injected pthread_create EAGAIN at call %d\n", n); return EAGAIN; }
    int (*real_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *) = dlsym(RTLD_NEXT, "pthread_create");
    return real_create(thread, attr, start, arg);
}
