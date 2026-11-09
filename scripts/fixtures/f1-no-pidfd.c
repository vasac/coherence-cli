/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * https://oss.oracle.com/licenses/upl.
 */

/* Linux-only test launcher. Restrict this process and its descendants only.
 * Go starts after the filter is installed, so its actual pidfd capability probe
 * receives ENOSYS. This is a recorded restricted policy, not an older-kernel or
 * injected Go-observer result. No privilege or global policy change is needed.
 */
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fputs("usage: f1-no-pidfd <owned-test-program> [arguments...]\n", stderr);
        return 2;
    }
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pidfd_open, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
        perror("owned pidfd-denial policy");
        return 125;
    }
    fprintf(stderr, "F1 native policy: pidfd_open returns ENOSYS; no_new_privs; original PID=%ld\n", (long)getpid());
    execvp(argv[1], argv + 1);
    perror("exec owned native test");
    return 126;
}
