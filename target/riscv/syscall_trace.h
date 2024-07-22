/*
 * Helper for tracing linux-syscall.
 */

#ifndef RISCV_SYSCALL_TRACE_H
#define RISCV_SYSCALL_TRACE_H

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"

#define __NR_ioctl      29
#define __NR_faccessat  48
#define __NR_openat     56
#define __NR_read       63
#define __NR_write      64
#define __NR_fstatat    79

#define __NR_set_tid_address 96
#define __NR_set_robust_list 99

#define __NR_uname      160
#define __NR_brk        214
#define __NR_mmap       222
#define __NR_mprotect   226
#define __NR_prlimit64  261
#define __NR_getrandom  278

//void handle_payload_in(CPUState *cs, trace_event_t *evt, FILE *f);
void handle_payload_out(CPUState *cs, trace_event_t *evt, FILE *f);

#endif /* RISCV_SYSCALL_TRACE_H */
