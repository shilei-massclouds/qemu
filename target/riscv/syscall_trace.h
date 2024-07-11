/*
 * Helper for tracing linux-syscall.
 */

#ifndef RISCV_SYSCALL_TRACE_H
#define RISCV_SYSCALL_TRACE_H

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"

#define __NR_openat 56

void handle_payload(CPUState *cs, trace_event_t *evt, FILE *f);

#endif /* RISCV_SYSCALL_TRACE_H */
