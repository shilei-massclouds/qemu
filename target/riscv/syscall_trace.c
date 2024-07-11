/*
 * Helper for tracing linux-syscall.
 */

#include "syscall_trace.h"

static void do_openat(CPUState *cs, trace_event_t *evt, FILE *f)
{
    uint8_t data[64];
    cpu_memory_rw_debug(cs, evt->ax[1], data, sizeof(data), 0);
    lk_trace_payload(1, evt, data, sizeof(data), f);
}

void handle_payload(CPUState *cs, trace_event_t *evt, FILE *f)
{
    switch (evt->ax[7])
    {
    case __NR_openat:
        do_openat(cs, evt, f);
        break;
    default:
        printf("unknown sysno: %lx\n", evt->ax[7]);
    }
}
