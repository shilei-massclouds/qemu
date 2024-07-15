/*
 * Helper for tracing linux-syscall.
 */

#include "syscall_trace.h"

static void formalize_str(uint8_t *data, size_t size)
{
    uint8_t *end = memchr(data, '\0', size);
    if (end == NULL) {
        end = data + size;
        end[-1] = '\0';
    }
}

static void handle_path(int index, CPUState *cs, trace_event_t *evt, FILE *f)
{
    uint8_t data[64];
    cpu_memory_rw_debug(cs, evt->ax[index], data, sizeof(data), 0);
    formalize_str(data, sizeof(data));
    lk_trace_payload(index, evt, data, sizeof(data), f);
}

// args[1]: path (cstr)
static void do_openat(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(1, cs, evt, f);
}

static void do_faccessat(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(1, cs, evt, f);
}

static void do_fstatat_in(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(1, cs, evt, f);
}

static void do_fstatat_out(CPUState *cs, trace_event_t *evt, FILE *f)
{
    // sizeof(struct stat): 128 bytes.
    uint8_t data[128];
    cpu_memory_rw_debug(cs, evt->ax[2], data, sizeof(data), 0);
    lk_trace_payload(2, evt, data, sizeof(data), f);
}

// args[0]: new_utsname
static void do_uname(CPUState *cs, trace_event_t *evt, FILE *f)
{
    // sizeof(struct new_utsname) is 390, 8bytes-alignment
    uint8_t data[392];
    cpu_memory_rw_debug(cs, evt->orig_a0, data, sizeof(data), 0);
    lk_trace_payload(0, evt, data, sizeof(data), f);
}

void handle_payload_in(CPUState *cs, trace_event_t *evt, FILE *f)
{
    switch (evt->ax[7])
    {
    case __NR_openat:
        do_openat(cs, evt, f);
        break;
    case __NR_faccessat:
        do_faccessat(cs, evt, f);
        break;
    case __NR_fstatat:
        do_fstatat_in(cs, evt, f);
        break;
    default:
        ;
    }
}

void handle_payload_out(CPUState *cs, trace_event_t *evt, FILE *f)
{
    if (evt->ax[0] != 0) {
        return;
    }

    switch (evt->ax[7])
    {
    case __NR_uname:
        do_uname(cs, evt, f);
        break;
    case __NR_fstatat:
        do_fstatat_out(cs, evt, f);
        break;
    default:
        ;
    }
}
