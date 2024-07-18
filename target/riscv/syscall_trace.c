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

static void do_fstatat_out(CPUState *cs, trace_event_t *evt, FILE *f)
{
    // sizeof(struct stat): 128 bytes.
    uint8_t data[128];
    if (evt->ax[0] == 0) {
        cpu_memory_rw_debug(cs, evt->ax[2], data, sizeof(data), 0);
        lk_trace_payload(2, evt, data, sizeof(data), f);
    }
}

// args[0]: new_utsname
static void do_uname(CPUState *cs, trace_event_t *evt, FILE *f)
{
    // sizeof(struct new_utsname) is 390, 8bytes-alignment
    uint8_t data[392];
    if (evt->ax[0] == 0) {
        cpu_memory_rw_debug(cs, evt->orig_a0, data, sizeof(data), 0);
        lk_trace_payload(0, evt, data, sizeof(data), f);
    }
}

static void do_write_evt(CPUState *cs, trace_event_t *evt, FILE *f)
{
    uint64_t actual_write_size = evt->ax[0];
    uint8_t* data = calloc(actual_write_size,sizeof(uint8_t));
    if (data == NULL) 
    {
        printf("qemu malloc failed while do_write_evt");
        return ;
    }
    cpu_memory_rw_debug(cs, evt->ax[1], data, sizeof(uint8_t)*(actual_write_size), 0);
    formalize_str(data,sizeof(uint8_t)*(actual_write_size));
    lk_trace_payload(1, evt, data, sizeof(uint8_t)*(actual_write_size), f);  
    free(data);
}

/*
void handle_payload_in(CPUState *cs, trace_event_t *evt, FILE *f)
{
    switch (evt->ax[7])
    {
    case __NR_fstatat:
        break;
    default:
        ;
    }
}
*/

void handle_payload_out(CPUState *cs, trace_event_t *evt, FILE *f)
{
    switch (evt->ax[7])
    {
    case __NR_openat:
        do_openat(cs, evt, f);
        break;
    case __NR_uname:
        do_uname(cs, evt, f);
        break;
    case __NR_faccessat:
        do_faccessat(cs, evt, f);
        break;
    case __NR_write:
        do_write_evt(cs, evt, f);
        break;
    case __NR_fstatat:
        handle_path(1, cs, evt, f);
        do_fstatat_out(cs, evt, f);
        break;
    default:
        ;
    }
}
