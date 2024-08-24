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

static void handle_path(int index, uint64_t addr, CPUState *cs, trace_event_t *evt, FILE *f)
{
    uint8_t data[64];
    cpu_memory_rw_debug(cs, addr, data, sizeof(data), 0);
    formalize_str(data, sizeof(data));
    lk_trace_payload(index, evt, data, sizeof(data), f);
}

// args[1]: path (cstr)
static void do_openat(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(1, evt->ax[1], cs, evt, f);
}

static void do_faccessat(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(1, evt->ax[1], cs, evt, f);
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

static void handle_string_at_heap(int index, uint64_t size, CPUState *cs, trace_event_t *evt, FILE *f) {
    uint8_t* data = malloc(size*sizeof(uint8_t));
    if (data == NULL) {
        fprintf(stderr,"qemu malloc failed");
        return ;
    }
    cpu_memory_rw_debug(cs, evt->ax[1], data, sizeof(uint8_t)*(size), 0);
    formalize_str(data,sizeof(uint8_t)*size);
    lk_trace_payload(index, evt, data, sizeof(uint8_t)*size, f);
    free(data);
}
static void do_write_event(CPUState *cs, trace_event_t *evt, FILE *f)
{
    if (evt->orig_a0 == 1 || evt->orig_a0 == 2) {
        uint64_t actual_write_size = evt->ax[0]+1;// + 1 for \0 and if error -1+1 == 0
        handle_string_at_heap(1,actual_write_size,cs,evt,f);
    }
}

/*
static void do_writev_event(CPUState *cs, trace_event_t *evt, FILE *f)
{
    uint64_t actual_write_size = evt->ax[0]+1;// + 1 for \0 and if error -1+1 == 0
    handle_string_at_heap(1,actual_write_size,cs,evt,f);
}
*/

static void do_read_event(CPUState *cs, trace_event_t *evt, FILE *f)
{
    if (evt->orig_a0 == 0) {
        uint64_t actual_write_size = evt->ax[0]+1;// + 1 for \0 and if error -1+1 == 0
        handle_string_at_heap(1,actual_write_size,cs,evt,f);
    }
}

static void do_execve(CPUState *cs, trace_event_t *evt, FILE *f)
{
    uint64_t argc = 0;
    char *const argv;

    handle_path(0, evt->ax[0], cs, evt, f);

    cpu_memory_rw_debug(cs, evt->ax[1], (uint8_t *)&argv, sizeof(char *), 0);
    while (argv != NULL) {
        argc += 1;
        uint8_t data[64]; // just reserve 64 bytes.
        cpu_memory_rw_debug(cs, (uint64_t)argv, data, sizeof(data), 0);
        formalize_str(data, sizeof(data));
        lk_trace_payload(1, evt, data, sizeof(data), f);
        cpu_memory_rw_debug(cs, evt->ax[1]+argc*sizeof(char *), (uint8_t *)&argv, sizeof(char *), 0);
    }
    uint64_t envc = 0;
    char *const envp;
    cpu_memory_rw_debug(cs, evt->ax[2], (uint8_t *)&envp, sizeof(char *), 0);
    while (envp != NULL) {
        envc += 1;
        uint8_t data[64]; // just reserve 64 bytes.
        cpu_memory_rw_debug(cs, (uint64_t)envp, data, sizeof(data), 0);
        formalize_str(data, sizeof(data));
        lk_trace_payload(2, evt, data, sizeof(data), f);
        cpu_memory_rw_debug(cs, evt->ax[2]+envc*sizeof(char *), (uint8_t *)&envp, sizeof(char *), 0);
    }
}

static void do_rt_sigaction(CPUState *cs, trace_event_t *evt, FILE *f)
{
    //
    // Type of argv[1] is sigaction.
    // struct sigaction {
    //     __sighandler_t sa_handler;
    //     unsigned long sa_flags;
    //     sigset_t sa_mask;       /* mask last for extensibility */
    // };
    // Its size is 24.
    //

    uint8_t data[24];
    if (evt->ax[0] == 0) {
        if (evt->ax[1] != 0) {
            cpu_memory_rw_debug(cs, evt->ax[1], data, sizeof(data), 0);
            lk_trace_payload(1, evt, data, sizeof(data), f);
        }
    }
}

static void do_rt_sigprocmask(CPUState *cs, trace_event_t *evt, FILE *f)
{
    uint64_t data;
    if (evt->ax[0] == 0) {
        if (evt->ax[1]) {
            cpu_memory_rw_debug(cs, evt->ax[1], &data, sizeof(data), 0);
            lk_trace_payload(1, evt, &data, sizeof(data), f);
        }
        if (evt->ax[2]) {
            cpu_memory_rw_debug(cs, evt->ax[2], &data, sizeof(data), 0);
            lk_trace_payload(2, evt, &data, sizeof(data), f);
        }
    }
}

static void do_statfs64(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(0, evt->orig_a0, cs, evt, f);
    // sizeof(struct statfs64) is 88 bytes.
    uint8_t data[120];
    if (evt->ax[0] == 0) {
        cpu_memory_rw_debug(cs, evt->ax[1], data, sizeof(data), 0);
        lk_trace_payload(1, evt, data, sizeof(data), f);
    }
}

static void do_mknodat(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(1, evt->ax[1], cs, evt, f);
}

static void do_getcwd(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(0, evt->orig_a0, cs, evt, f);
}

static void do_mkdirat(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(1, evt->ax[1], cs, evt, f);
}

static void do_unlinkat(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(1, evt->ax[1], cs, evt, f);
}

static void do_symlinkat(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(0, evt->orig_a0, cs, evt, f);
    handle_path(2, evt->ax[2], cs, evt, f);
}

static void do_chdir(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(0, evt->orig_a0, cs, evt, f);
}
static void do_mount(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(0, evt->orig_a0, cs, evt, f);
}

static void do_fchmodat(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(1, evt->ax[1], cs, evt, f);
}

static void do_fchownat(CPUState *cs, trace_event_t *evt, FILE *f)
{
    handle_path(1, evt->ax[1], cs, evt, f);
}

static void do_pipe2(CPUState *cs, trace_event_t *evt, FILE *f)
{
    if (evt -> ax[0] == 0) {
        uint8_t data[16];
        cpu_memory_rw_debug(cs, evt->orig_a0, data, sizeof(data), 0);
        lk_trace_payload(0, evt, data, sizeof(data), f);
    }
}

static void do_prlimit64(CPUState *cs, trace_event_t *evt, FILE *f)
{
    if (evt->ax[0] == 0) {
        if (evt->ax[2] != 0) {
            uint8_t data[16];
            cpu_memory_rw_debug(cs, evt->ax[2], data, sizeof(data), 0);
            lk_trace_payload(2, evt, data, sizeof(data), f);
        }
        if (evt->ax[3] != 0) {
            uint8_t data[16];
            cpu_memory_rw_debug(cs, evt->ax[3], data, sizeof(data), 0);
            lk_trace_payload(3, evt, data, sizeof(data), f);
        }
    }
}

void handle_payload_in(CPUState *cs, trace_event_t *evt, FILE *f)
{
    switch (evt->ax[7])
    {
    case __NR_execve:
        do_execve(cs, evt, f);
        break;
    default:
        ;
    }
}

void handle_payload_out(CPUState *cs, trace_event_t *evt, FILE *f)
{
    switch (evt->ax[7])
    {
    case __NR_getcwd:
        do_getcwd(cs, evt, f);
        break;
    case __NR_mknodat:
        do_mknodat(cs, evt, f);
        break;
    case __NR_openat:
        do_openat(cs, evt, f);
        break;
    case __NR_uname:
        do_uname(cs, evt, f);
        break;
    case __NR_faccessat:
        do_faccessat(cs, evt, f);
        break;
    case __NR_read:
        do_read_event(cs, evt, f);
        break;
    case __NR_write:
        do_write_event(cs, evt, f);
        break;
    case __NR_rt_sigaction:
        do_rt_sigaction(cs, evt, f);
        break;
    case __NR_statfs64:
        do_statfs64(cs, evt, f);
        break;
    case __NR_mkdirat:
        do_mkdirat(cs, evt, f);
        break;
    case __NR_unlinkat:
        do_unlinkat(cs, evt, f);
        break;
    case __NR_symlinkat:
        do_symlinkat(cs, evt, f);
        break;  
    case __NR_mount:
        do_mount(cs, evt, f);
        break;
    case __NR_chdir:
        do_chdir(cs, evt, f);
        break;
    case __NR_fchmodat:
        do_fchmodat(cs, evt, f);
        break;
    case __NR_fchownat:
        do_fchownat(cs, evt, f);
        break;
    case __NR_pipe2:
        do_pipe2(cs, evt, f);
        break;
    case __NR_rt_sigprocmask:
        do_rt_sigprocmask(cs, evt, f);
        break;
        /*
    case __NR_writev:
        do_writev_event(cs, evt, f);
        break;
        */
    case __NR_fstatat:
        handle_path(1, evt->ax[1], cs, evt, f);
        do_fstatat_out(cs, evt, f);
        break;
    case __NR_utimensat:
        handle_path(1, evt->ax[1], cs, evt, f);
        break;
    case __NR_prlimit64:
        do_prlimit64(cs, evt, f);
    default:
        ;
    }
}
