#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>


struct __attribute__((__packed__))val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    
};
struct __attribute__((__packed__))data_t {
    u64 id;
    int ret;
    char comm[TASK_COMM_LEN];
};


BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(events);
int trace_entry(struct pt_regs *ctx, int dfd)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        infotmp.update(&id, &val);
    }
    return 0;
};
int trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};
    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    data.id = valp->id;
    data.ret = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);
    return 0;
}