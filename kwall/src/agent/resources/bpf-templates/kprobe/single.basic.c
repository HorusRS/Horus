#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
struct val_t {
    u32 id;
    char comm[TASK_COMM_LEN];
};

struct data_t {
    u32 id;
    int ret;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(infotmp, u32, struct val_t);
BPF_PERF_OUTPUT(placeholder_of_bpf_perf);
int placeholder_of_entry_probe_handler(struct pt_regs *ctx)
{
	struct val_t val = {};
	u32 id = bpf_get_current_pid_tgid() >> 32; // PID is higher part
	if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
		val.id = id;
		infotmp.update(&id, &val);
	}
	return 0;
};
int placeholder_of_return_probe_handler(struct pt_regs *ctx)
{
	u32 id = bpf_get_current_pid_tgid() >> 32;
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
	placeholder_of_bpf_perf.perf_submit(ctx, &data, sizeof(data));
	infotmp.delete(&id);
	return 0;
}
