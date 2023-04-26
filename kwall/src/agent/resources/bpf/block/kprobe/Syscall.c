#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/errno.h>

struct data_t {
	u64 ts;
	u32 pid;
	u32 ppid;
	int ret;
	char comm[TASK_COMM_LEN];
	char pcomm[TASK_COMM_LEN];
};

struct counter_t {
	char count;
};

BPF_HASH(counters, u32, struct counter_t);

BPF_HASH(infotmp, u32, struct data_t);
BPF_PERF_OUTPUT(placeholder_of_bpf_perf);
int placeholder_of_entry_probe_handler(struct pt_regs *ctx)
{
	u64 ts = bpf_ktime_get_boot_ns();
	struct data_t data = {};
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	u32 pid = task->pid;
	u32 ppid = task->real_parent->pid;
	data.ts = ts;
	data.pid = pid;
	data.ppid = ppid;
	data.ret = 0; // this return value will be overriden
	bpf_probe_read_kernel(&data.comm, sizeof(data.comm), task->comm);
	bpf_probe_read_kernel(&data.pcomm, sizeof(data.pcomm), task->real_parent->comm);
	infotmp.update(&pid, &data);

	// this will be based on the Alert type of the signature
	placeholder_of_action
	return 0;
};
int placeholder_of_return_probe_handler(struct pt_regs *ctx)
{
	// we get just the pid instead of the whole task struct because
	// the needed info is stored in the `infotmp` table
	u32 pid = bpf_get_current_pid_tgid() >> 32; // PID is higher part
	struct data_t *datap;
	struct data_t data = {};
	datap = infotmp.lookup(&pid);
	if (datap == 0) {
		// missed entry
		return 0;
	}
	bpf_probe_read_kernel(&data.pcomm, sizeof(data.pcomm), datap->pcomm);
	bpf_probe_read_kernel(&data.comm, sizeof(data.comm), datap->comm);
	data.ts = datap->ts;
	data.pid = datap->pid;
	data.ppid = datap->ppid;
	data.ret = PT_REGS_RC(ctx);
	// this will be based on the Alert type of the signature
	placeholder_of_perf_alert
	infotmp.delete(&pid);
	return 0;
}
