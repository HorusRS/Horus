#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/errno.h>

BPF_HASH(tracepoint_actions, u32, char);

int placeholder_of_entry_probe_handler(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32; // PID is higher part
	char action = tracepoint_actions.lookup(&pid);
	if (action) {
		// this will be based on the Alert type of the signature
		placeholder_of_action
		// Remove the thread ID from the BPF_HASH
		tracepoint_actions.delete(&tid);
	}
}
