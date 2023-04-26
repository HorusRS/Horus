/*
 * this template is for alerting once per process (once per pid)
*/
struct counter_t *counter;
counter = counters.lookup(&pid);
if (!counter) {
	// mark this process as counted
	struct counter_t new_counter = {.count = 1};
	counters.update(&pid, &new_counter);
	placeholder_of_bpf_perf.perf_submit(ctx, &data, sizeof(data));
}
