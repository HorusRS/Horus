/*
 * this template is for alerting once per process (once per pid)
*/
char *counter = placeholder_of_count.lookup(&pid);
if (!counter) {
	// mark this process as counted
	char new_counter = 1;
	placeholder_of_count.update(&pid, &new_counter);
	placeholder_of_bpf_perf.perf_submit(args, &data, sizeof(data));
}
