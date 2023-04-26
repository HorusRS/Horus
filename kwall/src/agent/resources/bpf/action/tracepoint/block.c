char action = tracepoint_actions.lookup(&pid);
if (!action) {
	char action = 1;
	tracepoint_actions.update(&pid, &action);
}
