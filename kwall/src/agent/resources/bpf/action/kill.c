bpf_send_signal(SIGKILL);
// after seding kill, the process won't arrive to the `return` handle which sends back the data
// for thie reason, we need to send in already on the `enter` handle with a custom ret value
placeholder_of_perf_alert
