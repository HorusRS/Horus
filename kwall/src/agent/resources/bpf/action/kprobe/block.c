// Block the system call by overriding its return value
bpf_override_return(ctx, -EPERM); // "Operation not permitted"
