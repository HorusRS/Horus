use {
	colored::Colorize,
	lazy_static::lazy_static,
	bcc::{
		Kprobe,
		Kretprobe,
		Tracepoint,
		BPF,
		// BccError,
		perf_event::{
			PerfMap,
			PerfMapBuilder,
		},
	},
	std::{
		sync::{
			Arc,
			Mutex,
		},
		thread,
		fs,
		ptr,
		collections::HashMap,
		error::Error,
	},
	libc::c_int,
	libseccomp::{
		ScmpFilterContext,
		ScmpSyscall,
		ScmpAction,
	},
	nix::{
		sys::{
			ptrace,
			wait,
		},
		unistd::{
			Pid
		},
	},
	chrono::{
		DateTime,
		Utc,
	},
};

use {
	hrs_common::{
		sig,
		sig::{
			SignatureEntry,
			SignatureHash,
			Hash,
			SignatureData,
			Action,
			AlertBehavior,
		},
	},
};

#[repr(C)]
struct general_data_t {
	ts: u64,
	pid: u32,
	ppid: u32,
	ret: c_int,
	comm: [u8; 16],   // TASK_COMM_LEN
	pcomm: [u8; 16],   // TASK_COMM_LEN
}

#[repr(C)]
struct FileAccess_data_t {
	ts: u64,
	pid: u32,
	ppid: u32,
	ret: c_int,
	comm: [u8; 16],   // TASK_COMM_LEN
	pcomm: [u8; 16],   // TASK_COMM_LEN
	fname: [u8; 256],   // NAME_MAX
}

pub fn run_signature(sig_hash: &sig::SignatureHash, sig: &sig::SignatureEntry) {
	match &sig.data {
		SignatureData::Syscall(fname) => run_syscall_signature(sig_hash, sig, fname), // fname -> function name
		SignatureData::FileAccess(fnames) => run_fileaccess_signature(sig_hash, sig, fnames), // fname -> file name
	};
}

fn run_syscall_signature(sig_hash: &sig::SignatureHash, sig: &sig::SignatureEntry, fname: &str) {
	let mut module = BPF::new(generate_bpf_for_syscall_signature(sig_hash, sig).as_str())
		.expect("Can't compile eBPF");
	let kernel_function_name = module.get_syscall_fnname(fname);
	Kprobe::new()
		.handler(&sig_hash.to_handle("kprobe"))
		.function(&kernel_function_name)
		.attach(&mut module)
		.expect("Can't attach kprobe");
	Kretprobe::new()
		.handler(&sig_hash.to_handle("kretprobe"))
		.function(&kernel_function_name)
		.attach(&mut module)
		.expect("Can't attach kretprobe");

	let module = Arc::new(Mutex::new(module));
	let module_clone = Arc::clone(&module);
	let sig_hash = sig_hash.clone();
	let sig = sig.clone();
	thread::spawn(move || {
		// this table is the way to get data back from the probe
		let table = module_clone.lock().unwrap().table(&sig_hash.to_output()).unwrap();
		// this `.poll()` loop is what makes our callback get called
		let mut perf_map = PerfMapBuilder::new(table, generate_callback_function(&sig)).build().unwrap();
		loop {
			perf_map.poll(200);
		}
	});
}

fn run_fileaccess_signature(sig_hash: &sig::SignatureHash, sig: &sig::SignatureEntry, fnames: &Vec<String>) {
	let mut module = BPF::new(generate_bpf_for_fileaccess_signature(sig_hash, sig, fnames).as_str())
		.expect("Can't compile eBPF");
	Tracepoint::new()
		.handler(&sig_hash.to_handle("entry_tracepoint"))
		.subsystem("syscalls")
		.tracepoint("sys_enter_openat")
		.attach(&mut module)
		.expect("Can't attach kprobe");
	Tracepoint::new()
		.handler(&sig_hash.to_handle("exit_tracepoint"))
		.subsystem("syscalls")
		.tracepoint("sys_exit_openat")
		.attach(&mut module)
		.expect("Can't attach kretprobe");

	let module = Arc::new(Mutex::new(module));
	let module_clone = Arc::clone(&module);
	let sig_hash = sig_hash.clone();
	let sig = sig.clone();
	thread::spawn(move || {
		// this table is the way to get data back from the probe
		let table = module_clone.lock().unwrap().table(&sig_hash.to_output()).unwrap();
		// this `.poll()` loop is what makes our callback get called
		let mut perf_map = PerfMapBuilder::new(table, generate_callback_function(&sig)).build().unwrap();
		loop {
			perf_map.poll(200);
		}
	});
}

fn generate_callback_function(sig: &SignatureEntry) -> impl Fn() -> Box<dyn FnMut(&[u8]) + Send> {
	let sig = sig.clone();
	move || -> Box<dyn FnMut(&[u8]) + Send> {
		let sig = sig.clone(); // move into the final function that will be used
		Box::new( move |bytes_received| {
			// This is the actual callback
			let data = bytes_to_data::<general_data_t>(bytes_received);
			let pcomm = bytes_to_string(&data.pcomm);
			let comm = bytes_to_string(&data.comm);
			let pcmdline = read_cmdline(data.ppid).unwrap_or_else(|_| pcomm.clone());
			let cmdline = read_cmdline(data.pid).unwrap_or_else(|_| comm.clone());
			let command = if cmdline.contains(&comm) {
				cmdline
			} else {
				comm
			};
			let pcommand = if pcmdline.contains(&pcomm) {
				pcmdline
			} else {
				pcomm
			};

			let entry = format!("{:55} {} => {}",
								format!("[ {} | {} ]", sig.name, get_real_datetime(data.ts)).truecolor(128, 128, 128),
								format!("{:-7} -> {:-30}", data.ppid, pcommand).blue(),
								format!("{:-7} -> {:-30}", data.pid, command).red(),
								);

			println!("{}", entry);
			if let SignatureData::Syscall(syscall) = &sig.data {
				if let Action::Seccomp = &sig.action {
					// needed this override option to perform seccomp
					if check_bpf_kprobe_override() {
					// seccomp applies to syscalls only
						match inject_seccomp(&syscall, Pid::from_raw(data.pid as i32)) {
							Ok(_) => println!("Seccomp filter injected successfully."),
							Err(e) => eprintln!("Failed to inject seccomp filter: {}", e),
						}
					}
				}
			}
		})
	}
}

fn generate_fileaccess_statement(fnames: &Vec<String>) -> String {
	let mut fname_blocks = Vec::new();
	for fname in fnames {
		fname_blocks.push(include_str!("resources/bpf/detect/file.c").to_string()
						.replace("placeholder_for_sign", "==") // fileaccess -> operate if a file matches
						.replace("placeholder_for_fname", fname));
	}

	let whitelist_ifs = fname_blocks.join(" || ");

	include_str!("resources/bpf/statement/if.c").to_string()
		.replace("placeholder_of_statement", &whitelist_ifs)
		.replace("placeholder_of_true", "placeholder_of_fileaccess_true")
}

fn surround_in_fileaccess_statement(fileaccess_statement: &str, snippet: &str) -> String {
	fileaccess_statement.to_string()
		.replace("placeholder_of_fileaccess_true", snippet)
}

fn generate_whitelist_statement(programs: &Option<Vec<String>>) -> String {
	match programs {
		Some(programs) => {
			let mut whitelist_blocks = Vec::new();
			for program in programs {
				whitelist_blocks.push(include_str!("resources/bpf/detect/comm.c").to_string()
								.replace("placeholder_for_sign", "!=") // whitelisting -> operate if the command *doesn't* match
								.replace("placeholder_for_comm", program));
			}

			let whitelist_ifs = whitelist_blocks.join(" && ");

			include_str!("resources/bpf/statement/if.c").to_string()
				.replace("placeholder_of_statement", &whitelist_ifs)
				.replace("placeholder_of_true", "placeholder_of_whitelist_false")
		}
		None => "placeholder_of_whitelist_false".to_string(),
	}
}

fn surround_in_whitelist_statement(whitelist_statement: &str, snippet: &str) -> String {
	whitelist_statement.to_string()
		.replace("placeholder_of_whitelist_false", snippet)
}

fn generate_bpf_for_syscall_signature(sig_hash: &SignatureHash, sig: &SignatureEntry) -> String {
	let mut code = include_str!("resources/bpf/block/kprobe/Syscall.c").to_string();
	// generate whitelist (if exists) before anything else in order to make sure they get whitelisted
	let whitelist = generate_whitelist_statement(&sig.whitelist);
	// insert alert command based on alert type inside whitelist block
	// replace action placeholder into an action placeholder placed inside whitelist
	code = match &sig.action {
		Action::Block => code.replace("placeholder_of_action",
							&surround_in_whitelist_statement(&whitelist, include_str!("resources/bpf/action/kprobe/block.c"))),
		Action::Kill => code.replace("placeholder_of_action",
							&surround_in_whitelist_statement(&whitelist, include_str!("resources/bpf/action/kill.c"))),
		Action::Seccomp => code.replace("placeholder_of_action", ""), // seccomp isn't performed inside the eBPF
		Action::None => code.replace("placeholder_of_action", ""), // None will do nothing:)
	};
	code = match &sig.alert {
		AlertBehavior::Single => code.replace("placeholder_of_perf_alert",
							&surround_in_whitelist_statement(&whitelist, include_str!("resources/bpf/perf/kprobe/alert.single.c"))),
		AlertBehavior::Standard => code.replace("placeholder_of_perf_alert",
				&surround_in_whitelist_statement(&whitelist, include_str!("resources/bpf/perf/kprobe/alert.default.c"))),
		AlertBehavior::None => code.replace("placeholder_of_perf_alert", ""),
	};
	// replace basic (entry, return, bpf_perf) placeholders last
	code = code.replace("placeholder_of_bpf_perf", &sig_hash.to_output())
			.replace("placeholder_of_entry_handler", &sig_hash.to_handle("kprobe"))
			.replace("placeholder_of_return_handler", &sig_hash.to_handle("kretprobe"))
			.replace("placeholder_of_infotmp", &sig_hash.to_handle("infotmp_table"))
			.replace("placeholder_of_count", &sig_hash.to_handle("count_table"));
	code
}

fn generate_bpf_for_fileaccess_signature(sig_hash: &SignatureHash, sig: &SignatureEntry, fnames: &Vec<String>) -> String {
	let mut code = include_str!("resources/bpf/block/tracepoint/FileAccess.c").to_string();
	// generate whitelist (if exists) before anything else in order to make sure they get whitelisted
	let whitelist = generate_whitelist_statement(&sig.whitelist);
	let fileaccess = generate_fileaccess_statement(fnames);
	// insert alert command based on alert type inside whitelist block
	// replace action placeholder into an action placeholder placed inside whitelist
	code = match &sig.action {
		Action::Kill => code.replace("placeholder_of_action",
							&surround_in_whitelist_statement(&whitelist,
							&surround_in_fileaccess_statement(&fileaccess,
							include_str!("resources/bpf/action/kill.c")))),
		Action::Seccomp => code.replace("placeholder_of_action", ""), // seccomp isn't performed inside the eBPF
		Action::Block => code.replace("placeholder_of_action", ""), // block isn't possible in tracepoints
		Action::None => code.replace("placeholder_of_action", ""), // None will do nothing:)
	};
	code = match &sig.alert {
		AlertBehavior::Single => code.replace("placeholder_of_perf_alert",
							&surround_in_whitelist_statement(&whitelist,
							&surround_in_fileaccess_statement(&fileaccess,
							include_str!("resources/bpf/perf/tracepoint/alert.single.c")))),
		AlertBehavior::Standard => code.replace("placeholder_of_perf_alert",
							&surround_in_whitelist_statement(&whitelist,
							&surround_in_fileaccess_statement(&fileaccess,
							include_str!("resources/bpf/perf/tracepoint/alert.default.c")))),
		AlertBehavior::None => code.replace("placeholder_of_perf_alert", ""),
	};
	// replace basic (entry, return, bpf_perf) placeholders last
	code = code.replace("placeholder_of_bpf_perf", &sig_hash.to_output())
			.replace("placeholder_of_entry_handler", &sig_hash.to_handle("entry_tracepoint"))
			.replace("placeholder_of_return_handler", &sig_hash.to_handle("exit_tracepoint"))
			.replace("placeholder_of_infotmp", &sig_hash.to_handle("infotmp_table"))
			.replace("placeholder_of_tracepoint_actions", &sig_hash.to_handle("actions_table"))
			.replace("placeholder_of_count", &sig_hash.to_handle("count_table"));
	code
}

fn check_bpf_kprobe_override() -> bool {
	let kernel_config = match fs::read_to_string("/boot/config-$(uname -r)") {
		Ok(config) => config,
		Err(_) => return false,
	};

	kernel_config.contains("CONFIG_BPF_KPROBE_OVERRIDE=y")
}

fn setup_seccomp(fname: &str) -> Result<(), Box<dyn Error>> {
	let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
	let action = ScmpAction::Errno(libc::EPERM as i32);

	let syscall = ScmpSyscall::from_name(fname)?;
	filter.add_rule(action, syscall)?;

	filter.load()?;
	Ok(())
}

fn inject_seccomp(fname: &str, pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
	// Attach to the target process
	ptrace::attach(pid)?;
	wait::waitpid(pid, None)?;

	// Inject seccomp filter
	setup_seccomp(fname)?;

	// Detach and continue the process execution
	ptrace::detach(pid, None)?;
	Ok(())
}

fn get_real_datetime(ts: u64) -> String {
	lazy_static! {
		static ref BOOT_TIME: DateTime<chrono::Utc> = get_boot_time();
	}

	let ts_in_ms = ts / 1_000_000;
	let timestamp = BOOT_TIME.with_timezone(&chrono::Local) + chrono::Duration::milliseconds(ts_in_ms as i64);
	// time format is ISO-8601: %Y-%m-%dT%H:%M:%S%z (e.g. "2023-04-26T10:30:00-0700")
	timestamp.format("%Y-%m-%dT%H:%M:%S%z").to_string()
}

fn get_boot_time() -> DateTime<chrono::Utc> {
	let contents = fs::read_to_string("/proc/stat").expect("Failed to read /proc/stat");
	let line = contents
		.lines()
		.find(|line| line.starts_with("btime"))
		.expect("Failed to find boot time in /proc/stat");

	let boot_time: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
	DateTime::<chrono::Utc>::from_utc(chrono::NaiveDateTime::from_timestamp(boot_time as i64, 0), chrono::Utc)
}

fn read_cmdline(pid: u32) -> Result<String, std::io::Error> {
	let path = format!("/proc/{}/cmdline", pid);
	let content = fs::read_to_string(path)?;
	let args: Vec<&str> = content.split('\0').collect();
	Ok(args.join(" "))
}

fn bytes_to_string(x: &[u8]) -> String {
	match x.iter().position(|&r| r == 0) {
		Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
		None => String::from_utf8_lossy(x).to_string(),
	}
}

fn bytes_to_data<T>(x: &[u8]) -> T {
	unsafe { ptr::read_unaligned(x.as_ptr() as *const T) }
}
