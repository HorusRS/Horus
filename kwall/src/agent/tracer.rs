use {
	bcc::{
		Kprobe,
		Kretprobe,
		BPF,
		BccError,
		perf_event::{
			PerfMap,
			PerfMapBuilder,
		},
	},
	std::{
		ptr,
		collections::HashMap,
	},
};

use {
	hrs_common::{
		sig,
		sig::Hash,
	},
};


#[repr(C)]
struct data_t {
    id: u32,
    ret: isize,
    comm: [u8; 16],   // TASK_COMM_LEN
}

pub struct Tracer {
	pub perf_maps: Vec<PerfMap>,
	// pub signatures: HashMap<sig::SignatureHash, sig::SignatureEntry>,
}

impl Tracer {
	pub fn new() -> Self {

		// init signatures hash map
		Self {
			// signatures: HashMap::new(),
			perf_maps: Vec::new(),
		}
	}

	pub fn run_signatures(&mut self, signatures: &HashMap<sig::SignatureHash, sig::SignatureEntry>) {
		for (sig_hash, sig) in signatures {
			run_signature(sig_hash, sig);
		}
	}

}

fn run_signature(sig_hash: &sig::SignatureHash, sig: &sig::SignatureEntry) {
	let mut module = BPF::new(generate_bpf_c_block_for_sig_hash(sig_hash, sig).as_str())
		.expect("Can't compile eBPF");
	let kernel_function_name = module.get_syscall_fnname(sig._data.as_str());
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

	// this table is the way to get data back from the probe
	let table = module.table(&sig_hash.to_output()).unwrap();
	let mut perf_map = PerfMapBuilder::new(table, perf_data_callback).build().unwrap();
	// print a header
	println!("{:-7} {:-16} ", "PID", "COMM");
	// this `.poll()` loop is what makes our callback get called
	// perf_map.poll(200);
	loop {
		perf_map.poll(200);
	}
}

fn perf_data_callback() -> Box<dyn FnMut(&[u8]) + Send> {
	Box::new(|x| {
		// This callback
		let data = bytes_to_proc_data(x);
		println!(
			"{:-7} {:-16}",
			data.id,
			bytes_to_string(&data.comm),
		);
	})
}

fn generate_bpf_c_block_for_sig_hash(sig_hash: &sig::SignatureHash, sig: &sig::SignatureEntry) -> String {
	match sig._type.as_str() {
		"systemcalls.single.basic" => {
			let mut code = include_str!("resources/bpf-templates/kprobe/single.basic.c").to_string();
			code = code.replace("placeholder_of_bpf_perf", &sig_hash.to_output());
			code = code.replace("placeholder_of_entry_probe_handler", &sig_hash.to_handle("kprobe"));
			code = code.replace("placeholder_of_return_probe_handler", &sig_hash.to_handle("kretprobe"));
			return code;
		},
		_ => {
			println!("Error: Unsupported BPF type: {}", sig._type);
			"Error: Unsupported BPF type".to_string()
		}
	}
}

fn bytes_to_string(x: &[u8]) -> String {
	match x.iter().position(|&r| r == 0) {
		Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
		None => String::from_utf8_lossy(x).to_string(),
	}
}

fn bytes_to_proc_data(x: &[u8]) -> data_t {
	unsafe { ptr::read_unaligned(x.as_ptr() as *const data_t) }
}
