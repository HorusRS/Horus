use {
	bcc::{
		Kprobe,
		Kretprobe,
		BPF,
		// BccError,
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
	super::ebpf,
	hrs_common::{
		sig,
		sig::{
			Hash,
			SignatureData,
		},
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

	pub fn load_signatures(&mut self, signatures: &HashMap<sig::SignatureHash, sig::SignatureEntry>) {
		for (sig_hash, sig) in signatures {
			ebpf::run_signature(sig_hash, sig);
		}
	}


}
