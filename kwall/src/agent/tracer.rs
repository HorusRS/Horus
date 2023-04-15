use {
	std::{
		ptr,
		collections::HashMap,
	},
};

use {
	hrs_common::sig,
};

#[repr(C)]
#[derive(Debug)]
struct ProcData {
	id: u32,
	comm: [u8; 16], // TASK_COMM_LEN
}

pub struct Tracer {
	pub signatures: HashMap<sig::SigName, sig::SignatureInformation>,
}

impl Tracer {
	pub fn new() -> Self {

		// init signatures hash map
		let mut sig_map = HashMap::new();

		Self {
			signatures: sig_map,
		}
	}
}

fn bytes_to_string(x: &[u8]) -> String {
	match x.iter().position(|&r| r == 0) {
		Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
		None => String::from_utf8_lossy(x).to_string(),
	}
}

fn bytes_to_proc_data(x: &[u8]) -> ProcData {
	unsafe { ptr::read_unaligned(x.as_ptr() as *const ProcData) }
}
