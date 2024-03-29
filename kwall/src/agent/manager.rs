use {
	std::{
		collections::HashMap,
	},
};

use {
	super::globals::CONNECT_TO_SERVER,
	super::tracer,
	super::client,
	hrs_common::{
		sig,
	},
};

pub struct Manager {
	pub signatures: HashMap<sig::SignatureHash, sig::SignatureEntry>,
}

impl Manager {
	pub fn new() -> Self {

		// init signatures hash map
		let mut sig_map = HashMap::new();
		let connect = *CONNECT_TO_SERVER.read().unwrap();
		if connect {
			client::update_signatures();
		}
		match sig::load_signatures("user/signatures.toml") {
			Ok(signatures) => {
				for s in signatures {
					sig_map.insert(sig::hash(&s.name), s);
				}
			},
			Err(e) => eprintln!("{}",e), // no signatures added due to the failure
		}

		Self {
			signatures: sig_map,
		}
	}

	pub fn prompt(&self) {
		println!("Horus agent will start after this prompt:\n");
		println!("Loaded {} signatures", self.signatures.len());
		println!("{:?}", self.signatures);
	}

	pub fn load(&mut self) {
		tracer::run_signatures(&self.signatures)
	}
}
