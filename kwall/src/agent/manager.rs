use std::{
	collections::HashMap,
};

use {
	hrs_common::sig,
};

pub struct Manager {
	pub loaded_signatures: HashMap<sig::SigName, sig::SignatureInformation>,
}

impl Manager {
	pub fn new() -> Self {

		// init signatures hash map
		let mut sig_map = HashMap::new();
		for s in sig::load_signatures("config/signatures.toml") {
			sig_map.insert(s.name, s.info);
		}

		Self {
			loaded_signatures: sig_map,
		}
	}

	pub fn prompt(&mut self) {
		println!("Horus agent will start after this prompt:\n");
		println!("Loaded {} signatures", self.loaded_signatures.len());
	}
}
