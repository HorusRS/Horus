use {
	std::{
		collections::HashMap,
	},
};

use {
	hrs_common::sig,
};

pub struct Manager {
	pub signatures: HashMap<sig::SigName, sig::SignatureInformation>,
}

impl Manager {
	pub fn new() -> Self {

		// init signatures hash map
		let mut sig_map = HashMap::new();
		match sig::load_signatures("config/signatures.toml") {
			Ok(signatures) => {
				for s in signatures{
					sig_map.insert(s.name, s.info);
				}
			},
			Err(e) => {
				println!("{}",e);
				// no signatures added due to the failure
			}
		}

		Self {
			signatures: sig_map,
		}
	}

	pub fn prompt(&mut self) {
		println!("Horus agent will start after this prompt:\n");
		println!("Loaded {} signatures", self.signatures.len());
	}
}
