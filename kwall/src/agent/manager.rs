use {
	std::{
		collections::HashMap,
	},
};

use {
	super::tracer,
	hrs_common::{
		sig,
	},
};

pub struct Manager {
	pub signatures: HashMap<sig::SignatureHash, sig::SignatureEntry>,
	tracer: tracer::Tracer,
}

impl Manager {
	pub fn new() -> Self {

		// init signatures hash map
		let mut sig_map = HashMap::new();
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
			tracer: tracer::Tracer::new(),
		}
	}

	pub fn prompt(&self) {
		println!("Horus agent will start after this prompt:\n");
		println!("Loaded {} signatures", self.signatures.len());
		println!("{:?}", self.signatures);
	}

	pub fn load(&mut self) {
		self.tracer.load_signatures(&self.signatures)
	}
}
