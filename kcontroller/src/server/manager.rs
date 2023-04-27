use {
	std::{
		// collections::HashMap,
	},
};

use {
	// hrs_common::sig,
	super::{
		server,
	},
};

pub struct Manager {
}

impl Manager {
	pub fn new() -> Self {
		// init signatures hash map
		Self {
		}
	}

	pub fn prompt(&mut self) {
		println!("Horus server will start after this prompt:\n");
	}

	pub async fn start(&mut self) {
		server::run(8080).await
	}
}

