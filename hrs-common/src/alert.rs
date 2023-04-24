use {
	serde_derive::{Deserialize, Serialize},
};

// local mods
use super::program::{
	Program
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AlertEntry {
	pub name: String,
	pub program: Program,
	pub timestamp: u64,
}
