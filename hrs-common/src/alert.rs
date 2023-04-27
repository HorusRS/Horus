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
	pub threat_level: u8,
	pub parent_program: Program,
	pub program: Program,
	pub datetime: String,
}
