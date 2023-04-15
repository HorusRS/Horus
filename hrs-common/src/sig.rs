use {
	md5,
	serde_derive::{Deserialize, Serialize},
};

// local mods
use super::{
	config,
};

pub type SignatureHash = String;

pub trait Hash {
	fn to_output(&self) -> String;
	fn to_handle(&self, handle_type: &str) -> String;
}

pub fn hash(raw: &str) -> SignatureHash {
		let digest = md5::compute(raw);
		let res = format!("{:x}", digest);
		res
}

impl Hash for SignatureHash {
	fn to_output(&self) -> String {
		let res = format!("output_{}", &self);
		res
	}
	fn to_handle(&self, handle_type: &str) -> String {
		let res = format!("handle_{}_{}", handle_type, &self);
		res
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureEntry {
	pub _name: String,
	pub _type: String,
	pub _data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct FileContents {
	signature: Vec<SignatureEntry>
}

pub fn load_signatures(path: &str) -> Result<Vec<SignatureEntry>, config::ConfigError> {
	let data = config::load_config::<FileContents>(path)?;
	Ok(data.signature)
}

pub fn write_signatures(signature: Vec<SignatureEntry>, path: &str) {
	let data = FileContents {
		signature,
	};
	config::write_config::<FileContents>(data, path);
}
