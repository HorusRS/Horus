use {
	serde_derive::{Deserialize, Serialize},
};

// local mods
use super::{
	config,
};

pub type SigName = String;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureEntry {
	pub name: SigName,
	pub info: SignatureInformation,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureInformation {
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
