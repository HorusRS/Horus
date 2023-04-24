use {
	md5,
	serde_derive::{Deserialize, Serialize},
};

// local mods
use super::objfile;
use super::program::{
	Program
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
pub enum ProcessAction {
	Kill,
	Secomp,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AlertBehavior {
	Standard,
	None,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "content")]
pub enum SignatureData {
	Syscall(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureEntry {
	pub name: String,
	pub action: ProcessAction,
	#[serde(default = "default_alert")]
	pub alert: AlertBehavior,
	pub data: SignatureData,
	#[serde(default = "default_whitelist")]
	pub whitelist: Option<Vec<Program>>,
}

fn default_alert() -> AlertBehavior {
	AlertBehavior::Standard
}
fn default_whitelist() -> Option<Vec<Program>> {
	None
}

#[derive(Serialize, Deserialize, Debug)]
struct FileContents {
	signature: Vec<SignatureEntry>
}

pub fn load_signatures(path: &str) -> Result<Vec<SignatureEntry>, config::ObjFileError> {
	let data = config::load::<FileContents>(path, config::ObjFileFormat::Toml)?;
	Ok(data.signature)
}

pub fn write_signatures(signature: Vec<SignatureEntry>, path: &str) -> Result<(), config::ObjFileError> {
	let data = FileContents {
		signature,
	};
	config::write::<FileContents>(&data, path, config::ObjFileFormat::Toml)
}
