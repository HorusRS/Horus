use {
	serde::{Deserialize, Serialize},
	std::{
		result::Result,
		fs,
		io,
	},
	toml,
};

#[derive(Debug)]
pub enum ConfigError {
	FailedToRead(io::Error),
	FailedToWrite(io::Error),
	InvalidFormat(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			ConfigError::FailedToRead(e) => write!(f, "File cannot be read from: {}", e),
			ConfigError::FailedToWrite(e) => write!(f, "File cannot be written to: {}", e),
			ConfigError::InvalidFormat(e) => write!(f, "Invalid file format: {}", e),
		}
	}
}

// loads wanted config from file
pub fn load_config<T>(path: &str) -> Result<T, ConfigError>
where for<'a> T: Deserialize<'a>
{
	let file_str = match fs::read_to_string(path) {
		Ok(c) => c,
		Err(e) => {
			return Err(ConfigError::FailedToRead(e))
		}
	};
	let data: T = match toml::from_str(&file_str) {
		Ok(c) => c,
		Err(e) => {
			return Err(ConfigError::InvalidFormat(e))
		}
	};
	Ok(data)
}

pub fn write_config<T>(data: &T, path: &str) -> Result<(), ConfigError>
where T: Serialize,
{
	let toml_str = toml::to_string(&data).unwrap();
	match fs::write(path, toml_str) {
		Ok(()) => Ok(()),
		Err(e) => Err(ConfigError::FailedToWrite(e)),
	}
}
