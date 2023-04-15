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
	InvalidFormat(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			ConfigError::FailedToRead(e) => write!(f, "File not found: {}", e),
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

// saves given config to file
pub fn write_config<T>(data: T, path: &str)
where T: Serialize
{
	let toml_str = toml::to_string(&data).unwrap();
	fs::write(path, String::new() + &toml_str).unwrap();
}
