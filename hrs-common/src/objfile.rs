use {
	serde::{Deserialize, Serialize},
	std::{
		result::Result,
		fs,
		io,
	},
	toml,
	serde_json,
};

pub enum ObjFileFormat {
	Toml,
	Json,
}

#[derive(Debug)]
pub enum ObjFileError {
	FailedToRead(io::Error),
	FailedToWrite(io::Error),
	InvalidFormat,
}

impl std::fmt::Display for ObjFileError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			ObjFileError::FailedToRead(e) => write!(f, "File cannot be read from: {}", e),
			ObjFileError::FailedToWrite(e) => write!(f, "File cannot be written to: {}", e),
			ObjFileError::InvalidFormat => write!(f, "Invalid file format"),
		}
	}
}

// loads wanted objects from file
pub fn load<T>(path: &str, format: ObjFileFormat) -> Result<T, ObjFileError>
where for<'a> T: Deserialize<'a>
{
	let file_str = match fs::read_to_string(path) {
		Ok(c) => c,
		Err(e) => {
			return Err(ObjFileError::FailedToRead(e))
		}
	};
	let data = match format {
		ObjFileFormat::Toml => {
			match toml::from_str(&file_str) {
				Ok(c) => c,
				Err(_) => {
					return Err(ObjFileError::InvalidFormat)
				}
			}
		}
		ObjFileFormat::Json => {
			match serde_json::from_str(&file_str) {
				Ok(c) => c,
				Err(_) => {
					return Err(ObjFileError::InvalidFormat)
				}
			}
		}
	};
	Ok(data)
}

pub fn write<T>(data: &T, path: &str, format: ObjFileFormat) -> Result<(), ObjFileError>
where T: Serialize,
{
	let data_str = match format {
		ObjFileFormat::Toml => {
			match toml::to_string(&data) {
				Ok(c) => c,
				Err(_) => {
					return Err(ObjFileError::InvalidFormat)
				}
			}
		}
		ObjFileFormat::Json => {
			match serde_json::to_string(&data) {
				Ok(c) => c,
				Err(_) => {
					return Err(ObjFileError::InvalidFormat)
				}
			}
		}
	};
	match fs::write(path, data_str) {
		Ok(()) => Ok(()),
		Err(e) => Err(ObjFileError::FailedToWrite(e)),
	}
}
