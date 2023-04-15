use {
	serde::{Deserialize, Serialize},
	std::{fs, process::exit},
	toml,
};

// loads wanted config from file
pub fn load_config<T>(path: &str) -> T
where for<'a> T: Deserialize<'a>
{
	let file_str = match fs::read_to_string(path) {
		Ok(c) => c,
		Err(_) => {
			eprintln!("Could not read file `{}`", path);
			exit(1);
		}
	};
	let data: T = toml::from_str(&file_str)
		.expect("Unable to parse TOML");
	data
}

// saves given config to file
pub fn write_config<T>(data: T, path: &str)
where T: Serialize
{
    let toml_str = toml::to_string(&data).unwrap();
    fs::write(path, String::new() + &toml_str).unwrap();
}
