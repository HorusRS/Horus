#[allow(non_camel_case_types)]

pub mod toml_config{
    use serde_derive::{Deserialize, Serialize};
    use std::fs;
    use std::process::exit;
    use toml;
    // Top level struct to hold the TOML data.

    #[derive(Serialize, Deserialize, Debug)]
    pub struct Config_t {
        pub signatures: Vec<Signature_t>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct Signature_t {
        pub alert_name: String,
        pub pattern_type: String,
        pub pattern_data: String,
    }
    pub fn load_agent_config(path: &str) -> Config_t {
        let file_str = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Could not read file `{}`", path);
                exit(1);
            }
        };
        let data: Config_t = toml::from_str(&file_str).unwrap();
        return data;
    }

    pub fn load_to_signatures(data: Vec<Signature_t>) {
        let toml_str = toml::to_string(&data).unwrap();
        fs::write("test.toml", "[config]\n".to_owned() + &toml_str).unwrap();
    }
}
