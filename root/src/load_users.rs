pub mod devices{

    use serde_derive::{Deserialize, Serialize};
    use std::fs;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Config {
        pub devices: Vec<Device>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Device {
        pub device_name: String,
        pub address: String,
        pub patterns_to_collect: Vec<String>,
    }

    pub fn load_devices() -> Config {
        let config_toml = fs::read_to_string("devices.toml").unwrap();
        let config: Config = toml::from_str(&config_toml).unwrap();

        for device in &config.devices {
            println!("Device name: {}", device.device_name);
            println!("Address: {}", device.address);
            println!("Patterns to collect: {:?}", device.patterns_to_collect);
        }
        return config;
    }
}