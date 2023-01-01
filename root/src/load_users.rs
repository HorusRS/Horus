use serde_derive::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Deserialize, Serialize)]
struct Config {
    devices: Vec<Device>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Device {
    device_name: String,
    address: String,
    patterns_to_collect: Vec<String>,
}

fn load_devices() -> Config {
    let config_toml = fs::read_to_string("devices.toml").unwrap();
    let config: Config = toml::from_str(&config_toml).unwrap();

    for device in &config.devices {
        println!("Device name: {}", device.device_name);
        println!("Address: {}", device.address);
        println!("Patterns to collect: {:?}", device.patterns_to_collect);
    }
    return config
}
