use serde::Deserialize;
use toml;

#[derive(Deserialize, Debug)]
struct Devices {
    devices: Vec<Device>,
}

#[derive(Deserialize, Debug)]
struct Device {
    device_name: String,
    address: String,
    patterns_to_collect: Vec<String>,
}

fn main() {

        let filename = "devices.toml";
    
        // Read the contents of the file using a `match` block 
        // to return the `data: Ok(c)` as a `String` 
        // or handle any `errors: Err(_)`.
        let contents = match fs::read_to_string(filename) {
            // If successful return the files text as `contents`.
            // `c` is a local variable.
            Ok(c) => c,
            // Handle the `error` case.
            Err(_) => {
                // Write `msg` to `stderr`.
                eprintln!("Could not read file `{}`", filename);
                // Exit the program with exit code `1`.
                exit(1);
            }
        };

    let devices: Devices = toml::from_str(contents).unwrap();

    println!("{:?}", devices);
}
