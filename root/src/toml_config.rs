#[allow(non_camel_case_types)]

pub mod toml_config{
    use serde_derive::{Deserialize, Serialize};
    use std::fs;
    use std::process::exit;
    use toml;
    // Top level struct to hold the TOML data.
    #[derive(Deserialize)]
    pub struct Signature_t {
        pub config: Config,
    }
    
    // Config struct holds to data from the `[config]` section.c
    #[derive(Deserialize)]
    pub struct Config {
        pub alert_name: String,
        pub pattern_type: String,
        pub pattern_data: String,
    }
    #[derive(Serialize)]
    pub struct load_config {
        pub alert_name: String,
        pub pattern_type: String,
        pub pattern_data: String,
    }
    
    pub fn load_signatures() -> Signature_t{

        load_to_signatures();
        // Variable that holds the filename as a `&str`.
        let filename = "test.toml";
    
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
    
        // Use a `match` block to recturn the 
        // file `contents` as a `Data struct: Ok(d)`
        // or handle any `errors: Err(_)`.
        let data: Signature_t = match toml::from_str(&contents) {
            // If successful, return data as `Data` struct.
            // `d` is a local variable.
            Ok(d) => d,
            // Handle the `error` case.
            Err(_) => {
                // Write `msg` to `stderr`.
                eprintln!("Unable to load data from `{}`", filename);
                // Exit the program with exit code `1`.
                exit(1);
            }
        };
        return data;
    }
    pub fn load_to_signatures(){
        let my_struct = load_config{
            alert_name: "Anti debugging".to_string(),
            pattern_type: "systemcalls.single".to_string(),
            pattern_data: "arch_ptrace".to_string()
        };
        let toml_string = match toml::to_string(&my_struct){
            Ok(d) => d,
            // Handle the `error` case.
            Err(_) => {
                // Write `msg` to `stderr`.
                eprintln!("Unable to load data");
                // Exit the program with exit code `1`.
                exit(1);
            }
        };
        fs::write("check.toml", toml_string).unwrap();
    }

}