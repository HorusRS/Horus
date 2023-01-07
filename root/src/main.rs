// this is the root of the project..

use std::thread;

mod tracer;
use tracer::{run};

pub mod agent_config_helper;
use agent_config_helper::toml_config::{load_agent_config, Config_t};

fn main() {
    let config: Config_t = load_agent_config("agent_config.toml");
    for signature in config.signatures{
        let thread = thread::spawn(move || run(signature));
        thread.join().expect("Couldn't join on the associated thread");
    }
}
