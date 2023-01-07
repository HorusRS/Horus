// this is the root of the project..

use std::thread;

//mod tracer;
//use tracer::{run};

pub mod agent_config_helper;
use agent_config_helper::toml_config::{load_agent_config, Config_t, Signature_t};

fn main() {
    let sig: Config_t = load_agent_config("agent_config.toml");
    println!("{:?}", sig);
    /*
    let thread = thread::spawn(move || run(sig));
    thread.join().expect("Couldn't join on the associated thread");
    */
}
