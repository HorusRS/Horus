use toml_config::toml_config::Signature_t;
use tracer::run;
mod tracer;
mod load_users;
use std::thread;
pub mod toml_config;
use crate::toml_config::toml_config::{load_signatures};

fn main() {
    let sig: Signature_t = load_signatures();
    let thread = thread::spawn(move || run(sig));
    thread.join().expect("Couldn't join on the associated thread");
}