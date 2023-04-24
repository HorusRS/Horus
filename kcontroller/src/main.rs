use {
	clap::{Arg, Command},
	std::str::FromStr,
};

mod server;

enum RunMode {
	Local,
	Full,
}

impl FromStr for RunMode {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"local" => Ok(RunMode::Local),
			"full" => Ok(RunMode::Full),
			_ => Err(format!("Invalid run mode: '{}'", s)),
		}
	}
}
#[actix_web::main]
async fn main(){
	let matches = Command::new("kwall")
		.about("Horus's server:

This util is for testing purposes only and is not viable for any production use
on any machine, this is still a work in progress:) \
")
		.version("0.1.0")
		.author("Horus Development Team (Noam Eliyahu Daniel and Liam Sapir")
		.subcommand(
			Command::new("run")
				.about("Run server")
				.arg(
					Arg::new("mode")
						.value_name("MODE/STATE")
						.value_parser(["local", "full"])
						.help("Select the run mode: 'local' or 'full'")
						.default_value("local"),
				),
		)
		.get_matches();

	if let Some(matches) = matches.subcommand_matches("run") {
		let mode_str = matches.get_one::<String>("mode").unwrap();
		let mode = mode_str.parse::<RunMode>().unwrap();
		match mode {
			RunMode::Local => {
				let mut manager = server::Manager::new();
				manager.prompt();
                let protocol = server::Protocol::new(8000);
                protocol.start().await;
			}
			RunMode::Full => {
				todo!();
			}
		}
	}
}
