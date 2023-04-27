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
#[tokio::main]
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
		)
		.get_matches();

	if let Some(matches) = matches.subcommand_matches("run") {
		let mut manager = server::Manager::new();
		manager.prompt();
		manager.start().await;
	}
}
