use {
	clap::{Arg, Command},
	std::str::FromStr,
};

mod agent;

enum RunMode {
	Serverless,
	Full,
}

impl FromStr for RunMode {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"serverless" => Ok(RunMode::Serverless),
			"full" => Ok(RunMode::Full),
			_ => Err(format!("Invalid run mode: '{}'", s)),
		}
	}
}

fn main() {
	let matches = Command::new("kwall")
		.about("Horus's eBPF agent:

This util is for testing purposes only and is not viable for any production use
on any machine, this is still a work in progress:) \
")
		.version("0.1.0")
		.author("Horus Development Team (Noam Eliyahu Daniel and Liam Sapir")
		.subcommand(
			Command::new("run")
				.about("Run eBPF agent")
				.arg(
					Arg::new("mode")
						.value_name("MODE/STATE")
						.value_parser(["serverless", "full"])
						.help("Select the run mode: 'serverless' or 'full'")
						.default_value("serverless"),
				),
		)
		.get_matches();

	if let Some(matches) = matches.subcommand_matches("run") {
		let mode_str = matches.get_one::<String>("mode").unwrap();
		let mode = mode_str.parse::<RunMode>().unwrap();
		match mode {
			RunMode::Serverless => {
				let mut manager = agent::Manager::new();
				manager.prompt();
				manager.load();
				loop {
				}
			}
			RunMode::Full => {
				todo!();
			}
		}
	}
}
