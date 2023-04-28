use {
	std::fs,
	reqwest::blocking::Client,
};

use {
	hrs_common::{
		alert,
		alert::{
			AlertEntry,
		},
	},
};

pub fn send_log_to_elk(log_message: AlertEntry) {
	let client = Client::new();
	let url = "http://127.0.0.1:9200/alert-entries/_doc";
	let response = client.post(url)
		.header("Content-Type", "application/json")
		.body(serde_json::to_string(&log_message).unwrap())
		.send()
		.unwrap();
}

pub fn update_signatures() {
	let client = Client::new();
	let url = "http://127.0.0.1:8080/signatures";
	let response = client.post(url)
		.header("Content-Type", "application/json")
		.body("")
		.send()
		.unwrap();

	if !response.status().is_success() {
		println!("Failed to send log");
	}

	let bytes = response.bytes();
	let slice = bytes.as_ref();
	let content = String::from_utf8(slice.unwrap().to_vec()).unwrap();

	fs::write("user/signatures.toml", content).expect("Unable to write file");
}
