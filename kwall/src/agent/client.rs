// client.rs
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::fs;

use {
	hrs_common::{
		messages,
		messages::{
			ServerMessage,
			ClientMessage,
		},
		alert,
		alert::{
			AlertEntry,
		},
	},
};

pub fn send_log(log_message: AlertEntry) {
	let client = Client::new();
	let url = "http://127.0.0.1:8080/log";
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
