use {
	serde_derive::{Deserialize, Serialize},
};

use super::{
	alert,
	alert::{
		AlertEntry,
	},
	program::{
		Program
	},
};

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientMessage {
	MyNameIs(String),
	RequestFile(String),
	AskForLoggingPermission,
	Log(AlertEntry),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ServerMessage {
	SendFile(String),
	GiveLoggingPermission,
}
