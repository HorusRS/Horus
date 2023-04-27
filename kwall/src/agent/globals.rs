use std::sync::RwLock;
use lazy_static::lazy_static;

lazy_static! {
	pub static ref CONNECT_TO_SERVER: RwLock<bool> = RwLock::new(false);
}
