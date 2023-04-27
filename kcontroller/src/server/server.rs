// server.rs
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use hyper::header::CONTENT_TYPE;
use serde_json::json;
use std::convert::Infallible;
use serde::{Deserialize, Serialize};

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

pub async fn run(port: u16) {
	let make_svc = make_service_fn(|_conn| {
		async { Ok::<_, Infallible>(service_fn(handle_request)) }
	});

	let addr = ([127, 0, 0, 1], port).into();
	let server = Server::bind(&addr).serve(make_svc);

	println!("Server listening on: {:?}", addr);

	if let Err(e) = server.await {
		eprintln!("server error: {}", e);
	}
}

async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
	let mut response = Response::new(Body::empty());

	match (req.method(), req.uri().path()) {
		(&hyper::Method::POST, "/log") => {
			let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
			let log_message: AlertEntry = serde_json::from_slice(&body_bytes).unwrap();

			println!("Received log: - {:?}", log_message);
			// Store log_message somewhere (e.g., in a database or a file)

			*response.body_mut() = Body::from(json!({"status": "ok"}).to_string());
			*response.headers_mut() = hyper::header::HeaderMap::new();
			response.headers_mut().insert(CONTENT_TYPE, "application/json".parse().unwrap());
		}
		(&hyper::Method::POST, "/signatures") => {
			println!("Sent the signatures");
			// Store log_message somewhere (e.g., in a database or a file)

			let content = tokio::fs::read_to_string("user/signatures.toml").await.unwrap();
			*response.body_mut() = Body::from(content);
			*response.headers_mut() = hyper::header::HeaderMap::new();
			response.headers_mut().insert(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
		}
		_ => {
			*response.status_mut() = StatusCode::NOT_FOUND;
		}
	}

	Ok(response)
}
