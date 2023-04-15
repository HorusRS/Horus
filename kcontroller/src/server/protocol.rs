use actix_web::{web, HttpResponse, Responder, post, HttpServer, App, ResponseError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
enum ServerError {
    #[error("Invalid configuration provided")]
    InvalidConfiguration,
}

impl ResponseError for ServerError {}

#[derive(Serialize, Deserialize)]
struct Config {
    // Define your configuration struct here, based on your TOML format
    // For example:
    name: String,
    // port: u16,
}

#[post("/auth")]
async fn authenticate() -> impl Responder {
    let approval_status = "approved";
    HttpResponse::Ok()
        .append_header(("X-Approval-Status", approval_status))
        .finish()
}

#[post("/config")]
async fn configure(config: web::Json<Config>) -> impl Responder {
    // Handle the received configuration here
    match validate_config(&config) {
        Ok(()) => HttpResponse::Ok().finish(),
        Err(e) => e.error_response(),
    }
}

#[post("/status")]
async fn send_status() -> impl Responder {
    let status = "running";
    HttpResponse::Ok()
        .append_header(("X-Status", status))
        .finish()
}

fn validate_config(config: &Config) -> Result<(), ServerError> {
    // TODO: Add validation logic here
    if config.name.is_empty() {
        Err(ServerError::InvalidConfiguration)
    } else {
        Ok(())
    }
}

impl Protocol {
    pub async fn start(&self) -> std::io::Result<()> {
        let server_url = format!("localhost:{}", self.port);
        HttpServer::new(|| {
            App::new()
                .service(authenticate)
                .service(configure)
                .service(send_status)
        })
        .bind(server_url)?
        .run()
        .await
    }
}

pub struct Protocol {
    port: u16,
    // Add other fields here as needed
}

impl Protocol {
    pub fn new(port: u16) -> Self {
        Protocol {
            port,
            // Initialize other fields here as needed
        }
    }
}
