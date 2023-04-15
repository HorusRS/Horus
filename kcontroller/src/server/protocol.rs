use actix_web::{post, web, App, HttpServer, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize)]
struct Config {
    // Define your configuration struct here, based on your TOML format
    // For example:
    // name: String,
    // port: u16,
}

#[post("/auth")]
async fn auth(auth_token: web::Header<String>) -> HttpResponse {
    // Authenticate token
    let approval_status = "approved".to_string(); // Replace with your own authentication logic
    if approval_status == "approved" {
        HttpResponse::Ok().append_header(("X-Approval-Status", "approved")).finish()
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[get("/config")]
async fn config() -> HttpResponse {
    // Load configuration from file or database
    let config = Config {}; // Replace with your own configuration loading logic
    HttpResponse::Ok().json(config)
}

#[post("/run")]
async fn run(state: web::Data<Arc<Mutex<ServerState>>>) -> HttpResponse {
    let mut server_state = state.lock().unwrap();

    if server_state.status == "running" {
        return HttpResponse::BadRequest().body("Already running");
    }

    server_state.status = "running".to_string();

    // Start running
    // ...

    HttpResponse::Ok().finish()
}

#[post("/status")]
async fn status(status: web::Header<String>, state: web::Data<Arc<Mutex<ServerState>>>) -> HttpResponse {
    let mut server_state = state.lock().unwrap();

    if status == "running" {
        // Handle running notification from agent
        // ...

        server_state.status = "running".to_string();
    } else if status == "stopped" {
        // Handle stopped notification from agent
        // ...

        server_state.status = "stopped".to_string();
    }

    HttpResponse::Ok().finish()
}

#[post("/logging")]
async fn toggle_logging(logging: web::Header<String>, state: web::Data<Arc<Mutex<ServerState>>>) -> HttpResponse {
    if logging == "on" {
        // Handle logging toggle command from agent
        // ...

        let mut server_state = state.lock().unwrap();
        server_state.logging_enabled = true;

        HttpResponse::Ok().finish()
    } else {
        let mut server_state = state.lock().unwrap();
        server_state.logging_enabled = false;

        HttpResponse::Ok().finish()
    }
}

struct ServerState {
    status: String,
    logging_enabled: bool,
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let server_state = Arc::new(Mutex::new(ServerState {
        status: "stopped".to_string(),
        logging_enabled: false,
    }));

    HttpServer::new(move || {
        App::new()
            .data(Arc::clone(&server_state))
            .service(auth)
            .service(config)
            .service(run)
            .service(status)
            .service(toggle_logging)
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}
