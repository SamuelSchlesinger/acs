use log::info;
use acs::server;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize the logger
    env_logger::init();
    
    info!("Starting anonymous credit server with HTTPS");
    
    // Run the server using the extracted module
    server::run_server().await
}
