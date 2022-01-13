use crate::state::State;
use clap_rs as clap;
use color_eyre::Report;
use std::net::SocketAddr;
use std::{path::Path, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tracing_subscriber::EnvFilter;
use twelf::{config, Layer};

mod client;
mod state;

// TACACS+ server in Rust
#[config]
#[derive(Debug)]
struct Config {
    // Address to bind on
    listen_address: String,
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    let config = setup()?;
    let state = Arc::new(Mutex::new(State::new()));
    let listener = TcpListener::bind(&config.listen_address).await?;

    tracing::info!("listening on {}", &config.listen_address);

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            tracing::debug!("accepted connection");
            if let Err(e) = process(state, stream, addr).await {
                tracing::info!("an error occurred; error = {:?}", e);
            }
        });
    }
}

fn setup() -> Result<Config, Report> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }
    color_eyre::install()?;

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info")
    }
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let app = clap::App::new("tacrust").args(&Config::clap_args());
    let mut layers = vec![];
    for path in &[
        "tacrust.toml",
        "tacrustd/tacrust.toml",
        "/etc/tacrust.toml",
        "/etc/tacrustd/tacrust.toml",
    ] {
        if Path::new(path).exists() {
            layers.push(Layer::Toml(path.into()));
        }
    }
    layers.push(Layer::Env(Some("TACRUST_".to_string())));
    layers.push(Layer::Clap(app.get_matches().clone()));
    let config = Config::with_layers(&layers)?;

    Ok(config)
}

async fn process(
    state: Arc<Mutex<State>>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), Report> {
    // ref: https://github.com/tokio-rs/tokio/blob/master/examples/chat.rs
    // 1. match incoming connection with a client defined in the config
    // 2. decrypt incoming packet(s) using the corresponding client's key
    // 3. generate reply packet based on the decrypted packet
    // 4. send back the response

    Ok(())
}
