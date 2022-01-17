use crate::client::Client;
use crate::state::State;
use clap_rs as clap;
use color_eyre::Report;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::{path::Path, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_util::codec::{BytesCodec, Framed};
use tracing_subscriber::EnvFilter;
use twelf::{config, Layer};

mod client;
mod state;
mod tacacs;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
enum Credentials {
    Pam,
    Ascii(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    name: String,
    credentials: Credentials,
}

// TACACS+ server in Rust
#[config]
#[derive(Debug)]
pub struct Config {
    // Address to bind on
    listen_address: String,

    // Server key (for now we use a global one like tac_plus)
    key: String,

    // List of users
    #[serde(rename = "user")]
    users: Option<Vec<User>>,
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    let config = Arc::new(setup()?);
    let state = Arc::new(Mutex::new(State::new()));
    let listener = TcpListener::bind(&config.listen_address).await?;

    tracing::debug!("config: {:?}", config);
    tracing::info!("listening on {}", &config.listen_address);

    loop {
        let (stream, addr) = listener.accept().await?;
        let config = Arc::clone(&config);
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            tracing::debug!("accepted connection");
            if let Err(e) = process(config, state, stream, addr).await {
                tracing::info!("an error occurred; error = {}", e);
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
    config: Arc<Config>,
    state: Arc<Mutex<State>>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), Report> {
    let pipe = Framed::new(stream, BytesCodec::new());
    let mut client = Client::new(state.clone(), pipe).await?;
    tracing::info!("processing connection from {}", addr);

    loop {
        tokio::select! {
            Some(msg) = client.rx.recv() => {
                tracing::info!("sending {} bytes to {}: {:?}", msg.len(), addr, msg);
                client.pipe.send(msg.into()).await?;
            }
            result = client.pipe.next() => match result {
                Some(Ok(msg)) => {
                    tracing::info!("received {} bytes from {}: {:?}", msg.len(), addr, msg);
                    let response = tacacs::process_tacacs_packet(&mut client, config.clone(), &msg).await?;

                    {
                        let mut state = state.lock().await;
                        state.unicast(addr, response).await;
                    }
                }
                Some(Err(e)) => {
                    tracing::error!(
                        "an error occurred while processing connection from {}; error = {:?}",
                        addr,
                        e
                    );
                }
                None => break,
            },
        }
    }

    {
        let mut state = state.lock().await;
        state.clients.remove(&addr);
    }

    tracing::info!("connection from {} terminated", addr);

    Ok(())
}
