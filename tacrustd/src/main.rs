use crate::client::Client;
use crate::state::State;
use clap_rs as clap;
use color_eyre::Report;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::SocketAddr;
use std::{path::Path, sync::Arc};
use tacrust::tacacs_codec::TacacsCodec;
use tempfile::NamedTempFile;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tokio_util::codec::Framed;
use tracing_subscriber::EnvFilter;
use twelf::{config, Layer};

mod client;
mod state;
mod tacacs;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
enum Credentials {
    Pam,
    Ascii(String),
}

impl Default for Credentials {
    fn default() -> Self {
        Credentials::Pam
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Service {
    name: String,
    args: Vec<String>,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Cmd {
    name: String,
    list: Vec<String>,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Group {
    name: String,
    defservice: Option<String>,
    acl: Option<String>,
    pap: Option<String>,
    member: Option<String>,
    service: Option<Vec<Service>>,
    cmds: Option<Vec<Cmd>>,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct User {
    name: String,
    credentials: Credentials,
    member: Option<String>,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Acl {
    name: String,
    list: Vec<String>,
}

// TACACS+ server in Rust
#[config]
#[derive(Clone, Default, Debug)]
pub struct Config {
    // Address to bind on
    listen_address: String,

    // Immediately exit the server (useful for config validation)
    #[serde(default)]
    immediately_exit: bool,

    // Server key (for now we use a global one like tac_plus)
    key: String,

    // List of users
    users: Option<Vec<User>>,

    // List of ACLs
    acls: Option<Vec<Acl>>,

    // List of groups
    groups: Option<Vec<Group>>,
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info")
    }
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    color_eyre::install()?;

    let (join_handle, _cancel_tx) = start_server(None).await?;
    join_handle.await?;

    Ok(())
}

async fn start_server(
    config_override: Option<&[u8]>,
) -> Result<(JoinHandle<()>, UnboundedSender<()>), Report> {
    let config = Arc::new(setup(config_override)?);
    let state = Arc::new(RwLock::new(State::new(config.key.as_bytes().to_vec())));

    if config.acls.is_some() {
        let mut state = state.write().await;
        for acl in config.acls.as_ref().unwrap() {
            state
                .acls
                .insert(acl.name.to_string(), Arc::new(acl.clone()));
        }
    }

    if config.users.is_some() {
        let mut state = state.write().await;
        for user in config.users.as_ref().unwrap() {
            state
                .users
                .insert(user.name.to_string(), Arc::new(user.clone()));
        }
    }

    if config.groups.is_some() {
        let mut state = state.write().await;
        for group in config.groups.as_ref().unwrap() {
            state
                .groups
                .insert(group.name.to_string(), Arc::new(group.clone()));
        }
    }

    tracing::debug!("config: {:?}", config);
    tracing::debug!("state: {:?}", state.read().await);

    if config.immediately_exit {
        tracing::info!("no errors found in config, exiting immediately");
        std::process::exit(0);
    }

    tracing::info!("listening on {}", &config.listen_address);

    let listener = TcpListener::bind(&config.listen_address).await?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, addr) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::info!("error accepting connection; error = {}", e);
                            continue
                        },
                    };
                    let state = Arc::clone(&state);

                    tokio::spawn(async move {
                        tracing::debug!("accepted connection");
                        if let Err(e) = process(state, stream, addr).await {
                            tracing::info!("an error occurred; error = {}", e);
                        }
                    });
                }
                _ = rx.recv() => {
                    tracing::info!("received channel req to shutdown, exiting");
                    break;
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("received ctrl-c, exiting");
                    break;
                }
            }
        }
    });
    Ok((join_handle, tx))
}

fn setup(config_override: Option<&[u8]>) -> Result<Config, Report> {
    let mut layers = vec![];
    let mut tempconfig = NamedTempFile::new()?;

    let app = clap::App::new("tacrust").args(&Config::clap_args());
    for path in &[
        "tacrust.json",
        "tacrustd/tacrust.json",
        "/etc/tacrust.json",
        "/etc/tacrustd/tacrust.json",
    ] {
        if Path::new(path).exists() {
            layers.push(Layer::Json(path.into()));
        }
    }

    if config_override.is_some() {
        tempconfig.write_all(config_override.unwrap())?;
        layers.push(Layer::Json(tempconfig.path().into()));
    }

    layers.push(Layer::Env(Some("TACRUST_".to_string())));
    layers.push(Layer::Clap(app.get_matches().clone()));

    let config = Config::with_layers(&layers)?;

    Ok(config)
}

async fn process(
    shared_state: Arc<RwLock<State>>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), Report> {
    let pipe = Framed::new(stream, TacacsCodec::new());
    let mut client = Client::new(shared_state.clone(), pipe).await?;

    loop {
        tokio::select! {
            Some(msg) = client.rx.recv() => {
                tracing::info!("sending {} bytes to {}", msg.len(), addr);
                client.pipe.send(msg.into()).await?;
            }
            result = client.pipe.next() => match result {
                Some(Ok(msg)) => {
                    tracing::info!("received {} bytes from {}", msg.len(), addr);
                    let response = tacacs::process_tacacs_packet(shared_state.clone(), &addr, &msg).await?;
                    shared_state.read().await.unicast(addr, response).await;
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

    shared_state.write().await.sockets.remove(&addr);
    tracing::info!("connection from {} terminated", addr);
    Ok(())
}
