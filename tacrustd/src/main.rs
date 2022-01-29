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
    sync::RwLock,
};
use tokio_util::codec::{BytesCodec, Framed};
use tracing_subscriber::EnvFilter;
use twelf::{config, Layer};

mod client;
mod state;
mod tacacs;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
enum Credentials {
    Pam,
    Ascii(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Service {
    name: String,
    args: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Cmd {
    name: String,
    list: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Group {
    name: String,
    defservice: Option<String>,
    acl: Option<String>,
    pap: Option<String>,
    member: Option<String>,
    service: Option<Vec<Service>>,
    cmds: Option<Vec<Cmd>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    name: String,
    credentials: Credentials,
    member: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Acl {
    name: String,
    list: Vec<String>,
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
    users: Option<Vec<User>>,

    // List of ACLs
    acls: Option<Vec<Acl>>,

    // List of groups
    groups: Option<Vec<Group>>,
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    let config = Arc::new(setup()?);
    let state = Arc::new(RwLock::new(State::new(config.key.as_bytes().to_vec())));
    let listener = TcpListener::bind(&config.listen_address).await?;

    if config.acls.is_some() {
        let mut state = state.write().await;
        for acl in config.acls.as_ref().unwrap() {
            state.acls.insert(acl.name.clone(), acl.clone());
        }
    }

    if config.users.is_some() {
        let mut state = state.write().await;
        for user in config.users.as_ref().unwrap() {
            state.users.insert(user.name.clone(), user.clone());
        }
    }

    if config.groups.is_some() {
        let mut state = state.write().await;
        for group in config.groups.as_ref().unwrap() {
            state.groups.insert(group.name.clone(), group.clone());
        }
    }

    tracing::debug!("config: {:?}", config);
    tracing::debug!("state: {:?}", state.read().await);
    tracing::info!("listening on {}", &config.listen_address);

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            tracing::debug!("accepted connection");
            if let Err(e) = process(state, stream, addr).await {
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
        "tacrust.json",
        "tacrustd/tacrust.json",
        "/etc/tacrust.json",
        "/etc/tacrustd/tacrust.json",
    ] {
        if Path::new(path).exists() {
            layers.push(Layer::Json(path.into()));
        }
    }
    layers.push(Layer::Env(Some("TACRUST_".to_string())));
    layers.push(Layer::Clap(app.get_matches().clone()));
    let config = Config::with_layers(&layers)?;

    Ok(config)
}

async fn process(
    state: Arc<RwLock<State>>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), Report> {
    let pipe = Framed::new(stream, BytesCodec::new());
    let mut client = Client::new(state.clone(), pipe).await?;

    loop {
        tokio::select! {
            Some(msg) = client.rx.recv() => {
                tracing::info!("sending {} bytes to {}: {:?}", msg.len(), addr, msg);
                client.pipe.send(msg.into()).await?;
            }
            result = client.pipe.next() => match result {
                Some(Ok(msg)) => {
                    tracing::info!("received {} bytes from {}: {:?}", msg.len(), addr, msg);
                    let response = tacacs::process_tacacs_packet(state.clone(), &addr, &msg).await?;

                    {
                        let state = state.read().await;
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
        let mut state = state.write().await;
        state.clients.remove(&addr);
    }

    tracing::info!("connection from {} terminated", addr);

    Ok(())
}

pub trait Compare {
    fn name(&self) -> String;
    fn compare(&self, args: &mut Vec<String>) -> Vec<String> {
        let mut result_args: Vec<String> = Vec::new();
        for values in args.iter() {
            let target_val = self.name();
            if values.contains(&target_val) {
                result_args.push(values.clone());
            }
        }
        result_args
    }
}

impl Compare for Service {
    fn name(&self) -> String {
        self.name.clone()
    }
}
impl Compare for Cmd {
    fn name(&self) -> String {
        self.name.clone()
    }
}
