use crate::client::Client;
use crate::state::State;
use clap::Arg;
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
use tracing::Instrument;
use tracing_appender::non_blocking::WorkerGuard;
#[allow(unused_imports)]
use tracing_subscriber::prelude::*;
#[allow(unused_imports)]
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
    args: Option<Vec<String>>,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Cmd {
    name: String,
    list: Vec<String>,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Group {
    name: String,
    always_permit_authorization: Option<bool>,
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
    member: Option<Vec<String>>,
    always_permit_authorization: Option<bool>,
    acl: Option<String>,
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

    // Directory to log the files to
    log_dir: Option<String>,

    // PAM service to use for authentication
    pam_service: Option<String>,
}

pub struct RunningServer {
    // The join handle that can be awaited, will return unit type when the server terminates
    join_handle: JoinHandle<()>,

    // Send unit type to this channel to shutdown the server
    #[allow(dead_code)]
    cancel_channel: UnboundedSender<()>,

    // Logging guard which will flush the logs when it goes out of scope
    // This is None unless tracing is redirected to a file via --log-dir option
    #[allow(dead_code)]
    logging_guard: Option<WorkerGuard>,
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info")
    }
    color_eyre::install()?;

    let running_server = start_server(None).await?;

    running_server.join_handle.await?;

    Ok(())
}

#[cfg(test)]
fn setup_logging(_log_dir: &Option<String>) -> Option<WorkerGuard> {
    None
}

#[cfg(not(test))]
fn setup_logging(log_dir: &Option<String>) -> Option<WorkerGuard> {
    if let Some(dir) = log_dir {
        println!("Setting up logging in {}", dir);
        let file_appender = tracing_appender::rolling::never(dir, "tacrustd.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .finish()
            .with(tracing_subscriber::fmt::Layer::default().with_writer(non_blocking))
            .init();
        Some(guard)
    } else {
        println!("Setting up logging for stdout");
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .finish()
            .init();
        None
    }
}

async fn start_server(config_override: Option<&[u8]>) -> Result<RunningServer, Report> {
    let config = Arc::new(setup(config_override)?);
    let state = Arc::new(RwLock::new(State::new(
        config.key.as_bytes().to_vec(),
        config
            .pam_service
            .as_ref()
            .unwrap_or(&"tacrustd".to_string())
            .clone(),
    )));

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

    let logging_guard = setup_logging(&config.log_dir);

    tracing::info!("commit: {}", env!("GIT_HASH"));
    tracing::info!("version: {}", env!("FULL_VERSION"));
    tracing::info!("listening on {}", &config.listen_address);

    let listener = TcpListener::bind(&config.listen_address).await?;
    let (cancel_channel, mut cancel_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
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
                    let span = tracing::span!(tracing::Level::INFO, "tacacs_request", ?addr);

                    tokio::spawn(async move {
                        tracing::debug!("accepted connection");
                        if let Err(e) = process(state, stream, addr).await {
                            tracing::info!("an error occurred; error = {}", e);
                        }
                    }.instrument(span));
                }
                _ = cancel_rx.recv() => {
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
    Ok(RunningServer {
        join_handle,
        cancel_channel,
        logging_guard,
    })
}

fn setup(config_override: Option<&[u8]>) -> Result<Config, Report> {
    let mut layers = vec![];
    let mut tempconfig = NamedTempFile::new()?;

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

    let app = clap::App::new("tacrust")
        .args(&Config::clap_args())
        .arg(Arg::with_name("config").long("config").takes_value(true));
    let arg_matches = app.get_matches();

    if let Some(c) = arg_matches.value_of("config") {
        layers.clear();
        layers.push(Layer::Json(c.into()));
    }

    layers.push(Layer::Env(Some("TACRUST_".to_string())));
    layers.push(Layer::Clap(arg_matches.clone()));

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
