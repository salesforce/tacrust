use crate::client::Client;
use crate::state::State;
use clap::Arg;
use clap_rs as clap;
use color_eyre::Report;
use futures::SinkExt;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::net::SocketAddr;
use std::{path::Path, sync::Arc};
use tacrust::tacacs_codec::TacacsCodec;
use tempfile::NamedTempFile;
use tokio::sync::oneshot::Sender;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::Instrument;
use tracing_appender::non_blocking::WorkerGuard;
#[allow(unused_imports)]
use tracing_subscriber::prelude::*;
#[allow(unused_imports)]
use tracing_subscriber::{
    filter, filter::LevelFilter, fmt, prelude::*, reload, EnvFilter, Registry,
};
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
    forward_upstream: Option<bool>,
    acl: Option<String>,
    service: Option<Vec<Service>>,
    cmds: Option<Vec<Cmd>>,
    member: Option<Vec<String>>,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct User {
    name: String,
    credentials: Credentials,
    always_permit_authorization: Option<bool>,
    forward_upstream: Option<bool>,
    acl: Option<String>,
    service: Option<Vec<Service>>,
    cmds: Option<Vec<Cmd>>,
    member: Option<Vec<String>>,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Acl {
    name: String,
    list: Vec<String>,
}

// TACACS+ server in Rust
#[config]
#[allow(dead_code)]
#[derive(Clone, Default, Debug)]
pub struct Config {
    // Address to bind on
    listen_address: String,
    // Redirect packets to shrubbery daemon
    upstream_tacacs_server: Option<String>,

    // Immediately exit the server (useful for config validation)
    #[serde(default)]
    immediately_exit: bool,

    // Server key (for now we use a global one like tac_plus)
    key: String,

    // Extra keys (will be tried if primary key fails)
    extra_keys: Option<Vec<String>>,

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

    // Clients to enable debug logging for
    debug_traffic_from_ip_addrs: Option<HashSet<String>>,
}

pub struct RunningServer {
    // The join handle that can be awaited, will return unit type when the server terminates
    join_handle: JoinHandle<()>,

    // Send unit type to this channel to shutdown the server
    #[allow(dead_code)]
    cancel_channel: Sender<()>,

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
fn setup_logging(
    _log_dir: &Option<String>,
) -> (
    Option<WorkerGuard>,
    Option<reload::Handle<LevelFilter, Registry>>,
) {
    (None, None)
}

#[cfg(not(test))]
fn setup_logging(
    log_dir: &Option<String>,
) -> (
    Option<WorkerGuard>,
    Option<reload::Handle<LevelFilter, Registry>>,
) {
    let default_env_filter = EnvFilter::from_default_env().max_level_hint().unwrap();
    if let Some(dir) = log_dir {
        println!("Setting up logging in {}", dir);
        let file_appender = tracing_appender::rolling::never(dir, "tacrustd.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        let (reload_filter, reload_handle) = reload::Layer::new(default_env_filter);
        tracing_subscriber::registry()
            .with(reload_filter)
            .with(fmt::Layer::default())
            .with(tracing_subscriber::fmt::Layer::default().with_writer(non_blocking))
            .init();
        (Some(guard), Some(reload_handle))
    } else {
        println!("Setting up logging for stdout");
        let (reload_filter, reload_handle) = reload::Layer::new(default_env_filter);
        tracing_subscriber::registry()
            .with(reload_filter)
            .with(fmt::Layer::default())
            .init();
        (None, Some(reload_handle))
    }
}

async fn start_server(config_override: Option<&[u8]>) -> Result<RunningServer, Report> {
    let config = Arc::new(setup(config_override)?);
    let state = Arc::new(RwLock::new(State::new(
        config.key.as_bytes().to_vec(),
        config
            .extra_keys
            .as_ref()
            .unwrap_or(&vec![])
            .iter()
            .map(|k| k.as_bytes().to_vec())
            .collect(),
        config
            .pam_service
            .as_ref()
            .unwrap_or(&"tacrustd".to_string())
            .clone(),
        config
            .upstream_tacacs_server
            .as_ref()
            .unwrap_or(&"".to_string())
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
        tracing::debug!("no errors found in config, exiting immediately");
        std::process::exit(0);
    }

    #[allow(unused_variables)]
    let (logging_guard, logging_reload_handle) = setup_logging(&config.log_dir);
    #[allow(unused_variables)]
    let default_env_filter = EnvFilter::from_default_env().max_level_hint().unwrap();
    let (override_off_tx, mut override_off_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    tracing::debug!("commit: {}", env!("GIT_HASH"));
    tracing::debug!("version: {}", env!("FULL_VERSION"));
    tracing::debug!("listening on {}", &config.listen_address);

    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let listener = TcpListener::bind(&config.listen_address).await?;

    let join_handle = tokio::spawn(async move {
        let connection_counter = Arc::new(Semaphore::new(10000));
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, addr) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!("error accepting connection; error = {}", e);
                            continue
                        },
                    };

                    #[cfg(not(test))]
                    if let Some(ref debug_map) = &config.debug_traffic_from_ip_addrs {
                        if debug_map.contains(&addr.ip().to_string()) {
                            logging_reload_handle
                                .as_ref()
                                .unwrap()
                                .modify(|filter| *filter = LevelFilter::DEBUG)
                                .unwrap();
                        }
                    }

                    let state = Arc::clone(&state);
                    let span = tracing::span!(tracing::Level::INFO, "tacacs_request", ?addr);
                    let spawn_tcp_counter = Arc::clone(&connection_counter);
                    let override_off_tx = override_off_tx.clone();
                    tokio::spawn(async move {
                        let acquire_counter = spawn_tcp_counter.try_acquire();
                        if let Ok(_guard) = acquire_counter {
                            tracing::debug!("accepted connection");
                            if let Err(e) = process_tacacs_client(state, stream, addr).await {
                                tracing::debug!("error occurred processing tacacs packet: {}", e);
                            }
                        } else {
                            tracing::debug!("connection limit exceeded, rejecting connection");
                        }
                        override_off_tx.send(()).unwrap();
                    }.instrument(span));
                }
                _ = override_off_rx.recv() => {
                    #[cfg(not(test))]
                    logging_reload_handle
                        .as_ref()
                        .unwrap()
                        .modify(|filter| *filter = default_env_filter)
                        .unwrap();
                }
                _ = &mut cancel_rx => {
                    tracing::debug!("received channel req to shutdown, exiting");
                    break;
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::debug!("received ctrl-c, exiting");
                    break;
                }
            }
        }
    });
    Ok(RunningServer {
        join_handle,
        cancel_channel: cancel_tx,
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

    match config_override {
        Some(cfg) => {
            tempconfig.write_all(cfg)?;
            layers.push(Layer::Json(tempconfig.path().into()));
            layers.push(Layer::Env(Some("TACRUST_".to_string())));
        }
        None => {
            let app = clap::App::new("tacrust")
                .args(&Config::clap_args())
                .arg(Arg::with_name("config").long("config").takes_value(true));
            let arg_matches = app.get_matches();

            if let Some(c) = arg_matches.value_of("config") {
                layers.clear();
                layers.push(Layer::Json(c.into()));
            }
            layers.push(Layer::Env(Some("TACRUST_".to_string())));
            if config_override.is_none() {
                layers.push(Layer::Clap(arg_matches.clone()));
            }
        }
    }

    let config = Config::with_layers(&layers)?;

    Ok(config)
}

async fn process_tacacs_client(
    shared_state: Arc<RwLock<State>>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), Report> {
    let pipe = Framed::new(stream, TacacsCodec::new());
    let mut client = Client::new(shared_state.clone(), pipe).await?;

    loop {
        tokio::select! {
            Some(msg) = client.rx.recv() => {
                tracing::debug!("sending {} bytes to {}", msg.len(), addr);
                client.pipe.send(msg.into()).await?;
            }
            result = client.pipe.next() => match result {
                Some(Ok(msg)) => {
                    tracing::debug!("received {} bytes from {}", msg.len(), addr);
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

    shared_state
        .write()
        .await
        .upstream_tacacs_connections
        .remove(&addr);
    shared_state.write().await.sockets.remove(&addr);
    tracing::debug!("connection from {} terminated", addr);
    Ok(())
}
