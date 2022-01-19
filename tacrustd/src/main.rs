use crate::client::Client;
use crate::state::State;
use clap_rs as clap;
use color_eyre::Report;
use futures::{SinkExt, StreamExt};
use regex::Regex;
use serde::{Deserialize, Serialize};
use simple_error::bail;
use std::collections::HashMap;
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
    values: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Cmd {
    name: String,
    vals: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Group {
    name: String,
    defservice: Option<String>,
    acl: Option<String>,
    pap: Option<String>,
    member: Option<String>,
    #[serde(rename = "service")]
    service: Option<Vec<Service>>,
    #[serde(rename = "cmd")]
    cmd: Option<Vec<Cmd>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    name: String,
    credentials: Credentials,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Acl {
    permit: Vec<String>,
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

    // List of ACLs
    #[serde(rename = "acl")]
    acls: Option<Vec<Acl>>,

    #[serde(rename = "group")]
    group: Option<Vec<Group>>,
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    let config = Arc::new(setup()?);
    let state = Arc::new(RwLock::new(State::new(config.key.as_bytes().to_vec())));
    let listener = TcpListener::bind(&config.listen_address).await?;

    let acl = if config.acls.is_some() {
        config
            .acls
            .as_ref()
            .unwrap()
            .into_iter()
            .map(|acl| String::from(&(acl.permit.join(r"|"))))
            .fold(String::new(), |result, acl| {
                if result.is_empty() {
                    acl
                } else {
                    format!("{}|{}", result, acl)
                }
            })
    } else {
        String::new()
    };

    if config.users.is_some() {
        let mut state = state.write().await;
        for user in config.users.as_ref().unwrap() {
            state.users.insert(user.name.clone(), user.clone());
        }
    }

    {
        let mut state = state.write().await;
        state.acl_regex = Regex::new(&acl)?;
    }

    tracing::debug!("config: {:?}", config);
    tracing::debug!("state: {:?}", state.read().await);
    tracing::debug!("acl: {:?}", acl);
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
    state: Arc<RwLock<State>>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<(), Report> {
    let pipe = Framed::new(stream, BytesCodec::new());
    let mut client = Client::new(state.clone(), pipe).await?;
    let ip = addr.ip();

    {
        let state = state.read().await;
        if state.acl_regex.is_match(&(ip.to_string())) {
            tracing::info!("processing connection from {}", ip);
        } else {
            bail!("rejecting connection attempt from {}", ip);
        }
    }

    loop {
        tokio::select! {
            Some(msg) = client.rx.recv() => {
                tracing::info!("sending {} bytes to {}: {:?}", msg.len(), addr, msg);
                client.pipe.send(msg.into()).await?;
            }
            result = client.pipe.next() => match result {
                Some(Ok(msg)) => {
                    tracing::info!("received {} bytes from {}: {:?}", msg.len(), addr, msg);
                    let response = tacacs::process_tacacs_packet(&mut client, &msg).await?;

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

#[test]
pub fn parse_group_config_test() {
    let map: HashMap<String, String> =
        HashMap::from([(String::from("F5-LTM-User-Info-1"), String::from("remote"))]);
    let service = Service {
        name: "ppp protocol = ip".to_string(),
        values: map,
    };

    let cmd_map: HashMap<String, String> =
        HashMap::from([(String::from("permit"), String::from("power show"))]);
    let cmd = Cmd {
        name: "show".to_string(),
        vals: cmd_map,
    };

    let group = Group {
        name: String::from("testgroup"),
        defservice: Some("testservice".to_string()),
        acl: Some("testacl".to_string()),
        pap: Some("PAM".to_string()),
        member: Some("subgroup".to_string()),
        service: Some(vec![service]),
        cmd: Some(vec![cmd]),
    };

    let config = setup().unwrap();
    let res_group = config.group.unwrap();
    assert_eq!(group, res_group[0]);
}
