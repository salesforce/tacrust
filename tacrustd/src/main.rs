use crate::client::Client;
use crate::state::State;
use clap_rs as clap;
use color_eyre::Report;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use simple_error::bail;
use std::net::SocketAddr;
use std::{path::Path, sync::Arc};
use tacrust::{
    parser, serializer, AuthenticationReplyFlags, AuthenticationStatus, Body, Header, Packet,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_util::codec::{BytesCodec, Framed};
use tracing_subscriber::EnvFilter;
use twelf::{config, Layer};

mod client;
mod state;

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
struct Config {
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
                    let response = process_tacacs_packet(&mut client, config.clone(), &msg).await?;

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

const CLIENT_MAP_KEY_USERNAME: &str = "username";

async fn process_tacacs_packet(
    client: &mut Client,
    config: Arc<Config>,
    request_bytes: &[u8],
) -> Result<Vec<u8>, Report> {
    let request_packet = match parser::parse_packet(request_bytes, &config.key.as_bytes()) {
        Ok((_, p)) => p,
        Err(e) => bail!("unable to parse packet: {:?}", e),
    };

    let response_packet = match request_packet.body {
        Body::AuthenticationStart {
            action: _,
            priv_lvl: _,
            authen_type: _,
            authen_service: _,
            user,
            port: _,
            rem_addr: _,
            data: _,
        } => {
            client.map.insert(
                CLIENT_MAP_KEY_USERNAME.to_string(),
                String::from_utf8_lossy(&user).to_string(),
            );

            Ok(Packet {
                header: request_packet.header.clone(),
                body: Body::AuthenticationReply {
                    status: AuthenticationStatus::GetPass,
                    flags: AuthenticationReplyFlags { no_echo: true },
                    server_msg: b"Password: ".to_vec(),
                    data: b"".to_vec(),
                },
            })
        }
        Body::AuthenticationContinue {
            flags: _,
            user,
            data: _,
        } => {
            let username = match client.map.get(CLIENT_MAP_KEY_USERNAME) {
                Some(u) => Ok(u.clone()),
                None => Err(Report::msg("username not found")),
            }?;
            let password = String::from_utf8_lossy(&user).to_string();
            let authen_status = if verify_password_from_config(config.clone(), &username, &password)
                .await
                .unwrap_or(false)
            {
                AuthenticationStatus::Pass
            } else {
                AuthenticationStatus::Fail
            };
            tracing::debug!(
                "verifying credentials: username={}, password={} | result={:?}",
                username,
                password,
                authen_status
            );
            Ok(Packet {
                header: request_packet.header.clone(),
                body: Body::AuthenticationReply {
                    status: authen_status,
                    flags: AuthenticationReplyFlags { no_echo: false },
                    server_msg: b"".to_vec(),
                    data: b"".to_vec(),
                },
            })
        }
        _ => Err(Report::msg("not supported yet")),
    }?;

    let response_bytes =
        match serializer::serialize_packet(&response_packet, &config.key.as_bytes()) {
            Ok(b) => b,
            Err(e) => bail!("unable to serialize packet: {:?}", e),
        };
    Ok(response_bytes)
}

async fn verify_password_from_config(
    config: Arc<Config>,
    username: &str,
    password: &str,
) -> Result<bool, Report> {
    if config.users.is_none() {
        return Err(Report::msg("no users found in config"));
    }

    let user = config
        .users
        .as_ref()
        .unwrap()
        .into_iter()
        .find(|u| u.name == username);
    if user.is_none() {
        return Err(Report::msg("user not found in config"));
    }

    if let Credentials::Ascii(pw) = &user.unwrap().credentials {
        if password == pw {
            return Ok(true);
        }
    }

    Ok(false)
}
