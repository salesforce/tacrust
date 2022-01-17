use crate::client::Client;
use crate::{Config, Credentials};

use color_eyre::Report;
use simple_error::bail;
use std::sync::Arc;
use tacrust::{parser, serializer, AuthenticationReplyFlags, AuthenticationStatus, Body, Packet};

const CLIENT_MAP_KEY_USERNAME: &str = "username";

pub async fn process_tacacs_packet(
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

pub async fn verify_password_from_config(
    config: Arc<Config>,
    username: &str,
    password: &str,
) -> Result<bool, Report> {
    if config.users.is_none() {
        return Err(Report::msg("no users found in config"));
    }

    // for large number of users this would be highly inefficient
    // should be fixed by building a hashmap of usernames when loading config
    let user = config
        .users
        .as_ref()
        .unwrap()
        .into_iter()
        .find(|u| u.name == username);
    if user.is_none() {
        return Err(Report::msg("user not found in config"));
    }

    if let Credentials::Ascii(hash) = &user.unwrap().credentials {
        if tacrust::hash::verify_hash(password.as_bytes(), hash).unwrap_or(false) {
            return Ok(true);
        }
    }

    Ok(false)
}
