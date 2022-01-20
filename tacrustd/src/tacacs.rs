use crate::client::Client;
use crate::{Credentials, User};

use color_eyre::Report;
use simple_error::bail;
use std::collections::HashMap;
use tacrust::{parser, serializer, AuthenticationReplyFlags, AuthenticationStatus, Body, Packet};

const CLIENT_MAP_KEY_USERNAME: &str = "username";

pub async fn process_tacacs_packet(
    client: &mut Client,
    request_bytes: &[u8],
) -> Result<Vec<u8>, Report> {
    let state = client.shared_state.read().await;
    let request_packet = match parser::parse_packet(request_bytes, &(state.key)) {
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
            let authen_status = if verify_user_credentials(&(state.users), &username, &password)
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

    let response_bytes = match serializer::serialize_packet(&response_packet, &(state.key)) {
        Ok(b) => b,
        Err(e) => bail!("unable to serialize packet: {:?}", e),
    };
    Ok(response_bytes)
}

pub async fn verify_user_credentials(
    users: &HashMap<String, User>,
    username: &str,
    password: &str,
) -> Result<bool, Report> {
    let user = users.get(username);

    if user.is_none() {
        return Ok(false);
    }

    match &user.unwrap().credentials {
        Credentials::Ascii(hash) => {
            if tacrust::hash::verify_hash(password.as_bytes(), hash).unwrap_or(false) {
                return Ok(true);
            }
        }
        Credentials::Pam => {
            let mut pam_auth = pam::Authenticator::with_password("ssh")?;
            pam_auth.get_handler().set_credentials(username, password);
            return Ok(pam_auth.authenticate().is_ok());
        }
    }

    Ok(false)
}

#[tokio::test]
pub async fn test_verify_user_credentials() {
    let username = "rahul";
    let password = "helloworld";
    let mut users: HashMap<String, User> = HashMap::new();
    let pwd = "$6$4Q1OSpnJ.0z1p$zA3G.m2817WlmyTOQSn/mjq.j3AH6AorPXuztfKy1FK2XJUonk/oXimh/fJq0/2ktuYUGf83LPb5sGUv9RBxp/";
    let user = User {
        name: "rahul".to_string(),
        credentials: Credentials::Ascii(pwd.to_string()),
    };
    users.insert(user.name.clone(), user.clone());
    let result = verify_user_credentials(&users, username, password)
        .await
        .unwrap_or(false);
    assert!(result);
}

