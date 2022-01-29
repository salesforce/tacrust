use crate::state::State;
use crate::{Cmd, Compare, Credentials, Group, Service, User};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use color_eyre::Report;
use simple_error::bail;
use tacrust::{
    parser, serializer, AuthenticationReplyFlags, AuthenticationStatus, AuthorizationStatus, Body,
    Packet,
};
use tokio::sync::RwLock;

const CLIENT_MAP_KEY_USERNAME: &str = "username";

pub async fn process_tacacs_packet(
    shared_state: Arc<RwLock<State>>,
    addr: &SocketAddr,
    request_bytes: &[u8],
) -> Result<Vec<u8>, Report> {
    let mut state = shared_state.read().await;
    let map = match state.maps.get(&addr.ip()) {
        Some(existing_map) => existing_map.clone(),
        None => {
            let new_map = Arc::new(RwLock::new(HashMap::new()));
            {
                drop(state);
                {
                    let mut state = shared_state.write().await;
                    state.maps.insert(addr.ip(), new_map.clone());
                }
                state = shared_state.read().await;
            }
            new_map
        }
    };
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
            map.write().await.insert(
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
            let username = match map.read().await.get(CLIENT_MAP_KEY_USERNAME) {
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

        Body::AuthorizationRequest {
            auth_method: _,
            priv_lvl: _,
            authen_type: _,
            authen_service: _,
            user,
            port: _,
            rem_address: _,
            args,
        } => {
            let username = String::from_utf8_lossy(&user).to_string();
            // process auth args
            let mut arg_result: Vec<Vec<u8>> = Vec::new();
            if let Some(user) = state.users.get(&username) {
                let args_map = process_args(&args).await?;
                let result = verify_authorization(user, args_map, &state.groups).await;
                if result
                    .iter()
                    .map(|val| arg_result.push(val.as_bytes().to_vec()))
                    .count()
                    > 0
                {
                    Ok(Packet {
                        header: request_packet.header.clone(),
                        body: Body::AuthorizationReply {
                            status: AuthorizationStatus::AuthPassAdd,
                            data: vec![],
                            server_msg: vec![],
                            args: arg_result,
                        },
                    })
                } else {
                    Ok(Packet {
                        header: request_packet.header.clone(),
                        body: Body::AuthorizationReply {
                            status: AuthorizationStatus::AuthStatusFail,
                            data: vec![],
                            server_msg: vec![],
                            args,
                        },
                    })
                }
            } else {
                Ok(Packet {
                    header: request_packet.header.clone(),
                    body: Body::AuthorizationReply {
                        status: AuthorizationStatus::AuthStatusFail,
                        data: vec![],
                        server_msg: vec![],
                        args,
                    },
                })
            }
        }
        _ => Err(Report::msg("not supported yet")),
    }?;

    let response_bytes = match serializer::serialize_packet(&response_packet, &(state.key)) {
        Ok(b) => b,
        Err(e) => bail!("unable to serialize packet: {:?}", e),
    };
    Ok(response_bytes)
}

pub async fn process_args(args: &Vec<Vec<u8>>) -> Result<(Vec<String>, Vec<String>), Report> {
    let mut service: Vec<String> = Vec::new();
    let mut cmd: Vec<String> = Vec::new();

    for args in args.iter() {
        let val = String::from_utf8_lossy(args.clone().as_slice()).to_string();
        if val.contains(&"service".to_string()) {
            service.push(val);
        } else if val.contains(&"cmd".to_string()) {
            cmd.push(val);
        } else {
            return Err(Report::msg("the current arguement is not processed"));
        }
    }
    Ok((service, cmd))
}

pub async fn verify_authorization(
    user: &User,
    args: (Vec<String>, Vec<String>),
    groups: &HashMap<String, Group>,
) -> Vec<String> {
    let mut auth_result: Vec<String> = Vec::new();
    let args_local = &mut args.clone();
    match &user.member {
        Some(name) => {
            let mut group_name = name.as_str();
            while let Some(group) = groups.get(group_name) {
                let list_service = &mut verify_service(&group.service, &mut args_local.0).await;
                let list_cmd = &mut verify_cmd(&group.cmds, &mut args_local.1).await;
                if list_service.len() != 0 || list_cmd.len() != 0 {
                    auth_result.append(list_service);
                    auth_result.append(list_cmd);
                    return auth_result;
                }
                if let Some(member) = &group.member {
                    group_name = member.as_str();
                } else {
                    return auth_result;
                }
            }
            return auth_result;
        }

        None => {
            return auth_result;
        }
    }
}

pub async fn verify_service(service: &Option<Vec<Service>>, args: &mut Vec<String>) -> Vec<String> {
    let mut service_result: Vec<String> = Vec::new();
    let service_local = &mut service.clone();
    match service_local {
        Some(services) => {
            let mut iter = services.iter();
            while let Some(service) = iter.next() {
                let result = &mut service.compare(args);
                if result.len() == 0 {
                    continue;
                } else {
                    service_result.append(result)
                }
            }
            service_result
        }

        None => {
            return service_result;
        }
    }
}

pub async fn verify_cmd(cmd: &Option<Vec<Cmd>>, args: &mut Vec<String>) -> Vec<String> {
    let mut cmd_result: Vec<String> = Vec::new();
    let cmd_local = &mut cmd.clone();
    match cmd_local {
        Some(cmds) => {
            let mut iter = cmds.iter();
            while let Some(cmd) = iter.next() {
                let result = &mut cmd.compare(args);
                if result.len() == 0 {
                    continue;
                } else {
                    cmd_result.append(result)
                }
            }
            cmd_result
        }

        None => {
            return cmd_result;
        }
    }
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
