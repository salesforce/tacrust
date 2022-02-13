use crate::state::State;
use crate::{Cmd, Compare, Credentials, Group, Service, User};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use color_eyre::Report;
use regex::Regex;
use simple_error::bail;
use tacrust::{
    parser, serializer, AuthenticationReplyFlags, AuthenticationStatus, AuthorizationStatus, Body,
    Header, Packet,
};
use tokio::sync::RwLock;

const CLIENT_MAP_KEY_USERNAME: &str = "username";

fn generate_response_header(request_header: &Header) -> Header {
    Header {
        seq_no: request_header.seq_no + 1,
        ..*request_header
    }
}

pub async fn process_tacacs_packet(
    shared_state: Arc<RwLock<State>>,
    addr: &SocketAddr,
    request_bytes: &[u8],
) -> Result<Vec<u8>, Report> {
    let map = shared_state
        .write()
        .await
        .maps
        .remove(&addr.ip())
        .unwrap_or_else(|| Arc::new(RwLock::new(HashMap::new())))
        .clone();
    shared_state
        .write()
        .await
        .maps
        .insert(addr.ip(), map.clone());
    let request_packet = match parser::parse_packet(request_bytes, &(shared_state.read().await.key))
    {
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
            if user.len() > 0 {
                map.write().await.insert(
                    CLIENT_MAP_KEY_USERNAME.to_string(),
                    String::from_utf8_lossy(&user).to_string(),
                );

                Ok(Packet {
                    header: generate_response_header(&request_packet.header),
                    body: Body::AuthenticationReply {
                        status: AuthenticationStatus::GetPass,
                        flags: AuthenticationReplyFlags { no_echo: true },
                        server_msg: b"Password: ".to_vec(),
                        data: b"".to_vec(),
                    },
                })
            } else {
                Ok(Packet {
                    header: generate_response_header(&request_packet.header),
                    body: Body::AuthenticationReply {
                        status: AuthenticationStatus::GetUser,
                        flags: AuthenticationReplyFlags { no_echo: false },
                        server_msg: b"User: ".to_vec(),
                        data: b"".to_vec(),
                    },
                })
            }
        }
        Body::AuthenticationContinue {
            flags: _,
            user,
            data: _,
        } => {
            let username = {
                let map = map.read().await;
                map.get(CLIENT_MAP_KEY_USERNAME)
                    .unwrap_or(&String::new())
                    .clone()
            };
            if username.len() > 0 {
                let password = String::from_utf8_lossy(&user).to_string();
                let authen_status = if verify_user_credentials(
                    &(shared_state.read().await.users),
                    &username,
                    &password,
                )
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
                    header: generate_response_header(&request_packet.header),
                    body: Body::AuthenticationReply {
                        status: authen_status,
                        flags: AuthenticationReplyFlags { no_echo: false },
                        server_msg: b"".to_vec(),
                        data: b"".to_vec(),
                    },
                })
            } else {
                map.write().await.insert(
                    CLIENT_MAP_KEY_USERNAME.to_string(),
                    String::from_utf8_lossy(&user).to_string(),
                );

                Ok(Packet {
                    header: generate_response_header(&request_packet.header),
                    body: Body::AuthenticationReply {
                        status: AuthenticationStatus::GetPass,
                        flags: AuthenticationReplyFlags { no_echo: true },
                        server_msg: b"Password: ".to_vec(),
                        data: b"".to_vec(),
                    },
                })
            }
        }

        Body::AuthorizationRequest {
            auth_method: _,
            priv_lvl: _,
            authen_type: _,
            authen_service: _,
            user,
            port: _,
            rem_address,
            args,
        } => {
            let username = String::from_utf8_lossy(&user).to_string();
            let user = match shared_state.read().await.users.get(&username) {
                Some(u) => u.clone(),
                None => User::default(),
            };
            // process auth args
            let mut arg_result: Vec<Vec<u8>> = Vec::new();
            if user.name.len() > 0 {
                tracing::debug!("args: {:?}", &args);
                let args_map = process_args(&args).await?;
                let result =
                    verify_authorization(shared_state.clone(), &user, &rem_address, args_map).await;
                tracing::info!("authorization result: {:?}", result);
                if result
                    .iter()
                    .map(|val| arg_result.push(val.as_bytes().to_vec()))
                    .count()
                    > 0
                {
                    Ok(Packet {
                        header: generate_response_header(&request_packet.header),
                        body: Body::AuthorizationReply {
                            status: AuthorizationStatus::AuthPassAdd,
                            data: vec![],
                            server_msg: vec![],
                            args: arg_result,
                        },
                    })
                } else {
                    Ok(Packet {
                        header: generate_response_header(&request_packet.header),
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
                    header: generate_response_header(&request_packet.header),
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

    let response_bytes =
        match serializer::serialize_packet(&response_packet, &(shared_state.read().await.key)) {
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
        if val.starts_with(&"service=".to_string()) {
            service.push(val);
        } else if val.starts_with(&"cmd=".to_string()) || val.starts_with(&"cmdarg=".to_string()) {
            cmd.push(val);
        } else {
            return Err(Report::msg("the current arguement is not processed"));
        }
    }
    Ok((service, cmd))
}

pub async fn verify_authorization(
    shared_state: Arc<RwLock<State>>,
    user: &User,
    rem_address: &[u8],
    args: (Vec<String>, Vec<String>),
) -> Vec<String> {
    tracing::info!("verifying authorization for {}", user.name);
    let mut auth_result: Vec<String> = Vec::new();
    let args_local = &mut args.clone();
    match &user.member {
        Some(name) => {
            let mut next_group_name = name.to_string();
            let mut next_group = match shared_state.read().await.groups.get(&next_group_name) {
                Some(g) => g.clone(),
                None => Group::default(),
            };
            while next_group.name.len() > 0 {
                let list_service =
                    &mut verify_service(&next_group.service, &mut args_local.0).await;
                let list_cmd = &mut verify_cmd(&next_group.cmds, &mut args_local.1).await;
                let (acl_result, matching_acl) =
                    &mut verify_acl(shared_state.clone(), &next_group.acl, rem_address).await;
                if list_service.len() != 0 && list_cmd.len() != 0 && *acl_result {
                    auth_result.append(list_service);
                    auth_result.append(list_cmd);
                    auth_result.push(matching_acl.to_string());
                    return auth_result;
                }
                if let Some(member) = &next_group.member {
                    if member == &next_group_name {
                        return auth_result;
                    }
                    next_group_name = member.to_string();
                    next_group = match shared_state.read().await.groups.get(&next_group_name) {
                        Some(g) => g.clone(),
                        None => Group::default(),
                    };
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
    if let Some(services) = service {
        for service in services {
            let result = &mut service.compare(args);
            if result.len() != 0 {
                service_result.append(result)
            }
        }
    }
    service_result
}

pub async fn verify_cmd(cmd: &Option<Vec<Cmd>>, args: &mut Vec<String>) -> Vec<String> {
    let mut cmd_result: Vec<String> = Vec::new();
    if let Some(cmds) = cmd {
        for cmd in cmds {
            let result = &mut cmd.compare(args);
            if result.len() != 0 {
                cmd_result.append(result)
            }
        }
    }
    cmd_result
}

pub async fn verify_acl(
    shared_state: Arc<RwLock<State>>,
    acl: &Option<String>,
    rem_address: &[u8],
) -> (bool, String) {
    if acl.is_none() {
        return (false, String::new());
    }
    let acl = {
        match shared_state.read().await.acls.get(acl.as_ref().unwrap()) {
            Some(acl) => acl.clone(),
            None => return (false, String::new()),
        }
    };
    let rem_address = String::from_utf8_lossy(rem_address);
    tracing::debug!(
        "verifying rem_address {} against acl {:?}",
        rem_address,
        acl
    );
    for acl_expr in &(acl.list) {
        let acl_expr_split: Vec<&str> = acl_expr.split("=").collect();
        if acl_expr_split.len() != 2 {
            continue;
        }
        let (acl_action, acl_regex) = (
            acl_expr_split[0].clone().trim(),
            acl_expr_split[1].clone().trim(),
        );
        let acl_regex_compiled = shared_state
            .write()
            .await
            .regexes
            .remove(acl_regex)
            .unwrap_or_else(|| Regex::new(acl_regex).unwrap());
        shared_state
            .write()
            .await
            .regexes
            .insert(acl_regex.to_string(), acl_regex_compiled.clone());
        if !acl_regex_compiled.is_match(&rem_address) {
            continue;
        }
        match acl_action {
            "permit" => return (true, acl_expr.to_string()),
            "deny" => return (false, acl_expr.to_string()),
            _ => continue,
        }
    }
    (false, String::new())
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
