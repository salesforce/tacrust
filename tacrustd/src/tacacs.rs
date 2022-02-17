use crate::state::State;
use crate::{Cmd, Credentials, Service, User};
use color_eyre::Report;
use regex::Regex;
use simple_error::bail;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tacrust::{
    parser, serializer, AuthenticationReplyFlags, AuthenticationStatus, AuthorizationStatus, Body,
    Header, Packet,
};
use tokio::sync::RwLock;

const CLIENT_MAP_KEY_USERNAME: &str = "username";

#[derive(Clone, Debug)]
pub struct PacketArgs {
    service: Vec<String>,
    cmd: Vec<String>,
    cmd_args: Vec<String>,
}

fn normalized_match(s1: &str, s2: &str) -> bool {
    if s1.len() == 0 || s2.len() == 0 {
        return true;
    }
    let s1_match = s1 == "shell" || s1 == "exec";
    let s2_match = s2 == "shell" || s2 == "exec";
    return (s1_match && s2_match) || (s1 == s2);
}

pub trait Compare {
    fn avtype(&self) -> &'static str;
    fn name(&self) -> String;
    fn get_args(&self) -> Vec<String>;
    fn compare(&self, args: &Vec<String>) -> Vec<String> {
        let mut result_args: Vec<String> = Vec::new();
        tracing::debug!(
            "comparing packet=<{:?}> with config=<{:?}={:?}>",
            args,
            self.avtype(),
            self.name()
        );
        for avpairs in args.iter() {
            let target_value = self.name();
            let split_avpairs: Vec<&str> = (&avpairs).split(&"=").collect();
            if split_avpairs.len() != 2 {
                tracing::debug!("\tinvalid values for config_args [{:?}]", avpairs);
                continue;
            }
            let (tactype, tacvalue) = (split_avpairs[0], split_avpairs[1]);
            if tactype == self.avtype() && normalized_match(tacvalue, &target_value) {
                tracing::debug!(
                    "\tpacket <{}> == config <{}={}> ✓",
                    avpairs,
                    self.avtype(),
                    &target_value
                );
                let args = &mut self.get_args();
                result_args.append(args);
            } else {
                tracing::debug!(
                    "\tpacket <{}> != config <{}={}> ✘",
                    avpairs,
                    self.avtype(),
                    &target_value
                );
            }
        }
        result_args
    }
}

impl Compare for Service {
    fn name(&self) -> String {
        self.name.clone()
    }
    fn get_args(&self) -> Vec<String> {
        self.args.clone()
    }

    fn avtype(&self) -> &'static str {
        "service"
    }
}
impl Compare for Cmd {
    fn name(&self) -> String {
        self.name.clone()
    }
    fn get_args(&self) -> Vec<String> {
        self.list.clone()
    }

    fn avtype(&self) -> &'static str {
        "cmd"
    }
}

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
        .entry(addr.ip())
        .or_insert_with(|| Arc::new(RwLock::new(HashMap::new())))
        .clone();
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
                    "verifying credentials: username={}, password=({} bytes) | result={:?}",
                    username,
                    password.len(),
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
            let user_found = shared_state.read().await.users.contains_key(&username);
            let mut arg_result: Vec<Vec<u8>> = Vec::new();
            if user_found {
                let user = shared_state
                    .read()
                    .await
                    .users
                    .get(&username)
                    .unwrap()
                    .clone();
                for arg in &args {
                    tracing::debug!("arg: {}", String::from_utf8_lossy(&arg));
                }
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

pub async fn process_args(args: &Vec<Vec<u8>>) -> Result<PacketArgs, Report> {
    let mut packet_args = PacketArgs {
        service: vec![],
        cmd: vec![],
        cmd_args: vec![],
    };

    for args in args.iter() {
        let val = String::from_utf8_lossy(args.clone().as_slice()).to_string();
        if val.starts_with(&"service=".to_string()) {
            packet_args.service.push(val);
        } else if val.starts_with(&"cmd=".to_string()) {
            packet_args.cmd.push(val);
        } else if val.starts_with(&"cmdarg=".to_string())
            || val.starts_with(&"cmd-arg=".to_string())
        {
            packet_args.cmd_args.push(val);
        } else {
            continue;
        }
    }
    Ok(packet_args)
}

pub async fn verify_authorization(
    shared_state: Arc<RwLock<State>>,
    user: &User,
    rem_address: &[u8],
    args: PacketArgs,
) -> Vec<String> {
    tracing::info!("verifying authorization for {}", user.name);
    let mut auth_result: Vec<String> = Vec::new();
    let packet_args = &mut args.clone();
    if user.member.is_none() {
        return auth_result;
    }
    let mut next_group_name = user.member.as_ref().unwrap().to_string();
    let mut next_group_found = shared_state
        .read()
        .await
        .groups
        .contains_key(&next_group_name);
    while next_group_found {
        tracing::debug!("verifying authorization against group {}", &next_group_name);
        let next_group = shared_state
            .read()
            .await
            .groups
            .get(&next_group_name)
            .unwrap()
            .clone();
        let list_service = &mut verify_service(&next_group.service, &packet_args).await;
        tracing::debug!("service authorization results: {:?}", &list_service);
        let list_cmd = &mut verify_cmd(&next_group.cmds, &packet_args).await;
        tracing::debug!("cmd authorization results: {:?}", &list_cmd);
        let (acl_result, matching_acl) =
            &mut verify_acl(shared_state.clone(), &next_group.acl, rem_address).await;
        tracing::debug!("acl results: ({}, {})", &acl_result, &matching_acl);
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
            next_group_found = shared_state
                .read()
                .await
                .groups
                .contains_key(&next_group_name);
        } else {
            break;
        }
    }
    return auth_result;
}

pub async fn verify_service(
    service: &Option<Vec<Service>>,
    packet_args: &PacketArgs,
) -> Vec<String> {
    let mut service_result: Vec<String> = Vec::new();
    if let Some(services) = service {
        for service in services {
            let result = &mut service.compare(&packet_args.service);
            if result.len() != 0 {
                service_result.append(result)
            }
        }
    }
    service_result
}

pub async fn verify_cmd(cmd: &Option<Vec<Cmd>>, packet_args: &PacketArgs) -> Vec<String> {
    let mut cmd_result: Vec<String> = Vec::new();
    if let Some(cmds) = cmd {
        for cmd in cmds {
            let result = &mut cmd.compare(&packet_args.cmd);
            if result.len() == 0 {
                continue;
            }
            let mut formatted: Vec<String> =
                result.iter().map(|r| format!("cmd-arg = {}", r)).collect();
            cmd_result.append(&mut formatted);
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
        let (acl_action, acl_regex) = (acl_expr_split[0].trim(), acl_expr_split[1].trim());
        let acl_regex_compiled = shared_state
            .write()
            .await
            .regexes
            .entry(acl_regex.to_string())
            .or_insert_with(|| {
                Arc::new(Regex::new(acl_regex).unwrap_or_else(|_| Regex::new("$.").unwrap()))
            })
            .clone();
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
    users: &HashMap<String, Arc<User>>,
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
