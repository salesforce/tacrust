use crate::state::State;
use crate::{Cmd, Credentials, Service, User};
use color_eyre::Report;
use itertools::Itertools;
use lazy_static::lazy_static;
use regex::Regex;
use simple_error::bail;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tacrust::{parser, serializer, AuthenticationReplyFlags, AuthenticationStatus, AuthenticationType, AuthorizationStatus, Body, Header, Packet, AccountingReplyStatus};
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

pub trait ConfigAvPair {
    fn key(&self) -> &'static str;
    fn value(&self) -> String;
    fn subargs(&self) -> Vec<String>;
    fn compare(&self, packet_avpairs: &Vec<String>) -> Vec<String> {
        let mut result_args: Vec<String> = Vec::new();
        tracing::debug!(
            "\tcomparing config=<{}={}> with packet=<{:?}>",
            self.key(),
            self.value(),
            packet_avpairs
        );
        for packet_avpair in packet_avpairs {
            let self_value = self.value();
            let packet_avpair_split: Vec<&str> = (&packet_avpair).split(&"=").collect();
            if packet_avpair_split.len() != 2 {
                tracing::debug!("\t\tinvalid arguments in packet [{:?}]", packet_avpair);
                continue;
            }
            let (packet_avpair_key, packet_avpair_value) =
                (packet_avpair_split[0], packet_avpair_split[1]);
            if packet_avpair_key == self.key() && normalized_match(packet_avpair_value, &self_value)
            {
                tracing::debug!(
                    "\t\tconfig <{}={}> == packet<{}={}> ✓",
                    self.key(),
                    &self_value,
                    packet_avpair_key,
                    packet_avpair_value
                );
                let args = &mut self.subargs();
                result_args.append(args);
            } else {
                tracing::debug!(
                    "\t\tconfig <{}={}> != packet<{}={}> ✘",
                    self.key(),
                    &self_value,
                    packet_avpair_key,
                    packet_avpair_value
                );
            }
        }
        result_args
    }
}

impl ConfigAvPair for Service {
    fn value(&self) -> String {
        self.name.clone()
    }
    fn subargs(&self) -> Vec<String> {
        if self.args.is_none() {
            return vec![];
        }
        self.args.as_ref().unwrap().clone()
    }

    fn key(&self) -> &'static str {
        "service"
    }
}
impl ConfigAvPair for Cmd {
    fn value(&self) -> String {
        self.name.clone()
    }
    fn subargs(&self) -> Vec<String> {
        self.list.clone()
    }

    fn key(&self) -> &'static str {
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
            authen_type,
            authen_service: _,
            user,
            port: _,
            rem_addr: _,
            data,
        } => {
            if user.len() > 0 {
                map.write().await.insert(
                    CLIENT_MAP_KEY_USERNAME.to_string(),
                    String::from_utf8_lossy(&user).to_string(),
                );

                if authen_type == AuthenticationType::Pap as u8 {
                    let username = map
                        .read()
                        .await
                        .get(CLIENT_MAP_KEY_USERNAME)
                        .unwrap_or(&String::new())
                        .clone();
                    let password = String::from_utf8_lossy(&data).to_string();
                    let authen_status =
                        if verify_user_credentials(shared_state.clone(), &username, &password)
                            .await
                            .unwrap_or(false)
                        {
                            AuthenticationStatus::Pass
                        } else {
                            AuthenticationStatus::Fail
                        };
                    tracing::info!(
                        "verifying credentials: username={}, password=({} bytes) | result={:?}",
                        username,
                        password.len(),
                        authen_status
                    );

                    Ok(Packet {
                        header: generate_response_header(&request_packet.header),
                        body: Body::AuthenticationReply {
                            status: authen_status,
                            flags: AuthenticationReplyFlags { no_echo: true },
                            server_msg: b"".to_vec(),
                            data: b"".to_vec(),
                        },
                    })
                } else {
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
                let authen_status =
                    if verify_user_credentials(shared_state.clone(), &username, &password)
                        .await
                        .unwrap_or(false)
                    {
                        AuthenticationStatus::Pass
                    } else {
                        AuthenticationStatus::Fail
                    };
                tracing::info!(
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
                            args: vec![],
                        },
                    })
                }
            } else {
                tracing::info!(
                    "user specified in authz request not found in config: {}",
                    username
                );
                Ok(Packet {
                    header: generate_response_header(&request_packet.header),
                    body: Body::AuthorizationReply {
                        status: AuthorizationStatus::AuthStatusFail,
                        data: vec![],
                        server_msg: vec![],
                        args: vec![],
                    },
                })
            }
        }
        
        Body::AccountingRequest { 
            flags, 
            authen_method, 
            priv_lvl, 
            authen_type, 
            authen_service, 
            user, 
            port, 
            rem_addr, 
            args } => {
            Ok(Packet {
                header: generate_response_header(&request_packet.header),
                body: Body::AccountingReply {
                    status: AccountingReplyStatus::AcctStatusSuccess,
                    server_msg: vec![],
                    data: vec![]
                },
            })
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

async fn verify_authorization_helper(
    shared_state: Arc<RwLock<State>>,
    args: PacketArgs,
    service: &Option<Vec<Service>>,
    cmds: &Option<Vec<Cmd>>,
) -> Vec<String> {
    let mut auth_result: Vec<String> = Vec::new();

    let service_match_results = &mut verify_service(service, &args).await;
    tracing::debug!(
        "service authorization results: {:?}",
        &service_match_results
    );

    let cmd_match_results = &mut verify_cmd(shared_state.clone(), cmds, &args).await;
    tracing::debug!("cmd authorization results: {:?}", &cmd_match_results);

    tracing::debug!(
        "{} matches found for service, {} matches found for cmd",
        service_match_results.len(),
        cmd_match_results.len()
    );
    auth_result.append(service_match_results);
    auth_result.append(cmd_match_results);

    return auth_result.into_iter().unique().collect();
}

pub async fn verify_authorization(
    shared_state: Arc<RwLock<State>>,
    user: &User,
    rem_address: &[u8],
    args: PacketArgs,
) -> Vec<String> {
    tracing::info!("packet args: {:?}", args);
    tracing::info!("verifying authorization for {}", user.name);
    let mut auth_result: Vec<String> = Vec::new();
    let mut acl_results: Vec<(bool, Option<String>)> = Vec::new();
    let mut _acl_found = false;

    if user.acl.is_some() {
        _acl_found = true;
        let (acl_result, matching_acl) =
            verify_acl(shared_state.clone(), &user.acl, rem_address).await;
        acl_results.push((acl_result, matching_acl));
    }

    if user.member.is_none() {
        return auth_result;
    }

    let mut groups_pending = user.member.as_ref().unwrap().clone();
    let mut groups_processed = vec![];

    tracing::debug!("pending groups: {:?}", groups_pending);

    while let Some(next_group) = groups_pending.pop() {
        tracing::debug!("pending groups: {:?}", groups_pending);
        tracing::debug!("processed groups: {:?}", groups_processed);
        tracing::info!("result so far: {:?}", auth_result);
        tracing::info!("next group: {}", &next_group);

        let group = match shared_state.read().await.groups.get(&next_group) {
            Some(g) => g.clone(),
            None => {
                tracing::info!("group {} not found in config", next_group);
                continue;
            }
        };

        tracing::debug!("group {} was found in config", next_group);

        let auth_results_for_group = verify_authorization_helper(
            shared_state.clone(),
            args.clone(),
            &group.service,
            &group.cmds,
        )
        .await;
        auth_result.extend(auth_results_for_group);

        if group.acl.is_some() {
            _acl_found = true;
            let (acl_result, matching_acl) =
                verify_acl(shared_state.clone(), &group.acl, rem_address).await;
            acl_results.push((acl_result, matching_acl));
        }

        groups_processed.push(group.name.clone());

        if group.member.is_none() {
            continue;
        }
        let next_group = group.member.as_ref().unwrap().to_string();
        if groups_processed.contains(&next_group) {
            continue;
        }
        groups_pending.push(next_group);
    }

    for (acl_result, matching_acl) in acl_results.into_iter() {
        if matching_acl.is_some() {
            tracing::debug!("an acl was matched: ({}, {:?})", &acl_result, matching_acl);
            if acl_result {
                return auth_result.into_iter().unique().collect();
            } else {
                return vec![];
            }
        }
    }

    if _acl_found {
        tracing::debug!(
            "at least one acl was found to be applicable to the user, but none permitted the request",
        );
        return vec![];
    }

    tracing::debug!("no acls found applicable to the user");
    return auth_result.into_iter().unique().collect();
}

pub async fn verify_service(
    service: &Option<Vec<Service>>,
    packet_args: &PacketArgs,
) -> Vec<String> {
    let mut service_result: Vec<String> = Vec::new();
    if let Some(services) = service {
        for service in services {
            let config_service_args = &mut service.compare(&packet_args.service);
            service_result.append(config_service_args);
        }
    }
    service_result
}

pub async fn verify_cmd_args(
    shared_state: Arc<RwLock<State>>,
    config_cmd_args: &Vec<String>,
    packet_args: &PacketArgs,
) -> Vec<String> {
    let mut matching_args_result: Vec<String> = Vec::new();
    let mut packet_cmd_args_joined = String::new();
    for packet_cmd_arg in &packet_args.cmd_args {
        let split_args: Vec<&str> = packet_cmd_arg.split("=").collect();
        if split_args.len() != 2 {
            continue;
        }
        packet_cmd_args_joined.push_str(split_args[1]);
        packet_cmd_args_joined.push_str(" ");
    }
    tracing::debug!("packet_cmd_args_joined: {}", packet_cmd_args_joined);
    for config_cmd_arg in config_cmd_args {
        tracing::debug!("config_cmd_arg: {}", config_cmd_arg);
        if config_cmd_arg == "deny" {
            return matching_args_result;
        } else if config_cmd_arg == "permit" {
            matching_args_result.extend(packet_args.cmd_args.clone());
            return matching_args_result;
        }

        lazy_static! {
            static ref RE_PERMIT: Regex = Regex::new(r#"permit\s+(.*)"#).unwrap();
        }

        let cmd_arg_regex = if let Some(matches) = RE_PERMIT.captures(config_cmd_arg) {
            let config_cmd_arg_quoted = matches[1].to_string();
            config_cmd_arg_quoted.trim_matches('"').to_string()
        } else {
            config_cmd_arg.to_string()
        };

        tracing::debug!("cmd_arg_regex: {}", cmd_arg_regex);

        let regex_compiled = shared_state
            .write()
            .await
            .regexes
            .entry(cmd_arg_regex.to_string())
            .or_insert_with(|| {
                Arc::new(Regex::new(&cmd_arg_regex).unwrap_or_else(|_| Regex::new("$.").unwrap()))
            })
            .clone();
        if regex_compiled.is_match(&packet_cmd_args_joined) {
            matching_args_result.extend(packet_args.cmd_args.clone())
        }
    }
    matching_args_result
}

pub async fn verify_cmd(
    shared_state: Arc<RwLock<State>>,
    cmd: &Option<Vec<Cmd>>,
    packet_args: &PacketArgs,
) -> Vec<String> {
    let mut cmd_result: Vec<String> = Vec::new();
    if let Some(cmds) = cmd {
        for cmd in cmds {
            let config_cmd_args = &mut cmd.compare(&packet_args.cmd);
            if packet_args.cmd_args.len() > 0 {
                cmd_result.append(
                    &mut verify_cmd_args(shared_state.clone(), config_cmd_args, packet_args).await,
                );
            }
        }
    }
    cmd_result
}

pub async fn verify_acl(
    shared_state: Arc<RwLock<State>>,
    acl: &Option<String>,
    rem_address: &[u8],
) -> (bool, Option<String>) {
    tracing::debug!(
        "verifying acl {:?} against rem_address {:?}",
        acl,
        rem_address
    );
    if acl.is_none() {
        tracing::debug!("acl is empty");
        return (false, None);
    }
    let acl = {
        match shared_state.read().await.acls.get(acl.as_ref().unwrap()) {
            Some(acl) => acl.clone(),
            None => {
                tracing::debug!("acl {} not found in config", acl.as_ref().unwrap());
                return (false, None);
            }
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
            "permit" => return (true, Some(acl_expr.to_string())),
            "deny" => return (false, Some(acl_expr.to_string())),
            _ => continue,
        }
    }
    (false, None)
}

pub async fn verify_user_credentials(
    shared_state: Arc<RwLock<State>>,
    username: &str,
    password: &str,
) -> Result<bool, Report> {
    let user = match shared_state.read().await.users.get(username) {
        Some(u) => u.clone(),
        None => {
            tracing::info!("user {} not found in config", username);
            return Ok(false);
        }
    };

    match &user.credentials {
        Credentials::Ascii(hash) => {
            tracing::info!(
                "verifying password for {} against the hash specified in config",
                username
            );
            if tacrust::hash::verify_hash(password.as_bytes(), &hash).unwrap_or(false) {
                return Ok(true);
            }
        }
        Credentials::Pam => {
            let pam_service = shared_state.read().await.pam_service.clone();
            tracing::info!(
                "authenticating {} via pam service {}",
                username,
                pam_service
            );
            let mut pam_auth = pam::Authenticator::with_password(&pam_service)?;
            pam_auth.get_handler().set_credentials(username, password);
            return Ok(pam_auth.authenticate().is_ok());
        }
    }

    Ok(false)
}
