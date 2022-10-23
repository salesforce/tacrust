use crate::state::{ServiceArgValues, ServiceArgs, State};
use crate::{Credentials, Principal, Service, User};
use color_eyre::Report;
use indexmap::IndexMap;
use itertools::Itertools;
use lazy_static::lazy_static;
use regex::Regex;
use simple_error::bail;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use tacrust::{
    parser, serializer, AccountingReplyStatus, AuthenticationReplyFlags, AuthenticationStatus,
    AuthenticationType, AuthorizationStatus, Body, Header, Packet,
};
use tokio::sync::RwLock;
use tracing::Instrument;

const CLIENT_MAP_KEY_USERNAME: &str = "username";
const CLIENT_MAP_REQUESTED_AUTH_CONT_DATA: &str = "requested_auth_continue_data";

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum AclResult {
    Pass,
    Reject,
}

fn normalized_match(s1: &str, s2: &str) -> bool {
    if s1.is_empty() || s2.is_empty() {
        return true;
    }
    let s1_match = s1 == "shell" || s1 == "exec";
    let s2_match = s2 == "shell" || s2 == "exec";
    (s1_match && s2_match) || (s1 == s2)
}

fn generate_response_header(request_header: &Header) -> Header {
    Header {
        seq_no: request_header.seq_no + 1,
        ..*request_header
    }
}

pub(crate) async fn decrypt_request(
    request_bytes: &[u8],
    shared_state: Arc<RwLock<State>>,
) -> Result<(Vec<u8>, Packet), Report> {
    let shared_state_read = shared_state.read().await;
    let primary_key = &(shared_state_read.key);
    match parser::parse_packet(request_bytes, &(shared_state_read.key)) {
        Ok((_, p)) => {
            tracing::debug!("packet parsed with primary key");
            Ok((primary_key.to_vec(), p))
        }
        Err(e) => {
            tracing::debug!("unable to parse packet using primary key: {:?}", e);
            for extra_key in &(shared_state_read.extra_keys) {
                match parser::parse_packet(request_bytes, extra_key) {
                    Ok((_, p)) => {
                        tracing::debug!("packet parsed with extra key");
                        return Ok((extra_key.to_vec(), p));
                    }
                    Err(e) => {
                        tracing::debug!("unable to parse packet using extra key: {:?}", e)
                    }
                };
            }
            bail!("unable to parse packet using any keys: {:?}", e)
        }
    }
}

pub async fn process_tacacs_packet(
    shared_state: Arc<RwLock<State>>,
    addr: &SocketAddr,
    request_bytes: &[u8],
) -> Result<Vec<u8>, Report> {
    let (request_key, request_packet) =
        decrypt_request(request_bytes, shared_state.clone()).await?;

    tracing::debug!(request_header = ?request_packet.header);
    tracing::info!("{}", request_packet.body);

    let map = shared_state
        .write()
        .await
        .maps
        .entry((*addr, request_packet.header.session_id))
        .or_insert_with(|| Arc::new(RwLock::new(HashMap::new())))
        .clone();

    let response_packet = match &request_packet.body {
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
            if !user.is_empty() {
                let username = String::from_utf8_lossy(user).to_string();
                map.write()
                    .await
                    .insert(CLIENT_MAP_KEY_USERNAME.to_string(), username.to_string());
                if user_needs_forwarding(shared_state.clone(), &username).await? {
                    tracing::debug!(
                        "forwarding authentication request for user {} to upstream tacacs server",
                        username
                    );
                    process_proxy_request(shared_state.clone(), addr, request_bytes).await
                } else if *authen_type == AuthenticationType::Pap as u8 {
                    let username = map
                        .write()
                        .await
                        .remove(CLIENT_MAP_KEY_USERNAME)
                        .unwrap_or_default();

                    let password = String::from_utf8_lossy(data).to_string();
                    let authen_status =
                        if verify_user_credentials(shared_state.clone(), &username, &password)
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
                tracing::debug!("no username provided in authen start packet, requesting username");
                map.write().await.insert(
                    CLIENT_MAP_REQUESTED_AUTH_CONT_DATA.to_string(),
                    CLIENT_MAP_KEY_USERNAME.to_string(),
                );
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
            let requested_data = map
                .write()
                .await
                .remove(CLIENT_MAP_REQUESTED_AUTH_CONT_DATA)
                .unwrap_or_default();
            if requested_data == CLIENT_MAP_KEY_USERNAME {
                tracing::debug!("received username in authen cont packet, requesting password");
                let username = String::from_utf8_lossy(user).to_string();
                map.write()
                    .await
                    .insert(CLIENT_MAP_KEY_USERNAME.to_string(), username.to_string());
                Ok(Packet {
                    header: generate_response_header(&request_packet.header),
                    body: Body::AuthenticationReply {
                        status: AuthenticationStatus::GetPass,
                        flags: AuthenticationReplyFlags { no_echo: false },
                        server_msg: b"Password: ".to_vec(),
                        data: b"".to_vec(),
                    },
                })
            } else {
                let password = String::from_utf8_lossy(user).to_string();
                let username = map
                    .write()
                    .await
                    .remove(CLIENT_MAP_KEY_USERNAME)
                    .unwrap_or_default();
                if !username.is_empty() {
                    if user_needs_forwarding(shared_state.clone(), &username).await? {
                        tracing::debug!(
                            "forwarding authentication request for user {} to upstream tacacs server",
                            username
                        );
                        process_proxy_request(shared_state.clone(), addr, request_bytes).await
                    } else {
                        let authen_status =
                            if verify_user_credentials(shared_state.clone(), &username, &password)
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
                    }
                } else {
                    tracing::debug!(
                        "no valid username found for this session, requesting username"
                    );
                    map.write().await.insert(
                        CLIENT_MAP_REQUESTED_AUTH_CONT_DATA.to_string(),
                        CLIENT_MAP_KEY_USERNAME.to_string(),
                    );
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
            let username = String::from_utf8_lossy(user).to_string();
            let user_found = shared_state.read().await.users.contains_key(&username);
            if user_found {
                let user = shared_state
                    .read()
                    .await
                    .users
                    .get(&username)
                    .unwrap()
                    .clone();
                for arg in args {
                    tracing::debug!(arg = ?String::from_utf8_lossy(arg));
                }
                let (authz_status, authz_result) =
                    verify_authorization(shared_state.clone(), &user, addr, rem_address, args)
                        .await;
                tracing::debug!(?authz_status, ?authz_result);
                let mut authz_results_as_bytes: Vec<Vec<u8>> = Vec::new();
                for value in authz_result {
                    authz_results_as_bytes.push(value.as_bytes().to_vec());
                }
                match authz_status {
                    AuthorizationStatus::AuthPassAdd => Ok(Packet {
                        header: generate_response_header(&request_packet.header),
                        body: Body::AuthorizationReply {
                            status: AuthorizationStatus::AuthPassAdd,
                            data: vec![],
                            server_msg: vec![],
                            args: authz_results_as_bytes,
                        },
                    }),
                    AuthorizationStatus::AuthPassRepl => Ok(Packet {
                        header: generate_response_header(&request_packet.header),
                        body: Body::AuthorizationReply {
                            status: AuthorizationStatus::AuthPassRepl,
                            data: vec![],
                            server_msg: vec![],
                            args: authz_results_as_bytes,
                        },
                    }),
                    AuthorizationStatus::AuthForwardUpstream => {
                        process_proxy_request(shared_state.clone(), addr, request_bytes).await
                    }
                    _ => Ok(Packet {
                        header: generate_response_header(&request_packet.header),
                        body: Body::AuthorizationReply {
                            status: AuthorizationStatus::AuthStatusFail,
                            data: vec![],
                            server_msg: vec![],
                            args: vec![],
                        },
                    }),
                }
            } else {
                tracing::debug!(
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
            flags: _,
            authen_method: _,
            priv_lvl: _,
            authen_type: _,
            authen_service: _,
            user: _,
            port: _,
            rem_addr: _,
            args: _,
        } => Ok(Packet {
            header: generate_response_header(&request_packet.header),
            body: Body::AccountingReply {
                status: AccountingReplyStatus::AcctStatusSuccess,
                server_msg: vec![],
                data: vec![],
            },
        }),
        _ => Err(Report::msg("not supported yet")),
    }?;

    tracing::debug!(response_header = ?response_packet.header);
    tracing::info!("{}", response_packet.body);

    let response_bytes = match serializer::serialize_packet(&response_packet, &request_key) {
        Ok(b) => b,
        Err(e) => bail!("unable to serialize packet: {:?}", e),
    };
    Ok(response_bytes)
}

lazy_static! {
    static ref RE_SERVICE: Regex = Regex::new(r"service\s*(=|\*)\s*(.*)").unwrap();
    static ref RE_CMD: Regex = Regex::new(r"cmd\s*(=|\*)\s*(.*)").unwrap();
    static ref RE_CMD_ARG: Regex = Regex::new(r"cmd.arg\s*(=|\*)\s*(.*)").unwrap();
    static ref RE_MATCHER_ARG: Regex = Regex::new(r"(\S*?)\s*==\s*(.*)").unwrap();
    static ref RE_OTHER: Regex = Regex::new(r#"(\S*?)\s*(=|\*)\s*(.*)"#).unwrap();
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum AvPair {
    Service {
        mandatory: bool,
        value: String,
    },
    Cmd {
        mandatory: bool,
        value: String,
    },
    CmdArg {
        mandatory: bool,
        value: String,
    },
    MatcherArg {
        key: String,
        value: String,
    },
    Other {
        mandatory: bool,
        key: String,
        value: String,
    },
}

fn parse_avpair(avpair: &str) -> Option<AvPair> {
    if let Some(captures) = RE_SERVICE.captures(avpair) {
        return Some(AvPair::Service {
            mandatory: &captures[1] == "=",
            value: captures[2].trim_matches('"').to_string(),
        });
    }

    if let Some(captures) = RE_CMD.captures(avpair) {
        return Some(AvPair::Cmd {
            mandatory: &captures[1] == "=",
            value: captures[2].trim_matches('"').to_string(),
        });
    }

    if let Some(captures) = RE_CMD_ARG.captures(avpair) {
        return Some(AvPair::CmdArg {
            mandatory: &captures[1] == "=",
            value: captures[2].trim_matches('"').to_string(),
        });
    }

    if let Some(captures) = RE_MATCHER_ARG.captures(avpair) {
        return Some(AvPair::MatcherArg {
            key: captures[1].to_string(),
            value: captures[2].trim_matches('"').to_string(),
        });
    }

    if let Some(captures) = RE_OTHER.captures(avpair) {
        return Some(AvPair::Other {
            mandatory: &captures[2] == "=",
            key: captures[1].to_string(),
            value: captures[3].trim_matches('"').to_string(),
        });
    }

    None
}

struct IntermediateAuthZResults {
    authz_results: Vec<(AuthorizationStatus, String)>,
    acl_results: Vec<(AclResult, String)>,
}

async fn parse_args_for_config_service(service: &Service) -> Arc<RwLock<ServiceArgs>> {
    let service_args = Arc::new(RwLock::new(ServiceArgs::default()));
    let args = match &service.args {
        Some(a) => a,
        None => return service_args,
    };
    for arg in args {
        let parsed_arg = match parse_avpair(arg) {
            Some(a) => a,
            None => continue,
        };
        match &parsed_arg {
            AvPair::MatcherArg { key, value } => {
                service_args
                    .write()
                    .await
                    .matcher_args
                    .entry(key.to_string())
                    .or_insert_with(|| value.to_string());
            }
            AvPair::Other {
                mandatory,
                key,
                value,
            } => {
                if *mandatory {
                    service_args
                        .write()
                        .await
                        .mandatory_args
                        .entry(key.to_string())
                        .or_insert_with(|| ServiceArgValues {
                            default_value: value.to_string(),
                            allowed_values: HashSet::new(),
                        })
                        .allowed_values
                        .insert(value.to_string());
                } else {
                    service_args
                        .write()
                        .await
                        .optional_args
                        .entry(key.to_string())
                        .or_insert_with(|| ServiceArgValues {
                            default_value: value.to_string(),
                            allowed_values: HashSet::new(),
                        })
                        .allowed_values
                        .insert(value.to_string());
                }
            }
            _ => {}
        }
        tracing::debug!(?parsed_arg);
    }
    service_args
}

async fn authorize_svc(
    shared_state: Arc<RwLock<State>>,
    requested_service: &str,
    request_uses_cmd_authz: bool,
    principal: &(dyn Principal + Sync),
    request_avpairs: &[AvPair],
) -> IntermediateAuthZResults {
    tracing::debug!(?request_avpairs);

    let mut processed_avpairs: IndexMap<String, String> = IndexMap::new();
    let mut results = IntermediateAuthZResults {
        authz_results: vec![],
        acl_results: vec![],
    };

    let services = match principal.services() {
        Some(s) => {
            tracing::debug!(
                "{} services found for principal {}",
                s.len(),
                principal.name()
            );
            s
        }
        None => {
            tracing::debug!("no services found for principal {}", principal.name());
            return results;
        }
    };

    for service in services {
        if !normalized_match(&service.name, requested_service) {
            tracing::debug!(
                "{} != {} (the requested service)",
                &service.name,
                requested_service
            );
            continue;
        }
        tracing::debug!("service {} found in config", &service.name);
        let config_service_args = match shared_state
            .write()
            .await
            .service_args
            .entry((principal.name().to_string(), service.name.to_string()))
        {
            std::collections::hash_map::Entry::Occupied(o) => o.get().clone(),
            std::collections::hash_map::Entry::Vacant(_) => {
                parse_args_for_config_service(service).await
            }
        };
        let config_service_args_read = config_service_args.read().await;
        tracing::debug!(config_service_args=?*config_service_args_read);

        for request_avpair in request_avpairs {
            tracing::debug!(?request_avpair);

            let (mandatory, key, value) = match request_avpair {
                AvPair::Service { mandatory, value } => (*mandatory, "service", value.as_str()),
                AvPair::Cmd { mandatory, value } => (*mandatory, "cmd", value.as_str()),
                AvPair::CmdArg { mandatory, value } => (*mandatory, "cmd-arg", value.as_str()),
                AvPair::MatcherArg { key, value } => (true, key.as_str(), value.as_str()),
                AvPair::Other {
                    mandatory,
                    key,
                    value,
                } => (*mandatory, key.as_str(), value.as_str()),
            };

            let mut final_value = format!("{}{}{}", key, if mandatory { "=" } else { "*" }, value);
            if config_service_args_read.matcher_args.contains_key(key) {
                if config_service_args_read.matcher_args[key] == value {
                    tracing::debug!("request avpair mapped to config matcher arg, key: {}, value: {} | PASS_ADD", key, value);
                    results
                        .authz_results
                        .push((AuthorizationStatus::AuthPassAdd, String::new()));
                } else {
                    tracing::debug!(
                        "request avpair mapped to config matcher arg, key: {}, value: {} | FAIL",
                        key,
                        value
                    );
                    results
                        .authz_results
                        .push((AuthorizationStatus::AuthStatusFail, String::new()));
                    return results;
                }
                processed_avpairs.insert(key.to_string(), final_value.to_string());
            } else if config_service_args_read.mandatory_args.contains_key(key) {
                if config_service_args_read.mandatory_args[key]
                    .allowed_values
                    .contains(value)
                {
                    tracing::debug!("request avpair mapped to config mandatory arg, key: {}, value: {} | PASS_ADD", key, value);
                    results
                        .authz_results
                        .push((AuthorizationStatus::AuthPassAdd, String::new()));
                } else if mandatory {
                    tracing::debug!("mandatory request avpair mapped to config mandatory arg, key: {}, value: {} | FAIL", key, value);
                    results
                        .authz_results
                        .push((AuthorizationStatus::AuthStatusFail, String::new()));
                    return results;
                } else {
                    tracing::debug!("optional request avpair mapped to config mandatory arg, key: {}, value: {} | FAIL", key, value);
                    final_value = format!(
                        "{}={}",
                        key, config_service_args_read.mandatory_args[key].default_value
                    );
                    results.authz_results.push((
                        AuthorizationStatus::AuthPassRepl,
                        format!("service={}", requested_service),
                    ));
                    for (_avpair_key, avpair_value) in processed_avpairs.iter() {
                        results
                            .authz_results
                            .push((AuthorizationStatus::AuthPassRepl, avpair_value.to_string()));
                    }
                    results
                        .authz_results
                        .push((AuthorizationStatus::AuthPassRepl, final_value.to_string()));
                }
                processed_avpairs.insert(key.to_string(), final_value.to_string());
            } else if config_service_args_read.optional_args.contains_key(key) {
                if config_service_args_read.optional_args[key]
                    .allowed_values
                    .contains(value)
                {
                    tracing::debug!("request avpair mapped to config optional arg, value found in allow list, key: {}, value: {} | PASS_ADD", key, value);
                    results
                        .authz_results
                        .push((AuthorizationStatus::AuthPassAdd, String::new()));
                } else if mandatory {
                    tracing::debug!("mandatory request avpair mapped to config optional arg, value not found in allow list, key: {}, value: {} | PASS_ADD", key, value);
                    results
                        .authz_results
                        .push((AuthorizationStatus::AuthPassAdd, String::new()));
                } else {
                    tracing::debug!("optional request avpair mapped to config optional arg, value not found in allow list, key: {}, value: {} | PASS_REPL", key, value);
                    final_value = format!(
                        "{}*{}",
                        key, config_service_args_read.optional_args[key].default_value
                    );
                    results.authz_results.push((
                        AuthorizationStatus::AuthPassRepl,
                        format!("service={}", requested_service),
                    ));
                    for (_avpair_key, avpair_value) in processed_avpairs.iter() {
                        results
                            .authz_results
                            .push((AuthorizationStatus::AuthPassRepl, avpair_value.to_string()));
                    }
                    results
                        .authz_results
                        .push((AuthorizationStatus::AuthPassRepl, final_value.to_string()));
                }
                processed_avpairs.insert(key.to_string(), final_value.to_string());
            } else if mandatory {
                tracing::debug!(
                    "mandatory request avpair not mapped to any config arg, key: {}, value: {}",
                    key,
                    value
                );
                processed_avpairs.insert(key.to_string(), final_value.to_string());
            } else {
                tracing::debug!(
                    "optional request avpair not mapped to any config arg, key: {}, value: {}",
                    key,
                    value
                );
            }
        }

        for request_avpair in request_avpairs {
            tracing::debug!(?request_avpair);
            if let AvPair::Other {
                mandatory,
                key,
                value,
            } = request_avpair
            {
                if processed_avpairs.contains_key(key) {
                    continue;
                }
                if *mandatory {
                    tracing::debug!("mandatory request avpair not mapped to any config arg, key: {}, value: {} | FAIL", key, value);
                    results
                        .authz_results
                        .push((AuthorizationStatus::AuthStatusFail, String::new()));
                    return results;
                } else {
                    tracing::debug!("optional request avpair not mapped to any config arg, key: {}, value: {} | REPL", key, value);
                    results.authz_results.push((
                        AuthorizationStatus::AuthPassRepl,
                        format!("service={}", requested_service),
                    ));
                    for (_avpair_key, avpair_value) in processed_avpairs.iter() {
                        results
                            .authz_results
                            .push((AuthorizationStatus::AuthPassRepl, avpair_value.to_string()));
                    }
                }
            }
        }

        tracing::debug!(?processed_avpairs);

        for (mandatory_config_arg_key, mandatory_config_arg_values) in
            config_service_args_read.mandatory_args.iter()
        {
            if processed_avpairs.contains_key(mandatory_config_arg_key) {
                tracing::debug!(
                    "mandtory config arg {} already processed from request",
                    mandatory_config_arg_key
                );
            } else if !request_uses_cmd_authz {
                let new_value = format!(
                    "{}={}",
                    mandatory_config_arg_key, mandatory_config_arg_values.default_value
                );
                tracing::debug!(
                    "mandatory config arg {} not found in request, appending '{}' | PASS_ADD",
                    mandatory_config_arg_key,
                    new_value
                );
                results
                    .authz_results
                    .push((AuthorizationStatus::AuthPassAdd, new_value));
            } else {
                tracing::debug!("mandatory config arg {} not found in request but using cmd authz so not appending anything", mandatory_config_arg_key);
            }
        }
    }

    results
}

async fn authorize_cmd(
    shared_state: Arc<RwLock<State>>,
    principal: &(dyn Principal + Sync),
    request_avpairs: &[AvPair],
) -> IntermediateAuthZResults {
    tracing::debug!(?request_avpairs);

    let mut results = IntermediateAuthZResults {
        authz_results: vec![],
        acl_results: vec![],
    };

    let packet_cmd_args_joined = request_avpairs
        .iter()
        .filter_map(|avpair| match avpair {
            AvPair::CmdArg {
                mandatory: _,
                value,
            } => Some(value),
            _ => None,
        })
        .join(" ");
    tracing::debug!(?packet_cmd_args_joined);

    let cmds = match principal.cmds() {
        Some(c) => c,
        None => return results,
    };
    for cmd in cmds {
        for pattern in &cmd.list {
            lazy_static! {
                static ref RE_CMD_ARG_PATTERN: Regex =
                    Regex::new(r#"(permit|deny)\s*(.*)"#).unwrap();
            }
            if let Some(captures) = RE_CMD_ARG_PATTERN.captures(pattern) {
                let cmd_pattern_action = &captures[1];
                let cmd_pattern_regex = captures[2].trim_matches('"');
                tracing::debug!(?cmd_pattern_action, ?cmd_pattern_regex);

                let regex_compiled = shared_state
                    .write()
                    .await
                    .regexes
                    .entry(cmd_pattern_regex.to_string())
                    .or_insert_with(|| {
                        Arc::new(
                            Regex::new(cmd_pattern_regex)
                                .unwrap_or_else(|_| Regex::new("$.").unwrap()),
                        )
                    })
                    .clone();
                if cmd_pattern_action == "permit"
                    && regex_compiled.is_match(&packet_cmd_args_joined)
                {
                    results
                        .authz_results
                        .push((AuthorizationStatus::AuthPassAdd, String::new()));
                }
            }
        }
    }
    results
}

async fn authorize_exec(
    _shared_state: Arc<RwLock<State>>,
    principal: &(dyn Principal + Sync),
    request_avpairs: &[AvPair],
) -> IntermediateAuthZResults {
    tracing::debug!(?request_avpairs);

    let mut results = IntermediateAuthZResults {
        authz_results: vec![],
        acl_results: vec![],
    };
    let services = match principal.services() {
        Some(s) => s,
        None => return results,
    };
    for service in services {
        if !normalized_match(&service.name, "shell") {
            continue;
        }
        let service_args = match &service.args {
            Some(a) => a,
            None => continue,
        };
        for arg in service_args {
            results
                .authz_results
                .push((AuthorizationStatus::AuthPassAdd, arg.to_string()));
        }
    }
    results
}

async fn verify_authorization_against_principal(
    shared_state: Arc<RwLock<State>>,
    principal: &(dyn Principal + Sync),
    client_address: &SocketAddr,
    requested_service: &str,
    request_avpairs: &[AvPair],
) -> IntermediateAuthZResults {
    let request_uses_cmd_authz = is_cmd_authz(request_avpairs).await;

    tracing::debug!(name = ?principal.name());
    tracing::debug!(?client_address);
    tracing::debug!(?requested_service);
    tracing::debug!(?request_avpairs);
    tracing::debug!(?request_uses_cmd_authz);

    let mut results = if normalized_match(requested_service, "shell") {
        if request_uses_cmd_authz {
            let span = tracing::span!(tracing::Level::DEBUG, "authorize_cmd", principal = ?principal.name());
            authorize_cmd(shared_state.clone(), principal, request_avpairs)
                .instrument(span)
                .await
        } else {
            let span = tracing::span!(tracing::Level::DEBUG, "authorize_exec", principal = ?principal.name());
            authorize_exec(shared_state.clone(), principal, request_avpairs)
                .instrument(span)
                .await
        }
    } else {
        IntermediateAuthZResults {
            authz_results: vec![],
            acl_results: vec![],
        }
    };

    let span =
        tracing::span!(tracing::Level::DEBUG, "authorize_svc", principal = ?principal.name());
    results.authz_results.extend_from_slice(
        &authorize_svc(
            shared_state.clone(),
            requested_service,
            request_uses_cmd_authz,
            principal,
            request_avpairs,
        )
        .instrument(span)
        .await
        .authz_results,
    );
    results
}

async fn is_cmd_authz(request_avpairs: &[AvPair]) -> bool {
    for avpair in request_avpairs {
        if let AvPair::Cmd {
            mandatory: _,
            value,
        } = avpair
        {
            return !value.is_empty();
        }
    }

    false
}

async fn find_service_requested_for_authz(request_avpairs: &[AvPair]) -> Option<String> {
    for avpair in request_avpairs {
        match avpair {
            AvPair::Service {
                mandatory: _,
                value,
            } => return Some(value.to_string()),
            _ => continue,
        }
    }
    None
}

pub async fn verify_authorization(
    shared_state: Arc<RwLock<State>>,
    user: &User,
    client_address: &SocketAddr,
    rem_address: &[u8],
    request_args: &[Vec<u8>],
) -> (AuthorizationStatus, Vec<String>) {
    let request_avpairs: Vec<AvPair> = request_args
        .iter()
        .map(|arg| String::from_utf8_lossy(arg))
        .filter_map(|arg| parse_avpair(&arg))
        .collect();

    let requested_service = match find_service_requested_for_authz(&request_avpairs).await {
        Some(s) => s,
        None => {
            tracing::debug!("no service found in request args");
            return (AuthorizationStatus::AuthStatusFail, vec![]);
        }
    };

    tracing::debug!(rem_address=?String::from_utf8_lossy(rem_address));
    tracing::debug!(user=?user.name);
    tracing::debug!(?requested_service);

    let span = tracing::span!(tracing::Level::DEBUG, "verify_author", user = ?user.name);
    let intermediate_results = verify_authorization_against_principal(
        shared_state.clone(),
        user,
        client_address,
        &requested_service,
        &request_avpairs,
    )
    .instrument(span)
    .await;

    let mut authz_results = intermediate_results.authz_results;
    let mut acl_results = intermediate_results.acl_results;

    let empty_vec: Vec<String> = vec![];
    let mut groups_pending = user.member.as_ref().unwrap_or(&empty_vec).clone();
    let mut groups_processed = vec![];

    tracing::debug!(?groups_pending);

    while let Some(next_group) = groups_pending.pop() {
        tracing::debug!(?groups_pending);
        tracing::debug!(?groups_processed);
        tracing::debug!(?authz_results);
        tracing::debug!(?acl_results);
        tracing::debug!(?next_group);
        tracing::debug!("processing group {}", next_group);

        let group = match shared_state.read().await.groups.get(&next_group) {
            Some(g) => g.clone(),
            None => {
                tracing::debug!("group {} not found in config", next_group);
                continue;
            }
        };

        let span = tracing::span!(tracing::Level::DEBUG, "verify_author", group = ?group.name());
        let mut intermediate_results = verify_authorization_against_principal(
            shared_state.clone(),
            &*group,
            client_address,
            &requested_service,
            &request_avpairs,
        )
        .instrument(span)
        .await;

        authz_results.append(&mut intermediate_results.authz_results);
        acl_results.append(&mut intermediate_results.acl_results);

        groups_processed.push(group.name.clone());

        for next_group in group.member.as_ref().unwrap_or(&empty_vec).clone() {
            if !groups_processed.contains(&next_group) {
                groups_pending.push(next_group.to_string());
            }
        }
    }

    tracing::debug!(?authz_results);

    let authz_error = (
        AuthorizationStatus::AuthStatusError,
        "authz_error_no_results_found".to_string(),
    );
    let authz_status = authz_results
        .iter()
        .max_by(|first, second| ((*first).0 as u8).cmp(&(second.0 as u8)))
        .unwrap_or(&authz_error)
        .0;
    let authz_results: Vec<String> = authz_results
        .into_iter()
        .map(|result| result.1)
        .filter(|result| !result.is_empty())
        .unique()
        .collect();

    tracing::debug!(?acl_results);

    if let Some(result) = acl_results
        .into_iter()
        .find(|result| result.0 as u8 == AclResult::Reject as u8)
    {
        tracing::debug!("acl rejected by {:?}", result);
        return (AuthorizationStatus::AuthStatusFail, vec![]);
    }

    match authz_status {
        AuthorizationStatus::AuthPassAdd | AuthorizationStatus::AuthPassRepl => {
            (authz_status, authz_results)
        }
        _ => (authz_status, vec![]),
    }
}

#[allow(dead_code)]
pub async fn verify_acl(
    shared_state: Arc<RwLock<State>>,
    acl: &str,
    client_address: &SocketAddr,
) -> (AclResult, String) {
    let client_ip = client_address.ip().to_string();
    let acl = {
        match shared_state.read().await.acls.get(acl) {
            Some(acl) => acl.clone(),
            None => {
                tracing::debug!("acl {} not found in config", acl);
                return (AclResult::Reject, "acl_not_found".to_string());
            }
        }
    };
    for acl_expr in &(acl.list) {
        let acl_expr_split: Vec<&str> = acl_expr.split('=').collect();
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
        if !acl_regex_compiled.is_match(&client_ip) {
            continue;
        }
        match acl_action {
            "permit" => return (AclResult::Pass, acl_expr.to_string()),
            "deny" => return (AclResult::Reject, acl_expr.to_string()),
            _ => continue,
        }
    }
    (AclResult::Reject, "acl_not_applicable".to_string())
}

pub async fn user_needs_forwarding(
    shared_state: Arc<RwLock<State>>,
    username: &str,
) -> Result<bool, Report> {
    let user = match shared_state.read().await.users.get(username) {
        Some(u) => u.clone(),
        None => {
            tracing::debug!("user {} not found in config", username);
            return Ok(false);
        }
    };

    // TODO: Refactor to avoid the need for dummy SocketAddr
    let (authz_status, _) = verify_authorization(
        shared_state.clone(),
        &user,
        &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        &[],
        &[],
    )
    .await;

    Ok(authz_status == AuthorizationStatus::AuthForwardUpstream)
}

pub async fn verify_user_credentials(
    shared_state: Arc<RwLock<State>>,
    username: &str,
    password: &str,
) -> Result<bool, Report> {
    let user = match shared_state.read().await.users.get(username) {
        Some(u) => u.clone(),
        None => {
            tracing::debug!("user {} not found in config", username);
            return Ok(false);
        }
    };

    match &user.credentials {
        Credentials::Ascii(hash) => {
            tracing::debug!(
                "verifying password for {} against the hash specified in config",
                username
            );
            if tacrust::hash::verify_hash(password.as_bytes(), hash).unwrap_or(false) {
                return Ok(true);
            }
        }
        Credentials::Pam => {
            let pam_service = shared_state.read().await.pam_service.clone();
            tracing::debug!(
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

pub async fn process_proxy_request(
    shared_state: Arc<RwLock<State>>,
    client_addr: &SocketAddr,
    request_bytes: &[u8],
) -> Result<Packet, Report> {
    tracing::debug!("forwarding requested for the tacacs packet");
    let upstream_tacacs_server = shared_state.read().await.upstream_tacacs_server.clone();
    if upstream_tacacs_server.is_empty() {
        return Err(Report::msg(
            "upstream tacacs server not specified in config",
        ));
    }
    tracing::debug!(
        "forwarding {} bytes to {}",
        request_bytes.len(),
        upstream_tacacs_server
    );

    let mut upstream_connection = match shared_state
        .write()
        .await
        .upstream_tacacs_connections
        .get(client_addr)
    {
        Some(c) => c
            .try_clone()
            .expect("could not clone upstream tcp connection"),
        None => {
            let parsed_addr = upstream_tacacs_server.parse::<SocketAddr>()?;
            let connection_result = tokio::task::spawn_blocking(move || {
                TcpStream::connect_timeout(&parsed_addr, Duration::from_secs(1))
            })
            .await?;
            match connection_result {
                Ok(c) => c,
                Err(_) => return Err(Report::msg("error connecting to upstream server")),
            }
        }
    };

    if !shared_state
        .read()
        .await
        .upstream_tacacs_connections
        .contains_key(client_addr)
    {
        shared_state
            .write()
            .await
            .upstream_tacacs_connections
            .insert(
                *client_addr,
                upstream_connection
                    .try_clone()
                    .expect("could not close upstream tcp connection"),
            );
    }

    let request_vec = request_bytes.to_vec();
    let response = tokio::task::spawn_blocking(move || {
        upstream_connection.write_all(&request_vec).unwrap();
        upstream_connection.flush().unwrap();
        tracing::debug!("forwarded {} bytes to upstream server", &request_vec.len());
        let mut final_buffer = Vec::new();
        let mut wire_buffer: [u8; 4096] = [0; 4096];
        for _ in 0..5
        /* otherwise this can loop endlessly */
        {
            let bytes_read = upstream_connection.read(&mut wire_buffer).unwrap_or(0);
            if bytes_read > 0 {
                final_buffer.extend_from_slice(&wire_buffer[..bytes_read]);
                break;
            }
        }
        final_buffer
    })
    .await?;
    tracing::debug!("read {} bytes from upstream server", &response.len());

    let (_request_key, request_packet) = decrypt_request(&response, shared_state.clone()).await?;
    Ok(request_packet)
}
