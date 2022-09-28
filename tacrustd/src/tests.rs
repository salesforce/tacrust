use crate::start_server;
use base64::display::Base64Display;
use lazy_static::lazy_static;
use rand::Rng;
use std::collections::HashMap;
use std::io::prelude::*;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Once, RwLock};
use std::thread;
use std::time::Duration;
use tacrust::{AuthenticationStatus, AuthorizationStatus, Body};
use tokio::runtime::Runtime;
use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();
lazy_static! {
    static ref CONNECTIONS: Arc<RwLock<HashMap<SocketAddr, TcpStream>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

fn setup() {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info")
    }
    if std::env::var("RUST_BACKTRACE").is_err() {
        std::env::set_var("RUST_BACKTRACE", "1")
    }
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    color_eyre::install().unwrap();
}

fn test_server<T>(port: u16, timeout: Duration, test: T) -> ()
where
    T: FnOnce(&str) -> (),
{
    INIT.call_once(|| {
        setup();
    });
    let runtime: Runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(4)
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tacrust_server_address = format!("127.0.0.1:{}", port);
    let test_config =
        include_str!("../tacrust.json").replace("0.0.0.0:49", &tacrust_server_address);
    tracing::info!("starting test server at: {}", &tacrust_server_address);
    let running_server = runtime
        .block_on(start_server(Some(test_config.as_bytes())))
        .unwrap();
    thread::spawn(move || {
        thread::sleep(timeout);
        running_server.cancel_channel.send(()).unwrap();
    });
    test(&tacrust_server_address);
    runtime.block_on(running_server.join_handle).unwrap();
}

fn get_tacacs_response(
    server_address: &str,
    packet: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let server_address: SocketAddr = server_address.parse()?;
    tracing::info!("connecting to server at {}", server_address);
    let mut conn_map = CONNECTIONS.write().unwrap();
    let stream = conn_map.entry(server_address.clone()).or_insert_with(|| {
        let stream = TcpStream::connect_timeout(&server_address, Duration::from_secs(5)).unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
    });
    tracing::info!(
        "sending packet: {}",
        Base64Display::with_config(packet, base64::STANDARD)
    );
    let chunk_size: usize = rand::thread_rng().gen_range(2..6);
    let chunks: Vec<&[u8]> = packet.chunks(chunk_size).collect();
    for chunk in chunks {
        stream.write(chunk)?;
        stream.flush()?;
    }
    let mut response = [0; 4096];
    tracing::info!("receiving response");
    let len = stream.read(&mut response)?;
    Ok(response[..len].to_vec())
}

fn test_authen_packet(
    server_address: &str,
    packet: &[u8],
    key: &[u8],
    expected_status: AuthenticationStatus,
) {
    let mut response = vec![];
    for _ in 0..10 {
        if let Ok(r) = get_tacacs_response(server_address, packet) {
            if r.len() > 4 {
                response.extend_from_slice(&r);
                break;
            }
        } else {
            thread::sleep(Duration::from_millis(100));
        }
    }
    tracing::info!(
        "received response: {}",
        Base64Display::with_config(&response, base64::STANDARD)
    );
    let (_, parsed_response) = tacrust::parser::parse_packet(&response, key).unwrap();
    tracing::info!("parsed: {:?}", parsed_response);
    assert!(matches!(
        parsed_response.body,
        Body::AuthenticationReply { .. }
    ));
    if let Body::AuthenticationReply {
        status,
        flags: _,
        server_msg: _,
        data: _,
    } = parsed_response.body
    {
        assert_eq!(status, expected_status);
    }
}

fn test_author_packet(
    server_address: &str,
    packet: &[u8],
    key: &[u8],
    expected_status: AuthorizationStatus,
    expected_avpairs: Vec<Vec<u8>>,
) {
    let mut response = vec![];
    for _ in 0..10 {
        if let Ok(r) = get_tacacs_response(server_address, packet) {
            if r.len() > 4 {
                response.extend_from_slice(&r);
                break;
            }
        } else {
            thread::sleep(Duration::from_millis(100));
        }
    }
    tracing::info!(
        "received response: {}",
        Base64Display::with_config(&response, base64::STANDARD)
    );
    let (_, parsed_response) = tacrust::parser::parse_packet(&response, key).unwrap();
    tracing::info!("parsed: {:?}", parsed_response);
    assert!(matches!(
        parsed_response.body,
        Body::AuthorizationReply { .. }
    ));
    if let Body::AuthorizationReply {
        status,
        data: _,
        server_msg: _,
        args,
    } = parsed_response.body
    {
        assert_eq!(status, expected_status);
        assert_eq!(args, expected_avpairs);
    }
}

#[test]
fn test_java_author() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet = include_bytes!("../packets/java-author-1.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthStatusFail,
            vec![],
        );
    });
}

#[test]
fn test_cisco_nexus_9000() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet =
            include_bytes!("../packets/cisco-nexus-9000/aditya/01.a-authen-start-bad.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::GetPass);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/aditya/01.b-authen-cont-bad.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::Fail);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/aditya/02.a-authen-start-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::GetPass);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/aditya/02.b-authen-cont-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::Pass);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/aditya/03.a-author-shell-good.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"priv-lvl=15".to_vec()],
        );

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/aditya/03.b-author-shell-show-run-good.tacacs"
        );
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![
                b"priv-lvl=15".to_vec(),
                b"cmd-arg=running-config".to_vec(),
                b"cmd-arg=<cr>".to_vec(),
            ],
        );

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/aditya/04-author-shell-show-version-good.tacacs"
        );
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![
                b"priv-lvl=15".to_vec(),
                b"cmd-arg=version".to_vec(),
                b"cmd-arg=<cr>".to_vec(),
            ],
        );

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/aditya/05-author-shell-show-interface-good.tacacs"
        );
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"priv-lvl=15".to_vec()],
        );

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/aditya/06-author-shell-show-clock-bad.tacacs"
        );
        // Todo: This actually fails in Shrubbery daemon which stops recursing through parent
        // groups when it hits a match. Need to decide whether we should do the same
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![
                b"priv-lvl=15".to_vec(),
                b"cmd-arg=clock".to_vec(),
                b"cmd-arg=<cr>".to_vec(),
            ],
        );

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/aditya/07-author-shell-dir-root-good.tacacs"
        );
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"priv-lvl=15".to_vec()],
        );

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/aditya/08-author-shell-dir-home-good.tacacs"
        );
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![
                b"priv-lvl=15".to_vec(),
                b"cmd-arg=bootflash:/home".to_vec(),
                b"cmd-arg=<cr>".to_vec(),
            ],
        );

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/kamran/01.a-authen-start-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::GetPass);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/kamran/01.b-authen-cont-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::Pass);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/kamran/02.a-author-shell-good.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"priv-lvl=15".to_vec()],
        );

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/kamran/02.b-author-shell-show-run-good.tacacs"
        );
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"priv-lvl=15".to_vec()],
        );

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/kamran/03-author-shell-show-version-good.tacacs"
        );
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"priv-lvl=15".to_vec()],
        );

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/kamran/04-author-shell-show-interface-good.tacacs"
        );
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"priv-lvl=15".to_vec()],
        );

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/kamran/05-author-shell-show-clock-good.tacacs"
        );
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![
                b"priv-lvl=15".to_vec(),
                b"cmd-arg=clock".to_vec(),
                b"cmd-arg=<cr>".to_vec(),
            ],
        );

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/kamran/06-author-shell-dir-root-good.tacacs"
        );
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"priv-lvl=15".to_vec()],
        );

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/kamran/07-author-shell-dir-home-good.tacacs"
        );
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![
                b"priv-lvl=15".to_vec(),
                b"cmd-arg=bootflash:/home".to_vec(),
                b"cmd-arg=<cr>".to_vec(),
            ],
        );
    });
}

#[test]
fn test_f5_lb() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet = include_bytes!("../packets/f5-lb/01-authen-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::Pass);

        let packet = include_bytes!("../packets/f5-lb/02-author-good.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"F5-LTM-User-Info-1=admin".to_vec()],
        );
    });
}

#[test]
fn test_juniper_firewall() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet = include_bytes!("../packets/juniper-firewall/01-author-good.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![
                b"allow-commands=\"^.*\"".to_vec(),
                b"allow-configuration=\"^.*\"".to_vec(),
            ],
        );
    });
}

#[test]
fn test_mrv_lx() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet = include_bytes!("../packets/mrv-lx/01.a-authen-start-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::GetPass);

        let packet = include_bytes!("../packets/mrv-lx/01.b-authen-cont-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::Pass);

        let packet = include_bytes!("../packets/mrv-lx/02-author-good.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"priv-lvl=15".to_vec()],
        );
    });
}

#[test]
fn test_ciena_waveserver() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet = include_bytes!("../packets/ciena-waveserver/01.a-authen-start-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::GetPass);

        let packet = include_bytes!("../packets/ciena-waveserver/01.b-authen-cont-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::Pass);

        let packet = include_bytes!("../packets/ciena-waveserver/02.b-author-shell-good.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"priv-lvl=15".to_vec()],
        );

        let packet =
            include_bytes!("../packets/ciena-waveserver/02.a-author-shell-file-ls-good.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"priv-lvl=15".to_vec(), b"cmd-arg=ls".to_vec()],
        );
    });
}

#[test]
fn test_opengear_console() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet = include_bytes!("../packets/opengear-console/01.a-authen-start-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::GetPass);

        let packet = include_bytes!("../packets/opengear-console/01.b-authen-cont-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::Pass);

        let packet = include_bytes!("../packets/opengear-console/02-author-good.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"groupname=admin".to_vec()],
        );
    });
}

#[test]
fn test_fortigate_firewall() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet = include_bytes!("../packets/fortigate-firewall/01.a-authen-start-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::GetPass);

        let packet = include_bytes!("../packets/fortigate-firewall/01.b-authen-cont-good.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::Pass);

        let packet = include_bytes!("../packets/fortigate-firewall/02-author-good.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![
                b"memberof=FGT_admin".to_vec(),
                b"admin_prof=super_admin".to_vec(),
            ],
        );
    });
}

#[test]
fn test_acl_present_but_not_matched() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet = include_bytes!("../packets/johndoe_author_some_service.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthStatusFail,
            vec![],
        );
    });
}

#[test]
fn test_acl_not_present() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet = include_bytes!("../packets/janedoe_author_some_service.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"some_arg=some_value".to_vec()],
        );
    });
}

#[test]
fn test_multiple_group_memberships() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet = include_bytes!("../packets/jackdoe_author_raccess.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![b"groupname=admin".to_vec()],
        );
    });
}

#[test]
fn test_always_permit_authz_flag() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet = include_bytes!("../packets/alexdelarge_author_raccess.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![],
        );

        let packet = include_bytes!("../packets/faramir_author_carwash.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![],
        );

        let packet = include_bytes!("../packets/jacktorrance_author_carwash.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthStatusFail,
            vec![],
        );

        let packet = include_bytes!("../packets/davebowman_author_carwash.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthStatusFail,
            vec![],
        );
    });
}

#[test]
fn test_extra_keys() {
    let key = b"tackey2";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet = include_bytes!("../packets/faramir_author_carwash_tackey2.tacacs");
        test_author_packet(
            server_address,
            packet,
            key,
            AuthorizationStatus::AuthPassAdd,
            vec![],
        );
    });
}

#[test]
fn test_proxy_forwarding_for_user_authen() {
    let key = b"tackey";
    let downstream_port: u16 = rand::thread_rng().gen_range(10000..30000);
    let upstream_port: u16 = rand::thread_rng().gen_range(10000..30000);
    tracing::info!(
        "downstream_port: {}, upstream_port: {}",
        downstream_port,
        upstream_port
    );
    std::env::set_var(
        "TACRUST_UPSTREAM_TACACS_SERVER",
        format!("127.0.0.1:{}", upstream_port),
    );
    test_server(
        downstream_port,
        Duration::from_secs(5),
        |downstream_server_address: &str| {
            std::env::set_var("TACRUST_UPSTREAM_TACACS_SERVER", "");
            test_server(
                upstream_port,
                Duration::from_secs(5),
                |_upstream_server_address: &str| {
                    let packet = include_bytes!("../packets/faramir_authen_start.tacacs");
                    test_authen_packet(
                        downstream_server_address,
                        packet,
                        key,
                        AuthenticationStatus::GetPass,
                    );

                    let packet = include_bytes!("../packets/faramir_authen_cont.tacacs");
                    test_authen_packet(
                        downstream_server_address,
                        packet,
                        key,
                        AuthenticationStatus::Pass,
                    );
                },
            );
        },
    );
}

#[test]
fn test_proxy_forwarding_for_user_author() {
    let key = b"tackey";
    let downstream_port: u16 = rand::thread_rng().gen_range(10000..30000);
    let upstream_port: u16 = rand::thread_rng().gen_range(10000..30000);
    tracing::info!(
        "downstream_port: {}, upstream_port: {}",
        downstream_port,
        upstream_port
    );
    std::env::set_var(
        "TACRUST_UPSTREAM_TACACS_SERVER",
        format!("127.0.0.1:{}", upstream_port),
    );
    test_server(
        downstream_port,
        Duration::from_secs(5),
        |downstream_server_address: &str| {
            std::env::set_var("TACRUST_UPSTREAM_TACACS_SERVER", "");
            test_server(
                upstream_port,
                Duration::from_secs(5),
                |_upstream_server_address: &str| {
                    let packet = include_bytes!("../packets/faramir_author_carwash.tacacs");
                    test_author_packet(
                        downstream_server_address,
                        packet,
                        key,
                        AuthorizationStatus::AuthPassAdd,
                        vec![],
                    );
                },
            );
        },
    );
}

#[test]
fn test_proxy_forwarding_for_group() {
    let key = b"tackey";
    let downstream_port: u16 = rand::thread_rng().gen_range(10000..30000);
    let upstream_port: u16 = rand::thread_rng().gen_range(10000..30000);
    tracing::info!(
        "downstream_port: {}, upstream_port: {}",
        downstream_port,
        upstream_port
    );
    std::env::set_var(
        "TACRUST_UPSTREAM_TACACS_SERVER",
        format!("127.0.0.1:{}", upstream_port),
    );
    test_server(
        downstream_port,
        Duration::from_secs(5),
        |downstream_server_address: &str| {
            std::env::set_var("TACRUST_UPSTREAM_TACACS_SERVER", "");
            test_server(
                upstream_port,
                Duration::from_secs(5),
                |_upstream_server_address: &str| {
                    let packet = include_bytes!("../packets/strider_author_carwash.tacacs");
                    test_author_packet(
                        downstream_server_address,
                        packet,
                        key,
                        AuthorizationStatus::AuthPassAdd,
                        vec![b"vendor=brownbear".to_vec()],
                    );
                },
            );
        },
    );
}

#[test]
fn test_golang_emulate_wda_authen() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), |server_address: &str| {
        let packet =
            include_bytes!("../packets/golang-emulate-wda/golang-authen-start-no-username.tacacs");
        test_authen_packet(server_address, packet, key, AuthenticationStatus::GetUser);

        let packet = include_bytes!(
            "../packets/golang-emulate-wda/golang-authen-cont-username-kamran.tacacs"
        );
        test_authen_packet(server_address, packet, key, AuthenticationStatus::GetPass);

        let packet = include_bytes!(
            "../packets/golang-emulate-wda/golang-authen-cont-password-kamran.tacacs"
        );
        test_authen_packet(server_address, packet, key, AuthenticationStatus::Pass);
    });
}
