use crate::start_server;
use base64::display::Base64Display;
use lazy_static::lazy_static;
use rand::Rng;
use serial_test::serial;
use std::io::prelude::*;
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;
use tacrust::{AuthenticationStatus, AuthorizationStatus, Body};
use tokio::runtime::Runtime;
use tracing_subscriber::EnvFilter;

lazy_static! {
    static ref SETUP_COMPLETED: bool = setup();
    static ref RUNTIME: Runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(4)
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
}

fn setup() -> bool {
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
    true
}

fn test_server<T>(port: u16, timeout: Duration, test: T) -> ()
where
    T: FnOnce() -> (),
{
    assert!(*SETUP_COMPLETED);
    std::env::set_var("TACRUST_LISTEN_ADDRESS", format!("127.0.0.1:{}", port));
    let (join_handle, cancel_tx) = RUNTIME.block_on(start_server()).unwrap();
    thread::spawn(move || {
        thread::sleep(timeout);
        cancel_tx.send(()).unwrap();
    });
    test();
    RUNTIME.block_on(join_handle).unwrap();
}

fn get_tcp_client_for_tacrust() -> TcpStream {
    let server_address: SocketAddr = std::env::var("TACRUST_LISTEN_ADDRESS")
        .unwrap()
        .parse()
        .unwrap();
    tracing::info!("connecting to server at {}", server_address);
    let stream = TcpStream::connect_timeout(&server_address, Duration::from_secs(1)).unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    stream
}

fn test_authen_packet(packet: &[u8], key: &[u8], expected_status: AuthenticationStatus) {
    let mut client = get_tcp_client_for_tacrust();
    tracing::info!(
        "sending packet: {}",
        Base64Display::with_config(packet, base64::STANDARD)
    );
    client.write(packet).unwrap();
    let mut response = [0; 4096];
    tracing::info!("receiving response");
    let len = client.read(&mut response).unwrap();
    tracing::info!(
        "received response: {}",
        Base64Display::with_config(&response[0..len], base64::STANDARD)
    );
    let (_, parsed_response) = tacrust::parser::parse_packet(&response[0..len], key).unwrap();
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

fn test_author_packet(packet: &[u8], key: &[u8], expected_status: AuthorizationStatus) {
    let mut client = get_tcp_client_for_tacrust();
    tracing::info!(
        "sending packet: {}",
        Base64Display::with_config(packet, base64::STANDARD)
    );
    client.write(packet).unwrap();
    let mut response = [0; 4096];
    tracing::info!("receiving response");
    let len = client.read(&mut response).unwrap();
    tracing::info!(
        "received response: {}",
        Base64Display::with_config(&response[0..len], base64::STANDARD)
    );
    let (_, parsed_response) = tacrust::parser::parse_packet(&response[0..len], key).unwrap();
    tracing::info!("parsed: {:?}", parsed_response);
    assert!(matches!(
        parsed_response.body,
        Body::AuthorizationReply { .. }
    ));
    if let Body::AuthorizationReply {
        status,
        data: _,
        server_msg: _,
        args: _,
    } = parsed_response.body
    {
        assert_eq!(status, expected_status);
    }
}

#[test]
#[serial]
fn test_java_author() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(1), || {
        let packet = include_bytes!("../packets/java-author-1.tacacs");
        test_author_packet(packet, key, AuthorizationStatus::AuthStatusFail);
    });
}

#[test]
#[serial]
fn test_golang_authen() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(1), || {
        {
            let packet = include_bytes!("../packets/golang-authen-1.tacacs");
            test_authen_packet(packet, key, AuthenticationStatus::GetPass);
        }

        {
            let packet = include_bytes!("../packets/golang-authen-2.tacacs");
            test_authen_packet(packet, key, AuthenticationStatus::Pass);
        }
    });
}

#[test]
#[serial]
fn test_cisco_nexus_9000() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(5), || {
        let packet =
            include_bytes!("../packets/cisco-nexus-9000/aditya/01.a-authen-start-bad.tacacs");
        test_authen_packet(packet, key, AuthenticationStatus::GetPass);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/aditya/01.b-authen-cont-bad.tacacs");
        test_authen_packet(packet, key, AuthenticationStatus::Fail);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/aditya/02.a-authen-start-good.tacacs");
        test_authen_packet(packet, key, AuthenticationStatus::GetPass);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/aditya/02.b-authen-cont-good.tacacs");
        test_authen_packet(packet, key, AuthenticationStatus::Pass);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/aditya/03.a-author-shell-good.tacacs");
        test_author_packet(packet, key, AuthorizationStatus::AuthPassAdd);

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/aditya/03.b-author-shell-show-run-good.tacacs"
        );
        test_author_packet(packet, key, AuthorizationStatus::AuthPassAdd);

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/aditya/04-author-shell-show-version-good.tacacs"
        );
        test_author_packet(packet, key, AuthorizationStatus::AuthPassAdd);

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/aditya/05-author-shell-show-interface-bad.tacacs"
        );
        test_author_packet(packet, key, AuthorizationStatus::AuthStatusFail);

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/aditya/06-author-shell-show-clock-bad.tacacs"
        );
        // Todo: This actually fails in Shrubbery daemon which stops recursing through parent
        // groups when it hits a match. Need to decide whether we should do the same
        test_author_packet(packet, key, AuthorizationStatus::AuthPassAdd);

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/aditya/07-author-shell-dir-root-bad.tacacs"
        );
        test_author_packet(packet, key, AuthorizationStatus::AuthStatusFail);

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/aditya/08-author-shell-dir-home-good.tacacs"
        );
        test_author_packet(packet, key, AuthorizationStatus::AuthPassAdd);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/kamran/01.a-authen-start-good.tacacs");
        test_authen_packet(packet, key, AuthenticationStatus::GetPass);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/kamran/01.b-authen-cont-good.tacacs");
        test_authen_packet(packet, key, AuthenticationStatus::Pass);

        let packet =
            include_bytes!("../packets/cisco-nexus-9000/kamran/02.a-author-shell-good.tacacs");
        test_author_packet(packet, key, AuthorizationStatus::AuthPassAdd);

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/kamran/02.b-author-shell-show-run-bad.tacacs"
        );
        test_author_packet(packet, key, AuthorizationStatus::AuthStatusFail);

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/kamran/03-author-shell-show-version-bad.tacacs"
        );
        test_author_packet(packet, key, AuthorizationStatus::AuthStatusFail);

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/kamran/04-author-shell-show-interface-bad.tacacs"
        );
        test_author_packet(packet, key, AuthorizationStatus::AuthStatusFail);

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/kamran/05-author-shell-show-clock-good.tacacs"
        );
        test_author_packet(packet, key, AuthorizationStatus::AuthPassAdd);

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/kamran/06-author-shell-dir-root-bad.tacacs"
        );
        test_author_packet(packet, key, AuthorizationStatus::AuthStatusFail);

        let packet = include_bytes!(
            "../packets/cisco-nexus-9000/kamran/07-author-shell-dir-home-good.tacacs"
        );
        test_author_packet(packet, key, AuthorizationStatus::AuthPassAdd);
    });
}

#[test]
#[serial]
fn test_f5_lb() {
    let key = b"tackey";
    let port: u16 = rand::thread_rng().gen_range(10000..30000);
    test_server(port, Duration::from_secs(1), || {
        let packet = include_bytes!("../packets/f5-lb/01-authen-good.tacacs");
        test_authen_packet(packet, key, AuthenticationStatus::Pass);
    });
}
