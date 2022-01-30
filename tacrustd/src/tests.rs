use crate::start_server;
use lazy_static::lazy_static;
use rand::Rng;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing_subscriber::EnvFilter;

lazy_static! {
    static ref MUTEX: Mutex<()> = setup();
}

fn setup() -> Mutex<()> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info")
    }
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    color_eyre::install().unwrap();
    Mutex::new(())
}

async fn test_server<T>(port: u16, timeout: Duration, test: T) -> ()
where
    T: FnOnce() -> (),
{
    let _lock = MUTEX.lock().await;
    std::env::set_var("TACRUST_LISTEN_ADDRESS", format!("127.0.0.1:{}", port));
    let (join_handle, cancel_tx) = start_server().await.unwrap();
    tokio::spawn(async move {
        sleep(timeout).await;
        cancel_tx.send(()).unwrap();
    });
    test();
    join_handle.await.unwrap_or_default();
}

#[tokio::test]
async fn server_startup_and_shutdown() {
    let port: u16 = rand::thread_rng().gen();
    test_server(port, Duration::from_secs(5), || {
        tracing::info!("server is running on port {}", port);
    })
    .await;
}

#[tokio::test]
async fn test_java_author() {
    let port: u16 = rand::thread_rng().gen();
    let packet = include_bytes!("../packets/java-author-1.tacacs");
    test_server(port, Duration::from_secs(5), || {
        tracing::info!("server is running on port {}", port);
    })
    .await;
}
