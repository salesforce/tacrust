use clap_rs as clap;
use color_eyre::Report;
use std::path::Path;
use tracing::info;
use tracing_subscriber::EnvFilter;
use twelf::{config, Layer};

/// Simple program to greet a person
#[config]
#[derive(Debug)]
struct Conf {
    /// Name of the person to greet
    name: String,

    /// Number of times to greet
    count: u8,
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    let config = setup()?;

    if config.count > 100 {
        panic!("Are you crazy?");
    }

    for _ in 0..config.count {
        info!("Hello {}!", config.name)
    }

    Ok(())
}

fn setup() -> Result<Conf, Report> {
    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }
    color_eyre::install()?;

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info")
    }
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let app = clap::App::new("tacrust").args(&Conf::clap_args());
    let mut layers = vec![];
    for path in &[
        "tacrust.toml",
        "tacrustd/tacrust.toml",
        "/etc/tacrust.toml",
        "/etc/tacrustd/tacrust.toml",
    ] {
        if Path::new(path).exists() {
            layers.push(Layer::Toml(path.into()));
        }
    }
    layers.push(Layer::Env(Some("TACRUST_".to_string())));
    layers.push(Layer::Clap(app.get_matches().clone()));
    let config = Conf::with_layers(&layers).unwrap();

    Ok(config)
}
