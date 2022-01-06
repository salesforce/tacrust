use clap::Parser;
use color_eyre::Report;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Deserialize, Serialize)]
struct Config {
    key: String,
    another: u32,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            key: "default".into(),
            another: 100,
        }
    }
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    /// Name of the person to greet
    #[clap(short, long)]
    name: String,

    /// Number of times to greet
    #[clap(short, long, default_value_t = 1)]
    count: u8,
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    let config = setup()?;
    let args = Args::parse();

    info!("[Config] key={}, another={}", config.key, config.another);

    if args.count > 100 {
        panic!("Are you crazy?");
    }

    for _ in 0..args.count {
        info!("Hello {}!", args.name)
    }

    Ok(())
}

fn setup() -> Result<Config, Report> {
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

    let figment = Figment::from(Serialized::defaults(Config::default()))
        .merge(Toml::file("tacrust.toml"))
        .merge(Env::prefixed("TACRUST_"));
    let config = figment.extract()?;

    Ok(config)
}
