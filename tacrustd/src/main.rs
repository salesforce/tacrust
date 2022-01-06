use clap::App;
use color_eyre::Report;
use tracing::info;
use tracing_subscriber::EnvFilter;
use twelf::{config, Layer};

/// Simple program to greet a person
#[config]
struct Conf {
    /// Name of the person to greet
    name: String,

    /// Number of times to greet
    count: u8,
}

#[tokio::main]
async fn main() -> Result<(), Report> {
    let app = clap::App::new("tacrust").args(&Conf::clap_args());
    let config = setup(&app)?;

    if config.count > 100 {
        panic!("Are you crazy?");
    }

    for _ in 0..config.count {
        info!("Hello {}!", config.name)
    }

    Ok(())
}

fn setup(app: &App) -> Result<Conf, Report> {
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

    let config = Conf::with_layers(&[
        Layer::Toml("tacrust.toml".into()),
        Layer::Env(Some("TACRUST_".to_string())),
        Layer::Clap(app.get_matches().clone()),
    ])
    .unwrap();

    Ok(config)
}
