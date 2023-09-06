use std::{
    fs,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
};

use anyhow::Context;
use ini::Ini;
use lazy_static::lazy_static;
use log::LevelFilter;

use cosmo_cli::{
    api::HttpApiServer,
    cli::{self, Command},
};

const INI_CONFIG_SECTION: &str = "default";
const API_KEY_ENTRY: &str = "api_key";

#[tokio::main]
async fn main() {
    let cli_opts = cli::parse_from(&mut std::env::args_os()).unwrap_or_else(|e| e.exit());

    setup_logger(cli_opts.log_level_filter);

    // TODO: check if needed
    openssl_probe::init_ssl_cert_env_vars();

    human_panic::setup_panic!(Metadata {
        name: env!("CARGO_PKG_NAME").into(),
        version: cosmo_cli::version().into(),
        authors: "Exein <support@exein.io>".into(),
        homepage: "https://cosmo.exein.io".into(),
    });

    // Handle setup command before the others
    if let Command::Setup = cli_opts.command {
        if let Err(e) = setup_config() {
            let e = e.context("error initializing the configuration");
            cli::report_error(&e);
            std::process::exit(1)
        }

        cli::print_cmd_output(&"Configuration complete", cli_opts.output_mode);
        std::process::exit(0)
    }

    // Choose api key in the following order
    //
    // 1. check if it's passed via command line argument
    // 2. try read from configuration file
    let api_key = match cli_opts.api_key {
        Some(ak) => ak,
        None => match try_api_key_from_config_file() {
            Ok(ak) => ak,
            Err(e) => {
                let e = e.context("error reading api key from config file");
                cli::report_error(&e);
                println!("\nRun the 'setup' command to initialize the configuration");
                std::process::exit(1)
            }
        },
    };

    let mut api_server = HttpApiServer::new(cli_opts.api_server, api_key).await;

    // Run Command
    match cosmo_cli::run_cmd(cli_opts.command, &mut api_server).await {
        Ok(cmd_output) => {
            log::debug!("Printing in {:?} mode", cli_opts.output_mode);
            cli::print_cmd_output(&*cmd_output, cli_opts.output_mode)
        }
        Err(e) => {
            cli::report_error(&e);
            std::process::exit(1)
        }
    }
}

/// Setup the logger given the `LevelFilter`.
fn setup_logger(filter: LevelFilter) {
    env_logger::builder()
        .format_timestamp(None)
        .format_target(false)
        .format_module_path(false)
        .filter_level(filter)
        .init()
}

fn setup_config() -> Result<(), anyhow::Error> {
    // Read api key from stdin
    // TODO: hadle unwraps
    let stdin = io::stdin();
    let mut iterator = stdin.lock().lines();
    print!("Insert your Api Key: ");
    io::stdout().flush()?;
    let api_key = iterator.next().unwrap().unwrap();

    // Write config
    let config_file_path = config_file_path();
    fs::create_dir_all(
        config_file_path
            .parent()
            .expect("config file should have a parent"),
    )?;
    let mut conf = Ini::new();
    conf.with_section(Some(INI_CONFIG_SECTION))
        .set(API_KEY_ENTRY, api_key);
    conf.write_to_file(config_file_path)?;

    Ok(())
}

/// Get the token path depending on the operating system.
/// Uses crate `dirs` to find OS cache directory.
fn config_file_path() -> &'static Path {
    const TOKEN_CACHE_DIR: &str = "cosmo-cli";
    const TOKEN_CACHE_FILE: &str = "config";

    lazy_static! {
        static ref TOKEN_CACHE_PATH: PathBuf = dirs::config_dir()
            .map(|home_dir| home_dir.join(TOKEN_CACHE_DIR).join(TOKEN_CACHE_FILE))
            .expect("Error constructing the path for the cache of the token");
    }

    &TOKEN_CACHE_PATH
}

fn try_api_key_from_config_file() -> Result<String, anyhow::Error> {
    let i = Ini::load_from_file(config_file_path())?;

    let default_section = i
        .section(Some(INI_CONFIG_SECTION))
        .context("no default section found")?;

    let api_key = default_section
        .get(API_KEY_ENTRY)
        .context("no api key entry found")?;

    Ok(api_key.to_string())
}
