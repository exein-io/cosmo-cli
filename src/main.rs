use std::path::{Path, PathBuf};

use cosmo_cli::{api::HttpApiServer, cli};
use lazy_static::lazy_static;
use log::LevelFilter;

/// Setup the logger given the `LevelFilter`.
fn setup_logger(filter: LevelFilter) {
    let mut logger_builder = env_logger::builder();
    logger_builder.format_module_path(false);
    logger_builder.filter_level(filter);
    logger_builder.init();
}

/// Get the token path depending on the operating system.
/// Uses crate `dirs` to find OS cache directory.
fn token_cache_path() -> &'static Path {
    const TOKEN_CACHE_DIR: &str = "cosmo-cli";
    const TOKEN_CACHE_FILE: &str = "cosmo-cli-token";

    lazy_static! {
        static ref TOKEN_CACHE_PATH: PathBuf = dirs::cache_dir()
            .map(|home_dir| home_dir.join(TOKEN_CACHE_DIR).join(TOKEN_CACHE_FILE))
            .expect("Error constructing the path for the cache of the token");
    }

    &TOKEN_CACHE_PATH
}

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

    // Authentication // Skip auth if logout command
    // if let cli::Command::Logout = cli_opts.command {
    //     if let Err(e) = std::fs::remove_file(token_cache_path()) {
    //         if let std::io::ErrorKind::NotFound = e.kind() {
    //             cli::report_error(&e.into());
    //             std::process::exit(1)
    //         }
    //     }
    //     cli::print_cmd_output(&"Logout successfully", cli_opts.output_mode);
    //     std::process::exit(0)
    // }

    let mut api_server = HttpApiServer::new(cli_opts.api_server, cli_opts.api_key).await;

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
