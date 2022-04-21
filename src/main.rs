use std::{
    alloc::System,
    env,
    path::{Path, PathBuf},
};

#[global_allocator]
static GLOBAL: System = System;

use cosmo_cli::{
    api::HttpApiServer,
    cli,
    security::{firebase::Firebase, token_cacher::TokenCacher},
};
use lazy_static::lazy_static;
use log::LevelFilter;

const FIREBASE_API_KEY: &str = "AIzaSyBbu0Q_aIz5g1jxA4f_1WR55sFaUmlnpxY";
const COSMO_API_SERVER: &str = "https://cosmo-api.exein.io:443";

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

    // Uses Firebase behind a token cache layer
    let token_cacher = {
        // Uses firebase api key from environment if present otherwise uses the default one.
        // TIP: Use this environment variable for development
        let firebase_api_key = env::var("COSMO_FIREBASE_API_KEY").unwrap_or_else(|err| {
            const END_MSG: &str = "Using default Firebase API_KEY";
            match err {
                env::VarError::NotPresent => {
                    log::debug!("No custom firebase api key found. {END_MSG}")
                }
                env::VarError::NotUnicode(_) => {
                    log::warn!("Non unicode character found in custom firebase api key. {END_MSG}")
                }
            }
            FIREBASE_API_KEY.into()
        });
        let firebase = Firebase::new(firebase_api_key, true);

        TokenCacher {
            auth_service: firebase,
            token_path: token_cache_path().to_path_buf(),
        }
    };

    // Uses custom server provided in the command line if present
    // otherwise uses the default one
    let mut api_server = {
        let api_server_address = cli_opts
            .api_server
            .unwrap_or_else(|| COSMO_API_SERVER.into());
        HttpApiServer::new(api_server_address, token_cacher)
    };

    // Run Command
    if let Err(e) = cli_opts.command.run(&mut api_server).await {
        cli::report_error(&e);
        std::process::exit(1)
    }
}
