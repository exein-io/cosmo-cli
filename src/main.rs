use std::{alloc::System, env};

#[global_allocator]
static GLOBAL: System = System;

use cosmo_cli::{
    api::HttpApiServer,
    cli,
    security::{firebase::Firebase, token_cacher::TokenCacher},
};

// Firebase API KEY for Cosmo Project
const FIREBASE_API_KEY: &str = "AIzaSyBbu0Q_aIz5g1jxA4f_1WR55sFaUmlnpxY";

#[tokio::main]
async fn main() {
    // Parse CLI
    let cli_opts = cli::parse_from(&mut std::env::args_os()).unwrap_or_else(|e| e.exit());

    // TODO: check if needed
    openssl_probe::init_ssl_cert_env_vars();

    // Setup the custom panic handler
    human_panic::setup_panic!(Metadata {
        name: env!("CARGO_PKG_NAME").into(),
        version: env!("CARGO_PKG_VERSION").into(),
        authors: "Exein <support@exein.io>".into(),
        homepage: "cosmo.exein.io".into(),
    });

    // Setup logger
    let mut logger_builder = env_logger::builder();
    logger_builder.format_module_path(false);
    logger_builder.filter_level(cli_opts.log_level_filter);
    logger_builder.init();

    // Setup auth service
    // It uses Firebase behind a token cache layer
    let token_cacher = {
        // Setup Firebase
        // Try to read firebase api key from environment otherwise uses the default one.
        // Use this environment variable for development
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

        // Setup the token cache
        const TOKEN_CACHE_DIR: &str = "cosmo-cli";
        const TOKEN_CACHE_FILE: &str = "cosmo-cli-token";
        let token_path = dirs::cache_dir()
            .map(|home_dir| home_dir.join(TOKEN_CACHE_DIR).join(TOKEN_CACHE_FILE))
            .expect("PATH ERROR");
        TokenCacher {
            auth_service: firebase,
            token_path,
        }
    };

    // Setup api server
    let mut api_server = HttpApiServer::new(
        "cosmo-api.exein.io".into(),
        "443".to_string(),
        true,
        token_cacher,
    );

    // Run Command
    if let Err(e) = cli_opts.command.run(&mut api_server).await {
        cli::report_error(&e);
        std::process::exit(1)
    }
}
