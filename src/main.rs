use std::alloc::System;

#[global_allocator]
static GLOBAL: System = System;

use cosmo_cli::{
    api::HttpApiServer,
    cli,
    security::{firebase::Firebase, token_cacher::TokenCacher},
    LOGO,
};

const TOKEN_CACHE_FILE: &str = "cosmo-cli-token";
const TOKEN_CACHE_DIR: &str = "cosmo-cli";

#[tokio::main]
async fn main() {
    openssl_probe::init_ssl_cert_env_vars();

    human_panic::setup_panic!(Metadata {
        name: env!("CARGO_PKG_NAME").into(),
        version: env!("CARGO_PKG_VERSION").into(),
        authors: "Exein <support@exein.io>".into(),
        homepage: "cosmo.exein.io".into(),
    });

    // ASCII logo
    println!("{}", *LOGO);

    // Setup Logger
    let mut logger_builder = env_logger::builder();
    logger_builder.format_module_path(false);
    #[cfg(debug_assertions)]
    logger_builder.filter_level(log::LevelFilter::Debug);
    #[cfg(not(debug_assertions))]
    logger_builder.filter_level(log::LevelFilter::Info);
    logger_builder.init();

    #[cfg(any(feature = "aws", feature = "staging"))]
    let firebase = Firebase::new("AIzaSyBbu0Q_aIz5g1jxA4f_1WR55sFaUmlnpxY".into(), true);
    #[cfg(feature = "development")]
    let firebase = Firebase::new("AIzaSyBjkvSnROm_v5fJh4x1OEki3t7LlGJQFWM".into(), true);

    let token_path = dirs::cache_dir()
        .map(|home_dir| home_dir.join(TOKEN_CACHE_DIR).join(TOKEN_CACHE_FILE))
        .expect("PATH ERROR");

    let token_cacher = TokenCacher {
        auth_service: firebase,
        token_path,
    };

    #[cfg(feature = "development")]
    let mut api_server =
        HttpApiServer::new("localhost".into(), "8000".to_string(), false, token_cacher);
    #[cfg(feature = "staging")]
    let mut api_server = HttpApiServer::new(
            //"172.20.20.170".into(),
            "cosmo-staging.exein.io".into(),
            "443".to_string(),
            true,
            token_cacher,
    );
    #[cfg(feature = "aws")]
    let mut api_server = HttpApiServer::new(
        "18.157.92.27".into(),
        "80".to_string(),
        false,
        token_cacher,
    );

    // Start
    let cmd = cli::parse_command();
    if let Err(e) = cmd.run(&mut api_server).await {
        log::error!("{}", e)
    }
}
