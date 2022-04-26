use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
};

use api::ApiServer;
use lazy_static::lazy_static;

pub mod api;
pub mod cli;
pub mod security;
pub mod services;

pub fn version() -> &'static str {
    #[cfg(debug_assertions)]
    lazy_static! {
        static ref VERSION: String = format!("{}+dev", env!("CARGO_PKG_VERSION"));
    }

    #[cfg(not(debug_assertions))]
    lazy_static! {
        static ref VERSION: String = env!("CARGO_PKG_VERSION").to_string();
    }
    &VERSION
}

fn read_bytes_from_file(filename: &str) -> Result<Vec<u8>, std::io::Error> {
    let f = File::open(filename)?;
    let reader = BufReader::new(f);
    reader.bytes().collect()
}

#[allow(dead_code)]
async fn check_version<U: ApiServer>(api_server: &U) -> Result<(), anyhow::Error> {
    let current_version = semver::Version::parse(version())?;
    let latest_version = api_server.updates_check().await?;

    // TODO: fix repo path
    if current_version < latest_version.version {
        println!(
            r#"
A new version of Exein Cosmo is available! Download it at path/to/repo/releases/latest
and install it by running ./exein-analyzer-cli-installer.run in your terminal.
"#
        );
        println!("{}", latest_version.changelog);
    }

    Ok(())
}

// TODO: hadle unwraps
fn read_username_and_password_from_stdin() -> (String, String) {
    let stdin = io::stdin();
    let mut iterator = stdin.lock().lines();
    println!("If you haven't registered an account with Exein yet, visit hub.exein.io/signup to continue\n");
    print!("Email: ");
    io::stdout().flush().unwrap();
    let username = iterator.next().unwrap().unwrap();
    let password = rpassword::prompt_password("Password: ").unwrap();
    (username, password)
}
