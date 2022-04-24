pub mod api;
pub mod cli;
pub mod security;
pub mod services;

use anyhow::{anyhow, Context};
use api::ApiServer;
use cli::{Analysis, ApiKeyAction, Command, OutputMode};
use core::fmt;
use lazy_static::lazy_static;
use project_service::Project;
use services::*;
use std::{
    env,
    error::Error,
    fs::File,
    io::{self, prelude::*, BufRead, BufReader, Write},
};

use crate::services::project_service::*;

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
async fn check_version<U: ApiServer>(api_server: &U) -> Result<(), Box<dyn Error>> {
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

#[derive(Debug)]
pub struct CommandOutput<T> {
    output_mode: OutputMode,
    inner_output: T,
}

impl<T> fmt::Display for CommandOutput<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // write!(f, "({}, {})", self.x, self.y)
        todo!()
    }
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

pub async fn run_cmd<U: ApiServer>(cmd: Command, api_server: &mut U) -> Result<(), anyhow::Error> {
    // check_version(api_server).await?; //TODO

    // Authentication
    if let Command::Logout = cmd {
        // Skip auth if logout command
    } else {
        log::debug!("Startup login");
        let auth_data = api_server.authenticate().await?;
        log::info!("Logged in as: {}", auth_data.username);
    }

    match cmd {
        Command::CreateProject {
            fw_filepath,
            fw_type,
            fw_subtype,
            name,
            description,
        } => {
            log::info!("Create Project...");
            let project_id = project_service::create(
                &fw_filepath,
                &fw_type,
                &fw_subtype,
                &name,
                description.as_deref(),
                api_server,
            )
            .await?;
            log::info!("Project created successfull. Project id: {}", project_id);
            log::info!(
                "Dashboard URL: {}/reports/{}",
                api_server.address(),
                project_id
            );
            Ok(())
        }
        Command::List => {
            let projects: Vec<Project> = project_service::list_projects(api_server).await?;
            let table = Project::get_table_from_list(&projects);
            log::debug!("res: {:#?}", projects);
            println!("{}", table);
            Ok(())
        }
        Command::Login => Ok(()),
        Command::Logout => {
            api_server.logout().await?;
            log::info!("Logout successfully");
            Ok(())
        }
        Command::Overview { project_id } => {
            let overview = project_service::overview(api_server, project_id).await?;
            log::debug!("res:: {:#?}", overview);

            let fw_type = overview["project"]["project_type"]
                .as_str()
                .context("Error extracting string")?;
            log::debug!("project type {}", fw_type);
            match fw_type {
                "LINUX" | "CONTAINER" => {
                    let lpo: LinuxProjectOverview = serde_json::from_value(overview).unwrap();
                    log::info!("Overview: {:#?}", lpo);
                }
                "UEFI" => {
                    let upo: UefiProjectOverview = serde_json::from_value(overview).unwrap();
                    log::info!("Overview: {:#?}", upo);
                }
                "VXWORKS" => {
                    let vpo: VxworksProjectOverview = serde_json::from_value(overview).unwrap();
                    log::info!("Overview: {:#?}", vpo);
                }
                np => log::error!("Type not supported: {}", np),
            }

            Ok(())
        }
        Command::Analysis {
            project_id,
            analysis,
            page,
            per_page,
        } => {
            let res = project_service::analysis(api_server, project_id, &analysis, page, per_page)
                .await?;

            if let Some(err) = res.error {
                println!("Analysis {} error: {}", analysis, err)
                // TODO:
            } else {
                let result = res.result.unwrap(); // Safe to unwrap

                log::info!("FW type:{} | Analysis: {}", res.fw_type, res.name);

                match analysis {
                    // Linux/Container Analysis
                    Analysis::Hardening => {
                        let an: Vec<LinuxHardeningAnalysis> =
                            serde_json::from_value(result).unwrap();
                        let table = LinuxHardeningAnalysis::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::CveCheck => {
                        let an: Vec<LinuxCveCheckAnalysis> =
                            serde_json::from_value(result).unwrap();
                        let table = LinuxCveCheckAnalysis::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::SecurityScan => {
                        let an: Vec<LinuxSecurityScanAnalysis> =
                            serde_json::from_value(result).unwrap();
                        let table = LinuxSecurityScanAnalysis::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::PasswordHash => {
                        let an: Vec<LinuxPasswordHashAnalysis> =
                            serde_json::from_value(result).unwrap();
                        let table = LinuxPasswordHashAnalysis::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::Crypto => {
                        let an: Vec<LinuxCryptoAnalysis> = serde_json::from_value(result).unwrap();
                        let table = LinuxCryptoAnalysis::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::Nvram => {
                        let an: Vec<LinuxNvramAnalysis> = serde_json::from_value(result).unwrap();
                        let table = LinuxNvramAnalysis::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::Kernel => {
                        let an: Vec<LinuxKernelAnalysis> = serde_json::from_value(result).unwrap();
                        let table = LinuxKernelAnalysis::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::SoftwareBOM => {
                        let an: Vec<LinuxSoftwareBOMAnalysis> =
                            serde_json::from_value(result).unwrap();
                        let table = LinuxSoftwareBOMAnalysis::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::StaticCode => {
                        let analysis_result: Vec<LinuxStaticCodeAnalysis> =
                            serde_json::from_value(result).unwrap();
                        let analysis_parsed: Result<Vec<LinuxStaticCode>, anyhow::Error> =
                            analysis_result
                                .into_iter()
                                .map(|executable_flaw| {
                                    let flaw_str = executable_flaw
                                        .flaws
                                        .as_str()
                                        .ok_or(anyhow!("failed to access flaw string"));

                                    let flaw_parsed = flaw_str.and_then(|flaw| {
                                        let flaw_parsed =
                                            serde_json::from_str::<LinuxStaticCodeAnalysisFlaws>(
                                                flaw,
                                            )
                                            .map_err(|_| anyhow!("failed to parse flaw"));
                                        flaw_parsed
                                    });

                                    flaw_parsed.map(|flaw| LinuxStaticCode {
                                        line: flaw.line.trim().to_string(),
                                        descr: flaw.descr.trim().to_string(),
                                        flaw_type: flaw.flaw_type.trim().to_string(),
                                        filename: executable_flaw.filename,
                                    })
                                })
                                .collect();
                        let analysis_parsed = analysis_parsed?;

                        log::debug!("{:#?}", analysis_parsed);
                        let table = LinuxStaticCode::get_table_from_list(&analysis_parsed);
                        println!("{}", table);
                    }
                    // UEFI Analysis
                    Analysis::Access => {
                        let an: Vec<UefiAccess> = serde_json::from_value(result).unwrap();
                        let table = UefiAccess::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::IntelBootGuard => {
                        let an: UefiIntelBootGuard = serde_json::from_value(result).unwrap();
                        let table = UefiIntelBootGuardRsa::get_table_from_list(&an.rsa);
                        println!("{}", table);
                        println!("ACM: {}", an.acm);
                    }
                    Analysis::Surface => {
                        let an: Vec<UefiSurface> = serde_json::from_value(result).unwrap();
                        let table = UefiSurface::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::SecureBoot => {
                        let an: UefiSecureBoot = serde_json::from_value(result).unwrap();
                        let table = UefiSecureBootCerts::get_table_from_list(&an.certs.kek, "kek");
                        println!("{}", table);
                        let table = UefiSecureBootCerts::get_table_from_list(&[an.certs.pk], "pk");
                        println!("{}", table);
                        let table =
                            UefiSecureBootCerts::get_table_from_list(&an.databases.certs.db, "db");
                        println!("{}", table);
                        let table = UefiSecureBootCerts::get_table_from_list(
                            &an.databases.certs.dbx,
                            "dbx",
                        );
                        println!("{}", table);
                    }

                    Analysis::UefiSecurityScan => {
                        let an: Vec<UefiSecurityScan> = serde_json::from_value(result).unwrap();
                        let table = UefiSecurityScan::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::PeimDxe => {
                        let an: Vec<UefiPeimDxe> = serde_json::from_value(result).unwrap();
                        let table = UefiPeimDxe::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    // Vxworks Analysis
                    Analysis::Functions => {
                        let an: Vec<VxworksData> = serde_json::from_value(result).unwrap();
                        let table = VxworksData::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::Symbols => {
                        let an: Vec<VxworksData> = serde_json::from_value(result).unwrap();
                        let table = VxworksData::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::Tasks => {
                        let an: Vec<VxworksTask> = serde_json::from_value(result).unwrap();
                        let table = VxworksTask::get_table_from_list(&an);
                        println!("{}", table);
                    }
                    Analysis::Capabilities => {
                        let an: Vec<VxworksCapability> = serde_json::from_value(result).unwrap();
                        let table = VxworksCapability::get_table_from_list(&an);
                        println!("{}", table);
                    }
                }
            }

            Ok(())
        }
        Command::Delete { project_id } => {
            project_service::delete(api_server, project_id).await?;
            log::debug!("deleted {:#?}", project_id);
            Ok(())
        }
        Command::Report {
            project_id,
            savepath,
        } => {
            let report = project_service::report(api_server, project_id, savepath).await?;
            log::info!("Report saved to {}", report);

            Ok(())
        }
        Command::Apikey { action } => {
            match action {
                ApiKeyAction::Create => {
                    let apikey_data = apikey_service::create(api_server).await?;
                    log::info!("api key created: {}", apikey_data.api_key);
                }
                ApiKeyAction::List => {
                    let apikey_data = apikey_service::list(api_server).await?;
                    if let Some(apikey_data) = apikey_data {
                        log::info!(
                            "api key: {} created on {}",
                            apikey_data.api_key,
                            apikey_data.creation_date
                        );
                    } else {
                        log::info!("No API key found!")
                    }
                }
                ApiKeyAction::Delete => {
                    apikey_service::delete(api_server).await?;
                    log::info!("api key deleted");
                }
            }

            Ok(())
        }
    }
}
