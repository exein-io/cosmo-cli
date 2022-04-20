extern crate nom;

pub mod api;
pub mod cli;
pub mod security;
pub mod services;

use anyhow::{anyhow, Context};
use api::ApiServer;
use clap::{ArgEnum, Subcommand};
use cli::PrintMode;
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
use uuid::Uuid;

use crate::services::project_service::*;

#[cfg(debug_assertions)]
lazy_static! {
    pub static ref CLI_VERSION: String = format!("{}+dev", env!("CARGO_PKG_VERSION"));
}

#[cfg(not(debug_assertions))]
lazy_static! {
    pub static ref CLI_VERSION: String = env!("CARGO_PKG_VERSION").to_string();
}

lazy_static! {
    pub static ref LOGO: String = format!(
        r#"
                        __        
    ____ ___  ___ ____ |__| ____  
  _/ __ \\  \/  // __ \|  |/    \ 
  \  ___/ >    <\  ___/|  |   |  \
   \___  >__/\_ \\___  >__|___|  /
       \/      \/    \/        \/ Analyzer v{}
"#,
        *CLI_VERSION
    );
}

fn read_bytes_from_file(filename: &str) -> Result<Vec<u8>, std::io::Error> {
    let f = File::open(filename)?;
    let reader = BufReader::new(f);
    reader.bytes().collect()
}

#[allow(dead_code)]
async fn check_version<U: ApiServer>(api_server: &U) -> Result<(), Box<dyn Error>> {
    let current_version = semver::Version::parse(&CLI_VERSION)?;
    let latest_version = api_server.updates_check().await?;

    if current_version < latest_version.version {
        println!(
            r#"
A new version of Exein Cosmo is available! Download it at https://cosmo.exein.io/static/exein-analyzer-cli-installer.run
and install it by running ./exein-analyzer-cli-installer.run in your terminal.
"#
        );
        println!("{}", latest_version.changelog);
    }

    Ok(())
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Create project
    CreateProject {
        /// Firmware path to analyze
        #[clap(short = 'f', long = "file", value_name = "FILE")]
        fw_filepath: String,
        /// Project name
        #[clap(short, long)]
        name: String,
        /// Project description
        #[clap(short, long)]
        description: Option<String>,
        /// Type of your firmware
        #[clap(short = 't', long = "type", value_name = "TYPE")]
        fw_type: String,
        /// Subtype of your firmware
        #[clap(short = 's', long = "subtype", value_name = "SUBTYPE")]
        fw_subtype: String,
    },
    List,
    Login,
    Logout,
    Overview {
        project_id: Uuid,
    },
    Analysis {
        project_id: Uuid,
        analysis: String,
        page: String,
        per_page: String,
    },
    Delete {
        project_id: Uuid,
    },
    Report {
        project_id: Uuid,
        savepath: String,
    },
    Apikey {
        #[clap(short, long, arg_enum)]
        action: ApiKeyAction,
    },
}

#[derive(Debug, Clone, ArgEnum)]
pub enum ApiKeyAction {
    List,
    Create,
    Delete,
}

impl Command {
    pub async fn run<U: ApiServer>(self, api_server: &mut U) -> Result<(), anyhow::Error> {
        //check_version(api_server).await?;

        // Authentication
        if let Self::Logout = self {
            // Trick to skip prehemptive auth if logout
        } else {
            log::debug!("First login attempt");
            let auth_data = api_server.authenticate().await?;
            log::info!("Logged in as: {}", auth_data.username);
        }

        match self {
            Self::CreateProject {
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
                    "Dashboard URL: https://cosmo.exein.io/reports/{}",
                    project_id
                );
                Ok(())
            }
            Self::List => {
                let projects: Vec<Project> = project_service::list_projects(api_server).await?;
                let table = Project::get_table_from_list(&projects);
                log::debug!("res: {:#?}", projects);
                println!("{}", table);
                Ok(())
            }
            Self::Login => Ok(()),
            Self::Logout => {
                api_server.logout().await?;
                log::info!("Logout successfully");
                Ok(())
            }
            Self::Overview { project_id } => {
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
            Self::Analysis {
                project_id,
                analysis,
                page,
                per_page,
            } => {
                let res =
                    project_service::analysis(api_server, project_id, &analysis, &page, &per_page)
                        .await?;

                match res.error {
                    None => {
                        let name = res.name.as_str();
                        let fw_type = res.fw_type;
                        let result = res.result.unwrap();
                        log::debug!("{} analysis {}", fw_type, name);
                        //log::debug!("res:: {:#?}", result);

                        match name {
                            // Linux/Container Analysis
                            "Hardening" => {
                                let an: Vec<LinuxHardeningAnalysis> =
                                    serde_json::from_value(result).unwrap();
                                log::debug!("Hardening: {:#?}", an);
                                let table = LinuxHardeningAnalysis::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "CveCheck" => {
                                let an: Vec<LinuxCveCheckAnalysis> =
                                    serde_json::from_value(result).unwrap();
                                log::debug!("CveCheck: {:#?}", an);
                                let table = LinuxCveCheckAnalysis::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "SecurityScan" => {
                                let an: Vec<LinuxSecurityScanAnalysis> =
                                    serde_json::from_value(result).unwrap();
                                log::debug!("SecurityScan: {:#?}", an);
                                let table = LinuxSecurityScanAnalysis::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "PasswordHash" => {
                                let an: Vec<LinuxPasswordHashAnalysis> =
                                    serde_json::from_value(result).unwrap();
                                log::debug!("PasswordHash: {:#?}", an);
                                let table = LinuxPasswordHashAnalysis::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "Crypto" => {
                                let an: Vec<LinuxCryptoAnalysis> =
                                    serde_json::from_value(result).unwrap();
                                log::debug!("Crypto: {:#?}", an);
                                let table = LinuxCryptoAnalysis::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "Nvram" => {
                                let an: Vec<LinuxNvramAnalysis> =
                                    serde_json::from_value(result).unwrap();
                                log::debug!("Nvram: {:#?}", an);
                                let table = LinuxNvramAnalysis::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "Kernel" => {
                                let an: Vec<LinuxKernelAnalysis> =
                                    serde_json::from_value(result).unwrap();
                                log::debug!("Kernel: {:#?}", an);
                                let table = LinuxKernelAnalysis::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "SoftwareBOM" => {
                                let an: Vec<LinuxSoftwareBOMAnalysis> =
                                    serde_json::from_value(result).unwrap();
                                log::debug!("SoftwareBOM: {:#?}", an);
                                let table = LinuxSoftwareBOMAnalysis::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "StaticCode" => {
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
                                                let flaw_parsed = serde_json::from_str::<
                                                    LinuxStaticCodeAnalysisFlaws,
                                                >(
                                                    flaw
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
                            "Access" => {
                                let an: Vec<UefiAccess> = serde_json::from_value(result).unwrap();
                                log::debug!("Access: {:#?}", an);
                                let table = UefiAccess::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "IntelBootGuard" => {
                                let an: UefiIntelBootGuard =
                                    serde_json::from_value(result).unwrap();
                                log::debug!("IntelBootGuard: {:#?}", an);
                                let table = UefiIntelBootGuardRsa::get_table_from_list(&an.rsa);
                                println!("{}", table);
                                println!("ACM: {}", an.acm);
                            }
                            "Surface" => {
                                let an: Vec<UefiSurface> = serde_json::from_value(result).unwrap();
                                log::debug!("Surface: {:#?}", an);
                                let table = UefiSurface::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "SecureBoot" => {
                                let an: UefiSecureBoot = serde_json::from_value(result).unwrap();
                                log::info!("SecureBoot: {:#?}", an);
                                let table =
                                    UefiSecureBootCerts::get_table_from_list(&an.certs.kek, "kek");
                                println!("{}", table);
                                let table =
                                    UefiSecureBootCerts::get_table_from_list(&[an.certs.pk], "pk");
                                println!("{}", table);
                                let table = UefiSecureBootCerts::get_table_from_list(
                                    &an.databases.certs.db,
                                    "db",
                                );
                                println!("{}", table);
                                let table = UefiSecureBootCerts::get_table_from_list(
                                    &an.databases.certs.dbx,
                                    "dbx",
                                );
                                println!("{}", table);
                            }

                            "UefiSecurityScan" => {
                                let an: Vec<UefiSecurityScan> =
                                    serde_json::from_value(result).unwrap();
                                log::debug!("UefiSecurityScan: {:#?}", an);
                                let table = UefiSecurityScan::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "PeimDxe" => {
                                let an: Vec<UefiPeimDxe> = serde_json::from_value(result).unwrap();
                                log::debug!("PeimDxe: {:#?}", an);
                                let table = UefiPeimDxe::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            // Vxworks Analysis
                            "Functions" => {
                                let an: Vec<VxworksData> = serde_json::from_value(result).unwrap();
                                log::debug!("Function: {:#?}", an);
                                let table = VxworksData::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "Symbols" => {
                                let an: Vec<VxworksData> = serde_json::from_value(result).unwrap();
                                log::debug!("Symbols: {:#?}", an);
                                let table = VxworksData::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "Tasks" => {
                                let an: Vec<VxworksTask> = serde_json::from_value(result).unwrap();
                                log::debug!("Tasks: {:#?}", an);
                                let table = VxworksTask::get_table_from_list(&an);
                                println!("{}", table);
                            }
                            "Capabilities" => {
                                let an: Vec<VxworksCapability> =
                                    serde_json::from_value(result).unwrap();
                                log::debug!("Capabilities: {:#?}", an);
                                let table = VxworksCapability::get_table_from_list(&an);
                                println!("{}", table);
                            }

                            an => log::error!("Analysis not supported: {}", an),
                        }
                    }
                    e => log::debug!("Analysis {} error: {}", analysis, e.unwrap()),
                }

                Ok(())
            }
            Self::Delete { project_id } => {
                project_service::delete(api_server, project_id).await?;
                log::debug!("deleted {:#?}", project_id);
                Ok(())
            }
            Self::Report {
                project_id,
                savepath,
            } => {
                let report = project_service::report(api_server, project_id, savepath).await?;
                log::info!("Report saved to {}", report);

                Ok(())
            }
            Self::Apikey { action } => {
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
}

#[derive(Debug)]
pub struct CommandOutput<T> {
    print_mode: PrintMode,
    inner_output: T,
}

impl<T> fmt::Display for CommandOutput<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // write!(f, "({}, {})", self.x, self.y)
        todo!()
    }
}

fn read_username_and_password_from_stdin() -> (String, String) {
    let stdin = io::stdin();
    let mut iterator = stdin.lock().lines();
    println!("If you haven’t registered an account with Exein yet, visit hub.exein.io/signup to continue\n");
    print!("Email: ");
    io::stdout().flush().unwrap();
    let username = iterator.next().unwrap().unwrap();
    let password = rpassword::read_password_from_tty(Some("Password: ")).unwrap();
    (username, password)
}
