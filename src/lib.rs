extern crate nom;

pub mod api;
pub mod cli;
pub mod security;
pub mod services;

use api::ApiServer;
use lazy_static::lazy_static;
use project_service::Project;
use services::*;
use std::{
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
                       .__        
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

async fn check_version<U: ApiServer>(api_server: &U) -> Result<(), Box<dyn Error>> {
    let current_version = semver::Version::parse(&CLI_VERSION)?;
    let latest_version = api_server.updates_check().await?;

    if current_version < latest_version.version {
        println!(
            r#"
A new version of Exein is available! Download it at https://beta.exein.io/static/exein-installer-current.run
and install it by running ./exein-installer-current.run in your terminal.
"#
        );
        println!("{}", latest_version.changelog);
    }

    Ok(())
}

pub enum Command {
    CreateProject {
        fw_filepath: String,
        name: String,
        description: Option<String>,
        fw_type: String,
        fw_subtype: String,
    },
    List,
    Logout,
    Overview {
        project_id: Uuid,
    },
    Analysis {
        project_id: Uuid,
        analysis: String,
    },
    Delete {
        project_id: Uuid,
    },
    Report {
        project_id: Uuid,
        savepath: String,
    },
    Apikey {
        action: String,
    },
}

impl Command {
    pub async fn run<U: ApiServer>(self, api_server: &mut U) -> Result<(), Box<dyn Error>> {
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
                Ok(())
            }
            Self::List => {
                let projects: Vec<Project> = project_service::list_projects(api_server).await?;
                let table = Project::get_table_from_list(&projects);
                log::debug!("res: {:#?}", projects);

                println!("{}", table);
                Ok(())
            }
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
                    .ok_or("Error extracting string")?;
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
            } => {
                let res = project_service::analysis(api_server, project_id, &analysis).await?;

                match res.error {
                    None => {
                        let name = res.name.as_str();
                        let fw_type = res.fw_type;
                        let result = res.result.unwrap();
                        log::debug!("{} analysis {}", fw_type, name);
                        log::debug!("res:: {:#?}", result);

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
                                let analysis_parsed: Result<Vec<LinuxStaticCode>, String> =
                                    analysis_result
                                        .into_iter()
                                        .map(|executable_flaw| {
                                            let flaw_str = executable_flaw
                                                .flaws
                                                .as_str()
                                                .ok_or(format!("failed to access flaw string"));

                                            let flaw_parsed: Result<
                                                LinuxStaticCodeAnalysisFlaws,
                                                String,
                                            > = flaw_str.and_then(|flaw| {
                                                let flaw_parsed = serde_json::from_str::<
                                                    LinuxStaticCodeAnalysisFlaws,
                                                >(
                                                    flaw
                                                )
                                                .map_err(|_| format!("failed to parse flaw"));
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
                                log::info!("Access: {:#?}", an);
                            }
                            "IntelBootGuard" => {
                                let an: UefiIntelBootGuard =
                                    serde_json::from_value(result).unwrap();
                                log::info!("IntelBootGuard: {:#?}", an);
                            }
                            "Surface" => {
                                let an: Vec<UefiSurface> = serde_json::from_value(result).unwrap();
                                log::info!("Surface: {:#?}", an);
                            }
                            "SecureBoot" => {
                                let an: UefiSecureBoot = serde_json::from_value(result).unwrap();
                                log::info!("SecureBoot: {:#?}", an);
                            }
                            "UefiSecurityScan" => {
                                let an: Vec<UefiSecurityScan> =
                                    serde_json::from_value(result).unwrap();
                                log::info!("UefiSecurityScan: {:#?}", an);
                            }
                            "PeimDxe" => {
                                let an: Vec<UefiPeimDxe> = serde_json::from_value(result).unwrap();
                                log::info!("PeimDxe: {:#?}", an);
                            }
                            // Vxworks Analysis
                            "Functions" => {
                                let an: Vec<VxworksData> = serde_json::from_value(result).unwrap();
                                log::info!("Function: {:#?}", an);
                            }
                            "Symbols" => {
                                let an: Vec<VxworksData> = serde_json::from_value(result).unwrap();
                                log::info!("Symbols: {:#?}", an);
                            }
                            "Tasks" => {
                                let an: Vec<VxworksTask> = serde_json::from_value(result).unwrap();
                                log::info!("Tasks: {:#?}", an);
                            }
                            "Capabilities" => {
                                let an: Vec<VxworksCapability> =
                                    serde_json::from_value(result).unwrap();
                                log::info!("Capabilities: {:#?}", an);
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
                match action.as_str() {
                    "create" => {
                        let apikey = apikey_service::create(api_server).await?;
                        log::debug!("api key create: {:#?}", apikey);
                    }
                    "list" => {
                        let apikey = apikey_service::list(api_server).await?;
                        log::debug!("api key list: {:#?}", apikey);
                    }
                    "delete" => {
                        apikey_service::delete(api_server).await?;
                        log::debug!("api key deleted");
                    }
                    _ => log::debug!("Action not supported"),
                }

                Ok(())
            }
        }
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
