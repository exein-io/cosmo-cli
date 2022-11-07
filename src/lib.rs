use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
};

use anyhow::{anyhow, bail, Context};
use api::ApiServer;
use cli::Command;
use lazy_static::lazy_static;

use crate::{
    cli::{Analysis, ApiKeyAction, CommandOutput, Organization},
    services::{
        apikey_service::{self, ApiKeyData},
        organization_service::{self, OrganizationData},
        project_service::{self, *},
    },
};

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

pub async fn run_cmd<U: ApiServer>(
    cmd: Command,
    api_server: &mut U,
) -> Result<Box<dyn CommandOutput>, anyhow::Error> {
    // check_version(api_server).await?; //TODO

    // Authentication
    if let Command::Logout = cmd {
        // Skip auth if logout command
    } else {
        log::debug!("Startup login");
        let auth_data = api_server.authenticate().await?;
        log::info!("Logged in as: {}", auth_data.username);
    }

    let cmd_output: Box<dyn CommandOutput> = match cmd {
        Command::CreateProject {
            fw_filepath,
            fw_type,
            fw_subtype,
            name,
            description,
            organization,
        } => {
            log::info!("Create Project...");
            let project_created = project_service::create(
                &fw_filepath,
                &fw_type,
                &fw_subtype,
                &name,
                description.as_deref(),
                organization.as_deref(),
                api_server,
            )
            .await?;

            let project_id = project_created.id;
            Box::new(format!("Project created successfull with id: {project_id}. Dashboard URL: {}/reports/{project_id}", api_server.address()))
        }
        Command::List => {
            impl CommandOutput for Vec<Project> {
                fn text(&self) -> String {
                    Project::get_table_from_list(self)
                }

                fn json(&self) -> String {
                    serde_json::to_string(self).unwrap()
                }
            }

            let projects: Vec<Project> = project_service::list_projects(api_server).await?;

            Box::new(projects)
        }
        Command::Login => Box::new(()),
        Command::Logout => {
            api_server.logout().await?;
            Box::new("Logout successfully")
        }
        Command::Overview { project_id } => {
            let overview = project_service::overview(api_server, project_id).await?;
            log::debug!("res:: {:#?}", overview);

            let fw_type = overview["project"]["project_type"]
                .as_str()
                .context("Error extracting string")?;
            log::debug!("project type {}", fw_type);
            match fw_type {
                "LINUX" => {
                    impl CommandOutput for LinuxProjectOverview {
                        fn text(&self) -> String {
                            LinuxProjectOverview::get_text_output(self)
                        }

                        fn json(&self) -> String {
                            serde_json::to_string(self).unwrap()
                        }
                    }

                    let lpo: LinuxProjectOverview = serde_json::from_value(overview)?;

                    Box::new(lpo)
                }
                "CONTAINER" => {
                    impl CommandOutput for ContainerProjectOverview {
                        fn text(&self) -> String {
                            ContainerProjectOverview::get_text_output(self)
                        }

                        fn json(&self) -> String {
                            serde_json::to_string(self).unwrap()
                        }
                    }

                    let lpo: ContainerProjectOverview = serde_json::from_value(overview)?;

                    Box::new(lpo)
                }
                "UEFI" => {
                    impl CommandOutput for UefiProjectOverview {
                        fn text(&self) -> String {
                            UefiProjectOverview::get_text_output(self)
                        }

                        fn json(&self) -> String {
                            serde_json::to_string(self).unwrap()
                        }
                    }

                    let upo: UefiProjectOverview = serde_json::from_value(overview)?;

                    Box::new(upo)
                }
                "VXWORKS" => {
                    impl CommandOutput for VxworksProjectOverview {
                        fn text(&self) -> String {
                            VxworksProjectOverview::get_text_output(self)
                        }

                        fn json(&self) -> String {
                            serde_json::to_string(self).unwrap()
                        }
                    }
                    let vpo: VxworksProjectOverview = serde_json::from_value(overview)?;

                    Box::new(vpo)
                }
                np => bail!("Type not supported: {}", np), //TODO: remove branch with prehemptive parse
            }
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
                Box::new(format!("Analysis {} error: {}", analysis, err))
            } else {
                let result = res.result.unwrap(); // Safe to unwrap

                log::info!("FW type:{} | Analysis: {}", res.fw_type, res.name);

                match analysis {
                    // Linux/Container Analysis
                    Analysis::Hardening => {
                        impl CommandOutput for Vec<LinuxHardeningAnalysis> {
                            fn text(&self) -> String {
                                LinuxHardeningAnalysis::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<LinuxHardeningAnalysis> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::CveCheck => {
                        impl CommandOutput for Vec<LinuxCveCheckAnalysis> {
                            fn text(&self) -> String {
                                LinuxCveCheckAnalysis::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<LinuxCveCheckAnalysis> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::SecurityScan => {
                        impl CommandOutput for Vec<LinuxSecurityScanAnalysis> {
                            fn text(&self) -> String {
                                LinuxSecurityScanAnalysis::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<LinuxSecurityScanAnalysis> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::PasswordHash => {
                        impl CommandOutput for Vec<LinuxPasswordHashAnalysis> {
                            fn text(&self) -> String {
                                LinuxPasswordHashAnalysis::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<LinuxPasswordHashAnalysis> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::Crypto => {
                        impl CommandOutput for Vec<LinuxCryptoAnalysis> {
                            fn text(&self) -> String {
                                LinuxCryptoAnalysis::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<LinuxCryptoAnalysis> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::Nvram => {
                        impl CommandOutput for Vec<LinuxNvramAnalysis> {
                            fn text(&self) -> String {
                                LinuxNvramAnalysis::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<LinuxNvramAnalysis> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::Kernel => {
                        impl CommandOutput for Vec<LinuxKernelAnalysis> {
                            fn text(&self) -> String {
                                LinuxKernelAnalysis::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<LinuxKernelAnalysis> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::SoftwareBOM => {
                        impl CommandOutput for Vec<LinuxSoftwareBOMAnalysis> {
                            fn text(&self) -> String {
                                LinuxSoftwareBOMAnalysis::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<LinuxSoftwareBOMAnalysis> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::StaticCode => {
                        let analysis_result: Vec<LinuxStaticCodeAnalysis> =
                            serde_json::from_value(result)?;
                        let analysis_parsed: Result<Vec<LinuxStaticCode>, anyhow::Error> =
                            analysis_result
                                .into_iter()
                                .map(|executable_flaw| {
                                    let flaw_str = executable_flaw
                                        .flaws
                                        .as_str()
                                        .ok_or_else(|| anyhow!("failed to access flaw string"));

                                    let flaw_parsed = flaw_str.and_then(|flaw| {
                                        serde_json::from_str::<LinuxStaticCodeAnalysisFlaws>(flaw)
                                            .map_err(|_| anyhow!("failed to parse flaw"))
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

                        log::trace!("Analysis parsed: {:#?}", analysis_parsed);

                        impl CommandOutput for Vec<LinuxStaticCode> {
                            fn text(&self) -> String {
                                LinuxStaticCode::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an = LinuxStaticCode::get_table_from_list(&analysis_parsed);

                        Box::new(an)
                    }
                    // UEFI Analysis
                    Analysis::Access => {
                        impl CommandOutput for Vec<UefiAccess> {
                            fn text(&self) -> String {
                                UefiAccess::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<UefiAccess> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::IntelBootGuard => {
                        impl CommandOutput for UefiIntelBootGuard {
                            fn text(&self) -> String {
                                let table = UefiIntelBootGuardRsa::get_table_from_list(&self.rsa);
                                format!("{}\nACM: {}", table, self.acm)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: UefiIntelBootGuard = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::Surface => {
                        impl CommandOutput for Vec<UefiSurface> {
                            fn text(&self) -> String {
                                UefiSurface::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<UefiSurface> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::SecureBoot => {
                        impl CommandOutput for UefiSecureBoot {
                            fn text(&self) -> String {
                                vec![
                                    UefiSecureBootCerts::get_table_from_list(
                                        &self.certs.kek,
                                        "kek",
                                    ),
                                    UefiSecureBootCerts::get_table_from_list(
                                        &[self.certs.pk.clone()],
                                        "pk",
                                    ),
                                    UefiSecureBootCerts::get_table_from_list(
                                        &self.databases.certs.db,
                                        "db",
                                    ),
                                    UefiSecureBootCerts::get_table_from_list(
                                        &self.databases.certs.dbx,
                                        "dbx",
                                    ),
                                ]
                                .join("\n")
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: UefiSecureBoot = serde_json::from_value(result)?;

                        Box::new(an)
                    }

                    Analysis::UefiSecurityScan => {
                        impl CommandOutput for Vec<UefiSecurityScan> {
                            fn text(&self) -> String {
                                UefiSecurityScan::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<UefiSecurityScan> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::PeimDxe => {
                        impl CommandOutput for Vec<UefiPeimDxe> {
                            fn text(&self) -> String {
                                UefiPeimDxe::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<UefiPeimDxe> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    // Vxworks Analysis
                    Analysis::Functions => {
                        let an: Vec<VxworksData> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::Symbols => {
                        impl CommandOutput for Vec<VxworksData> {
                            fn text(&self) -> String {
                                VxworksData::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<VxworksData> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::Tasks => {
                        impl CommandOutput for Vec<VxworksTask> {
                            fn text(&self) -> String {
                                VxworksTask::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<VxworksTask> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                    Analysis::Capabilities => {
                        impl CommandOutput for Vec<VxworksCapability> {
                            fn text(&self) -> String {
                                VxworksCapability::get_table_from_list(self)
                            }

                            fn json(&self) -> String {
                                serde_json::to_string(self).unwrap()
                            }
                        }

                        let an: Vec<VxworksCapability> = serde_json::from_value(result)?;

                        Box::new(an)
                    }
                }
            }
        }
        Command::Delete { project_id } => {
            project_service::delete(api_server, project_id).await?;
            Box::new(format!("Project {} deleted", project_id))
        }
        Command::Report {
            project_id,
            savepath,
        } => {
            let report = project_service::report(api_server, project_id, savepath).await?;
            Box::new(format!("Report saved to {}", report))
        }

        Command::Organization(action) => {
            impl CommandOutput for Vec<OrganizationData> {
                fn text(&self) -> String {
                    OrganizationData::get_table_from_list(self)
                }

                fn json(&self) -> String {
                    serde_json::to_string(self).unwrap()
                }
            }

            match action {
                Organization::Create { name, description } => {
                    organization_service::create(api_server, &name, &description).await?;
                    Box::new(format!("Organization created: {}", name))
                }
                Organization::List => {
                    let org = organization_service::list(api_server).await?;
                    Box::new(org)
                }
                Organization::Delete { id } => {
                    organization_service::delete(api_server, id).await?;
                    Box::new(format!("Organization deleted. ID: {}", id))
                }
            }
        }
        Command::Apikey { action } => {
            impl CommandOutput for ApiKeyData {
                fn text(&self) -> String {
                    format!(
                        "api key: {} created on {}",
                        self.api_key, self.creation_date
                    )
                }

                fn json(&self) -> String {
                    serde_json::to_string(self).unwrap()
                }
            }

            match action {
                ApiKeyAction::Create => {
                    let apikey_data = apikey_service::create(api_server).await?;
                    Box::new(apikey_data)
                }
                ApiKeyAction::List => {
                    if let Some(apikey_data) = apikey_service::list(api_server).await? {
                        Box::new(apikey_data)
                    } else {
                        Box::new("No API key found!")
                    }
                }
                ApiKeyAction::Delete => {
                    apikey_service::delete(api_server).await?;
                    Box::new("api key deleted")
                }
            }
        }
    };

    Ok(cmd_output)
}
