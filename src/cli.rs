use crate::Command;
use clap::{App, AppSettings, Arg, SubCommand};
use std::ffi::OsString;
use uuid::Uuid;

pub fn parse_command<'a>() -> Command {
    parse_command_from(&mut std::env::args_os()).unwrap_or_else(|e| e.exit())
}

fn parse_command_from<'a, I, T>(args: I) -> Result<Command, clap::Error>
where
    I: Iterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = App::new("")
        .about("Easy Cosmo pipeline helper")
        .setting(AppSettings::SubcommandRequired)
        .subcommand(
            SubCommand::with_name("create")
                .alias("new")
                .about("Create project")
                .arg(
                    Arg::with_name("file")
                        .help("Firmware path to analyze")
                        .long("file")
                        .short("f")
                        .value_name("file")
                        .required(true),
                )
                .arg(
                    Arg::with_name("type")
                        .help("Type of your firmware")
                        .long("type")
                        .short("t")
                        .value_name("type")
                        .required(true),
                )
                .arg(
                    Arg::with_name("subtype")
                        .help("Subtype of your firmware")
                        .long("subtype")
                        .short("s")
                        .value_name("subtype")
                        .required(false),
                )
                .arg(
                    Arg::with_name("name")
                        .help("Project name")
                        .long("name")
                        .short("n")
                        .value_name("name")
                        .required(true),
                )
                .arg(
                    Arg::with_name("description")
                        .help("Project description")
                        .long("description")
                        .short("d")
                        .value_name("description")
                        .required(false),
                ),
        )
        .subcommand(
            SubCommand::with_name("list")
                .alias("ls")
                .about("List all projects"),
        )
        .subcommand(SubCommand::with_name("logout").about("Logout"))
        .subcommand(
            SubCommand::with_name("overview")
                .alias("show")
                .about("Project overview")
                .arg(
                    Arg::with_name("project_id")
                        .help("ID of the project")
                        .long("id")
                        .short("i")
                        .value_name("project_id")
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("analysis")
                .alias("an")
                .about("Project analysis result")
                .arg(
                    Arg::with_name("project_id")
                        .help("ID of the project")
                        .long("id")
                        .short("i")
                        .value_name("project_id")
                        .required(true),
                )
                .arg(
                    Arg::with_name("analysis")
                        .help("Analysis name")
                        .long("analysis")
                        .short("a")
                        .value_name("analysis")
                        .required(true),
                )
                .arg(
                    Arg::with_name("page")
                        .help("Page number")
                        .long("page")
                        .short("p")
                        .value_name("page")
                        .required(false),
                )
                .arg(
                    Arg::with_name("per_page")
                        .help("Per page results")
                        .long("per_page")
                        .short("l")
                        .value_name("per_page")
                        .required(false),
                ),
        )
        .subcommand(
            SubCommand::with_name("delete")
                .alias("rm")
                .about("Delete a project")
                .arg(
                    Arg::with_name("project_id")
                        .help("ID of the project")
                        .long("id")
                        .short("i")
                        .value_name("project_id")
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("report")
                .about("Project report")
                .arg(
                    Arg::with_name("project_id")
                        .help("ID of the project")
                        .long("id")
                        .short("i")
                        .value_name("project_id")
                        .required(true),
                )
                .arg(
                    Arg::with_name("savepath")
                        .help("PDF report path")
                        .long("output")
                        .short("o")
                        .value_name("savepath")
                        .required(false),
                ),
        )
        .subcommand(
            SubCommand::with_name("apikey")
                .about("API key handler")
                .arg(
                    Arg::with_name("action")
                        .help("Action to perform")
                        .long("action")
                        .short("a")
                        .value_name("action")
                        .required(true)
                        .possible_values(&["create", "list", "delete"]),
                ),
        )
        .get_matches_from_safe(args)?;

    let command = match matches.subcommand() {
        ("create", Some(subcommand)) => {
            let fw_filepath = subcommand.value_of("file").unwrap().to_string();
            let fw_type = subcommand.value_of("type").unwrap().to_string();
            let fw_subtype = subcommand
                .value_of("subtype")
                .unwrap_or("generic")
                .to_string();
            let name = subcommand.value_of("name").unwrap().to_string();
            let description = subcommand.value_of("description").map(|d| d.to_string());

            Command::CreateProject {
                fw_filepath,
                fw_type,
                fw_subtype,
                name,
                description,
            }
        }
        ("list", Some(_)) => Command::List,
        ("logout", Some(_)) => Command::Logout,
        ("overview", Some(subcommand)) => {
            let project_id = subcommand.value_of("project_id").unwrap();
            let project_id = Uuid::parse_str(project_id).expect("Failed to parse project id");

            Command::Overview { project_id }
        }
        ("report", Some(subcommand)) => {
            let project_id = subcommand.value_of("project_id").unwrap();
            let project_id = Uuid::parse_str(project_id).expect("Failed to parse project id");
            let savepath = subcommand
                .value_of("savepath")
                .unwrap_or(format!("/tmp/{}.pdf", project_id).as_str())
                .to_string();

            Command::Report {
                project_id,
                savepath,
            }
        }
        ("analysis", Some(subcommand)) => {
            let project_id = subcommand.value_of("project_id").unwrap();
            let project_id = Uuid::parse_str(project_id).expect("Failed to parse project id");
            let analysis = subcommand.value_of("analysis").unwrap().to_string();
            let page = subcommand.value_of("page").unwrap_or("0").to_string();
            let per_page = subcommand.value_of("per_page").unwrap_or("10").to_string();

            Command::Analysis {
                project_id,
                analysis,
                page,
                per_page,
            }
        }
        ("delete", Some(subcommand)) => {
            let project_id = subcommand.value_of("project_id").unwrap();
            let project_id = Uuid::parse_str(project_id).expect("Failed to parse project id");

            Command::Delete { project_id }
        }
        ("apikey", Some(subcommand)) => {
            let action = subcommand.value_of("action").unwrap().to_string();

            Command::Apikey { action }
        }
        _ => panic!("This shouldn't happen {:?}", matches),
    };

    Ok(command)
}
