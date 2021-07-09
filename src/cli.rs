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
        .about("Easy Exein pipeline helper")
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
        .subcommand(SubCommand::with_name("status").about("Check models status"))
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
        .get_matches_from_safe(args)?;

    let command = match matches.subcommand() {
        ("create", Some(subcommand)) => {
            let fw_filepath = subcommand.value_of("file").unwrap().to_string();
            let fw_type = subcommand.value_of("type").unwrap().to_string();
            let fw_subtype = subcommand
                .value_of("fw_subtype")
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
        ("status", Some(_)) => Command::Status,
        ("list", Some(_)) => Command::List,
        ("logout", Some(_)) => Command::Logout,
        ("overview", Some(subcommand)) => {
            let project_id = subcommand.value_of("project_id").unwrap();
            let project_id = Uuid::parse_str(project_id).expect("Failed to parse project id");

            Command::Overview { project_id }
        }
        ("delete", Some(subcommand)) => {
            let project_id = subcommand.value_of("project_id").unwrap();
            let project_id = Uuid::parse_str(project_id).expect("Failed to parse project id");

            Command::Delete { project_id }
        }
        _ => panic!("This shouldn't happen {:?}", matches),
    };

    Ok(command)
}
