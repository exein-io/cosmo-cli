use std::{env, ffi::OsString};

use clap::{Arg, ArgEnum, Args, FromArgMatches, Parser, Subcommand};

use crate::Command;

#[derive(Debug, Clone, ArgEnum)]
pub enum PrintMode {
    Raw,
    Json,
}

#[derive(Debug, Clone)]
pub struct CosmoCliOpts {
    /// Specify custom api server
    pub api_server: Option<String>,

    // pub verbosity:
    pub print_mode: PrintMode,

    pub command: Command,
}

pub fn parse_from<'a, I, T>(args: I) -> Result<CosmoCliOpts, clap::Error>
where
    I: Iterator<Item = T>,
    T: Into<OsString> + Clone,
{
    #[derive(Parser, Debug)]
    struct DerivedArgs {
        #[clap(long, arg_enum, default_value_t = PrintMode::Raw)]
        print_mode: PrintMode,
    }

    let app = clap::Command::new(env!("CARGO_PKG_NAME"))
        .version(crate::CLI_VERSION.as_str())
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .disable_help_subcommand(true)
        .arg(
            Arg::new("api_server")
                .long("api_server")
                .help("Specify custom api server"),
        );

    let mut app = Command::augment_subcommands(app);

    // let app = DerivedArgs::augment_args(app);

    for a in app.get_subcommands_mut() {
        *a = DerivedArgs::augment_args(a.clone())
    }

    let matches = app.try_get_matches_from(args)?;

    let api_server = matches.value_of("api_server").map(str::to_string);

    // let override_log_level;
    let print_mode = match matches.subcommand() {
        Some((_, matches)) => {
            // Handle verbosity flag
            // override_log_level = log_level_from_verbosity_flag_count(matches.occurrences_of("v"));

            let derived_matches = DerivedArgs::from_arg_matches(&matches)?;

            derived_matches.print_mode
        }
        None => unreachable!("Subcommand should be specified"),
    };

    let command = Command::from_arg_matches(&matches)?;

    Ok(CosmoCliOpts {
        api_server,
        print_mode,
        command,
    })
}

// #[derive(Debug, Clone, Subcommand)]
// pub enum Command2 {
//     CreateProject {
//         fw_filepath: String,
//         name: String,
//         description: Option<String>,
//         fw_type: String,
//         fw_subtype: String,
//     },
//     List,
//     Login,
// }

// impl Command2 {
//     pub async fn run<U: ApiServer>(self, api_server: &mut U) -> Result<(), anyhow::Error> {
//         todo!()
//     }
// }

// fn with_verbosity_flag(app: Command) -> Command {
//     app.arg(
//         Arg::new("output")
//             .short('o')
//             .long("output")
//             .multiple_occurrences(true)
//             .takes_value(false)
//             .help("Pass many times for a more verbose output. Passing `-v` adds debug logs, `-vv` enables trace logging"),
//     )
// }

// fn parse_command_from<'a, I, T>(args: I) -> Result<Command, clap::Error>
// where
//     I: Iterator<Item = T>,
//     T: Into<OsString> + Clone,
// {
//     let matches = App::new("")
//         .about("Easy Cosmo pipeline helper")
//         .setting(AppSettings::SubcommandRequired)


//     let command = match matches.subcommand() {
//         ("create", Some(subcommand)) => {
//             let fw_filepath = subcommand.value_of("file").unwrap().to_string();
//             let fw_type = subcommand.value_of("type").unwrap().to_string();
//             let fw_subtype = subcommand
//                 .value_of("subtype")
//                 .unwrap_or("generic")
//                 .to_string();
//             let name = subcommand.value_of("name").unwrap().to_string();
//             let description = subcommand.value_of("description").map(|d| d.to_string());

//             Command::CreateProject {
//                 fw_filepath,
//                 fw_type,
//                 fw_subtype,
//                 name,
//                 description,
//             }
//         }
//         ("list", Some(_)) => Command::List,
//         ("login", Some(_)) => Command::Login,
//         ("logout", Some(_)) => Command::Logout,
//         ("overview", Some(subcommand)) => {
//             let project_id = subcommand.value_of("project_id").unwrap();
//             let project_id = Uuid::parse_str(project_id).expect("Failed to parse project id");

//             Command::Overview { project_id }
//         }
//         ("report", Some(subcommand)) => {
//             let project_id = subcommand.value_of("project_id").unwrap();
//             let project_id = Uuid::parse_str(project_id).expect("Failed to parse project id");
//             let savepath = subcommand
//                 .value_of("savepath")
//                 .unwrap_or(format!("/tmp/{}.pdf", project_id).as_str())
//                 .to_string();

//             Command::Report {
//                 project_id,
//                 savepath,
//             }
//         }
//         ("analysis", Some(subcommand)) => {
//             let project_id = subcommand.value_of("project_id").unwrap();
//             let project_id = Uuid::parse_str(project_id).expect("Failed to parse project id");
//             let analysis = subcommand.value_of("analysis").unwrap().to_string();
//             let page = subcommand.value_of("page").unwrap_or("0").to_string();
//             let per_page = subcommand.value_of("per_page").unwrap_or("10").to_string();

//             Command::Analysis {
//                 project_id,
//                 analysis,
//                 page,
//                 per_page,
//             }
//         }
//         ("delete", Some(subcommand)) => {
//             let project_id = subcommand.value_of("project_id").unwrap();
//             let project_id = Uuid::parse_str(project_id).expect("Failed to parse project id");

//             Command::Delete { project_id }
//         }
//         ("apikey", Some(subcommand)) => {
//             let action = subcommand.value_of("action").unwrap().to_string();

//             Command::Apikey { action }
//         }
//         _ => panic!("This shouldn't happen {:?}", matches),
//     };

//     Ok(command)
// }

fn show_backtrace() -> bool {
    if log::max_level() > log::LevelFilter::Error {
        return true;
    }

    if let Ok(true) = env::var("RUST_BACKTRACE").map(|s| s == "1") {
        return true;
    }

    false
}

pub fn report_error(e: &anyhow::Error) {
    // NB: This shows one error: even for multiple causes and backtraces etc,
    // rather than one per cause, and one for the backtrace. This seems like a
    // reasonable tradeoff, but if we want to do differently, this is the code
    // hunk to revisit, that and a similar build.rs auto-detect glue as anyhow
    // has to detect when backtrace is available.
    if show_backtrace() {
        log::error!("{:?}", e);
    } else {
        log::error!("{:#}", e);
    }
}
