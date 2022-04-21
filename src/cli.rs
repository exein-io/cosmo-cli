use std::{env, ffi::OsString};

use clap::{ArgEnum, Args, FromArgMatches, IntoApp, Parser, Subcommand};

use crate::Command;

#[derive(Debug, Clone, ArgEnum)]
pub enum PrintMode {
    Raw,
    Json,
}

#[derive(Debug, Clone)]
pub struct CosmoCliOpts {
    pub api_server: Option<String>,
    pub log_level_filter: log::LevelFilter,
    pub print_mode: PrintMode,
    pub command: Command,
}

pub fn parse_from<'a, I, T>(args: I) -> Result<CosmoCliOpts, clap::Error>
where
    I: Iterator<Item = T>,
    T: Into<OsString> + Clone,
{
    #[derive(Parser, Debug, Clone)]
    #[clap(about, version = crate::CLI_VERSION.as_str())]
    struct BaseCosmoCliOpts {
        /// Specify custom api server
        #[clap(long)]
        api_server: Option<String>,
        /// Verbosity
        #[clap(flatten)]
        verbose: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,
    }

    let app = BaseCosmoCliOpts::command()
        .subcommand_required(true)
        .arg_required_else_help(true)
        .disable_help_subcommand(true);

    let mut app = Command::augment_subcommands(app);

    #[derive(Parser, Debug)]
    struct DerivedArgs {
        #[clap(long, arg_enum, default_value_t = PrintMode::Raw)]
        print_mode: PrintMode,
    }

    for a in app.get_subcommands_mut() {
        *a = DerivedArgs::augment_args(a.clone())
    }

    let matches = app.try_get_matches_from(args)?;

    let base = BaseCosmoCliOpts::from_arg_matches(&matches)?;

    let print_mode = match matches.subcommand() {
        Some((_, matches)) => DerivedArgs::from_arg_matches(&matches)?.print_mode,
        None => unreachable!("Subcommand should be specified"),
    };

    let command = Command::from_arg_matches(&matches)?;

    Ok(CosmoCliOpts {
        api_server: base.api_server,
        log_level_filter: base.verbose.log_level_filter(),
        print_mode,
        command,
    })
}

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
