use std::{env, ffi::OsString, fmt};

use clap::{ArgEnum, Args, FromArgMatches, IntoApp, Parser, Subcommand};
use uuid::Uuid;

#[derive(Debug, Clone, ArgEnum)]
pub enum OutputMode {
    Text,
    Json,
}

#[derive(Debug, Clone)]
pub struct CosmoCliOpts {
    pub api_server: Option<String>,
    pub log_level_filter: log::LevelFilter,
    pub output_mode: OutputMode,
    pub command: Command,
}

pub fn parse_from<'a, I, T>(args: I) -> Result<CosmoCliOpts, clap::Error>
where
    I: Iterator<Item = T>,
    T: Into<OsString> + Clone,
{
    #[derive(Parser, Debug, Clone)]
    #[clap(about, version = crate::version())]
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
        #[clap(short = 'o', long = "output", arg_enum, default_value_t = OutputMode::Text)]
        output: OutputMode,
    }

    for a in app.get_subcommands_mut() {
        *a = DerivedArgs::augment_args(a.clone())
    }

    let matches = app.try_get_matches_from(args)?;

    let base = BaseCosmoCliOpts::from_arg_matches(&matches)?;

    let output_mode = match matches.subcommand() {
        Some((_, matches)) => DerivedArgs::from_arg_matches(&matches)?.output,
        None => unreachable!("Subcommand should be specified"),
    };

    let command = Command::from_arg_matches(&matches)?;

    Ok(CosmoCliOpts {
        api_server: base.api_server,
        log_level_filter: base.verbose.log_level_filter(),
        output_mode,
        command,
    })
}

fn show_backtrace() -> bool {
    if log::max_level() > log::LevelFilter::Info {
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

pub fn print_cmd_output<T: CommandOutput + ?Sized>(cmd_output: &T, mode: OutputMode) {
    let output = match mode {
        OutputMode::Text => cmd_output.text(),
        OutputMode::Json => cmd_output.json(),
    };
    println!("{output}")
}

pub trait CommandOutput {
    fn text(&self) -> String;
    fn json(&self) -> String;
}

impl CommandOutput for &str {
    fn text(&self) -> String {
        self.to_string()
    }

    fn json(&self) -> String {
        serde_json::json!({
            "msg": self,
        })
        .to_string()
    }
}

impl CommandOutput for String {
    fn text(&self) -> String {
        self.to_owned()
    }

    fn json(&self) -> String {
        serde_json::json!({
            "msg": self,
        })
        .to_string()
    }
}

impl CommandOutput for () {
    fn text(&self) -> String {
        String::new()
    }

    fn json(&self) -> String {
        String::new()
    }
}

#[derive(Debug, Clone, ArgEnum)]
pub enum ApiKeyAction {
    List,
    Create,
    Delete,
}

#[derive(Debug, Clone, ArgEnum)]
pub enum Analysis {
    // Linux/Container Analysis
    Hardening,
    CveCheck,
    SecurityScan,
    PasswordHash,
    Crypto,
    Nvram,
    Kernel,
    SoftwareBOM,
    StaticCode,
    // UEFI Analysis
    Access,
    IntelBootGuard,
    Surface,
    SecureBoot,
    UefiSecurityScan,
    PeimDxe,
    // Vxworks Analysis
    Functions,
    Symbols,
    Tasks,
    Capabilities,
}

impl fmt::Display for Analysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Analysis::Hardening => "Hardening",
            Analysis::CveCheck => "CveCheck",
            Analysis::SecurityScan => "SecurityScan",
            Analysis::PasswordHash => "PasswordHash",
            Analysis::Crypto => "Crypto",
            Analysis::Nvram => "Nvram",
            Analysis::Kernel => "Kernel",
            Analysis::SoftwareBOM => "SoftwareBOM",
            Analysis::StaticCode => "StaticCode",
            Analysis::Access => "Access",
            Analysis::IntelBootGuard => "IntelBootGuard",
            Analysis::Surface => "Surface",
            Analysis::SecureBoot => "SecureBoot",
            Analysis::UefiSecurityScan => "UefiSecurityScan",
            Analysis::PeimDxe => "PeimDxe",
            Analysis::Functions => "Functions",
            Analysis::Symbols => "Symbols",
            Analysis::Tasks => "Tasks",
            Analysis::Capabilities => "Capabilities",
        };

        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Create project
    #[clap(visible_alias = "new")]
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
        #[clap(
            short = 's',
            long = "subtype",
            value_name = "SUBTYPE",
            default_value_t = String::from("generic")
        )]
        fw_subtype: String,
    },
    /// List all projects
    #[clap(visible_alias = "ls")]
    List,
    /// Login to Cosmo
    Login,
    /// Logout
    Logout,
    /// Project overview
    #[clap(visible_alias = "show")]
    Overview {
        /// ID of the project
        #[clap(short = 'i', long = "id")]
        project_id: Uuid,
    },
    /// Project analysis result
    #[clap(visible_alias = "an")]
    Analysis {
        /// ID of the project
        #[clap(short = 'i', long = "id")]
        project_id: Uuid,
        /// Analysis name
        #[clap(short, long, arg_enum)]
        analysis: Analysis,
        /// Page number
        #[clap(short = 'p', long, default_value_t = 0)]
        page: i32,
        /// Per page results
        #[clap(short = 'l', long, default_value_t = 10)]
        per_page: i32,
    },
    /// Delete a project
    #[clap(visible_alias = "rm")]
    Delete {
        /// ID of the project
        #[clap(short = 'i', long = "id")]
        project_id: Uuid,
    },
    /// Project report
    Report {
        /// ID of the project
        #[clap(short = 'i', long = "id")]
        project_id: Uuid,
        /// Path to download PDF report path
        #[clap(short = 'f', long = "file")]
        savepath: String, //TODO: default format!("/tmp/{}.pdf", project_id).as_str() - change with a directory instead of file
    },
    /// Manage API key
    Apikey {
        /// Action to perform
        #[clap(short, long, arg_enum)]
        action: ApiKeyAction,
    },
}
