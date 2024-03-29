use std::{fs::File, path::Path};

use anyhow::{anyhow, Result};
use comfy_table::{Cell, CellAlignment, Row, Table};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{api::ApiServer, cli::Analysis};

pub const FILE_SIZE_LIMIT: usize = 2147483648; // 2 Gb
pub const CVE_DETAILS_BASE_URL: &str = "https://nvd.nist.gov/vuln/detail/";

#[derive(Deserialize, Debug)]
pub struct ProjectIdDTO {
    pub id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Project {
    pub description: Option<String>,
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub original_name: String,
    pub organization_name: Option<String>,
    pub score: f32,
    pub project_type: String,
    pub project_subtype: String,
    pub creation_date: String,
}

impl Project {
    pub fn get_table_from_list(list: &[Project]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 40;
        table.add_row(Row::from(vec![
            Cell::new("NAME"),
            Cell::new("ID"),
            Cell::new("DESCRIPTION"),
            Cell::new("ORIGINAL NAME"),
            Cell::new("SCORE"),
            Cell::new("TYPE"),
            Cell::new("SUBTYPE"),
            Cell::new("STATUS"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                let desc = project
                    .description
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                vec![
                    Cell::new(&project.name),
                    Cell::new(project.id),
                    Cell::new(desc),
                    Cell::new(&project.original_name),
                    Cell::new(project.score),
                    Cell::new(&project.project_type),
                    Cell::new(&project.project_subtype),
                    Cell::new(&project.status),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

// Linux/Container Analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxProjectOverview {
    pub kernel_security: Option<u16>,
    pub password_hash: u16,
    pub security_scan: u16,
    pub cve_check: LinuxProjectOverviewCveCheck,
    pub code: LinuxProjectOverviewCode,
    pub binary: LinuxProjectOverviewBinary,
    // pub project: Project,
    pub info: LinuxInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxInfo {
    pub arch: String,
    pub banner: Option<String>,
    pub kernel: Option<String>,
    pub kernelc: Option<String>,
    pub libc: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxProjectOverviewCveCheck {
    pub severity: LinuxProjectOverviewSeverity,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxProjectOverviewCode {
    pub vulnerabilities: u16,
    pub files_affected: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxProjectOverviewBinary {
    pub severity: LinuxProjectOverviewSeverity,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxProjectOverviewSeverity {
    pub low: u16,
    pub medium: u16,
    pub high: u16,
}

impl LinuxProjectOverview {
    pub fn get_text_output(project: &LinuxProjectOverview) -> String {
        let banner = project
            .info
            .banner
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_default();
        let kernel = project
            .info
            .kernel
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_default();
        let kernelc = project
            .info
            .kernelc
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_default();
        let libc = project
            .info
            .libc
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_default();
        let arch = &project.info.arch;

        format!(
            "Architecture: {}\nBanner: {}\nLib C: {}\nKernel version: {}\nKernel compiler: {}",
            arch, banner, libc, kernel, kernelc
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectAnalysis {
    pub(crate) name: String,
    pub(crate) fw_type: String,
    pub(crate) error: Option<String>,
    pub(crate) result: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxHardeningAnalysis {
    pub filename: String,
    pub r#type: String,
    pub score: u8,
    pub compiler: Option<String>,
    pub stripped: bool,
    pub suid: bool,
    pub execstack: bool,
    pub canary: bool,
    pub fortify: bool,
    pub nx: bool,
    pub pie: String,
    pub relro: String,
}

impl LinuxHardeningAnalysis {
    pub fn get_table_from_list(list: &[LinuxHardeningAnalysis]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 50;
        table.add_row(Row::from(vec![
            Cell::new("NAME"),
            Cell::new("HARDENING").set_alignment(CellAlignment::Center),
            Cell::new("SCORE"),
        ]));
        table.add_row(Row::from(vec![
            Cell::new(""),
            Cell::new("CANARY"),
            Cell::new("FORTIFY"),
            Cell::new("NX"),
            Cell::new("PIE"),
            Cell::new("RELRO"),
            Cell::new("EXEC STACK"),
            Cell::new("SUID"),
            Cell::new("STRIPPED"),
            Cell::new(""),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    Cell::new(&project.filename),
                    Cell::new(project.canary),
                    Cell::new(project.fortify),
                    Cell::new(project.nx),
                    Cell::new(&project.pie),
                    Cell::new(&project.relro),
                    Cell::new(project.execstack),
                    Cell::new(project.suid),
                    Cell::new(project.stripped),
                    Cell::new(project.score),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxCveCheckAnalysis {
    pub cveid: String,
    pub severity: String,
    pub summary: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub vector: String,
    pub patch: Option<String>,
    pub references: Option<String>,
    pub cvss: Option<serde_json::Value>,
    pub problems: Option<serde_json::Value>,
    pub published_date: Option<String>,
}

impl LinuxCveCheckAnalysis {
    pub fn get_table_from_list(list: &[LinuxCveCheckAnalysis]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 30;
        // table.set_max_width_for_column(4, 50);
        table.add_row(Row::from(vec![
            Cell::new("PRODUCT"),
            Cell::new("VERSION"),
            Cell::new("CVE ID"),
            Cell::new("SEVERITY"),
            Cell::new("DETAILS"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    Cell::new(&project.product),
                    Cell::new(&project.version),
                    Cell::new(&project.cveid),
                    Cell::new(&project.severity),
                    Cell::new(format!("{}{}", CVE_DETAILS_BASE_URL, &project.cveid)),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxSecurityScanAnalysis {
    pub filename: String,
    pub r#type: Vec<String>,
    pub desc: String,
}

impl LinuxSecurityScanAnalysis {
    pub fn get_table_from_list(list: &[LinuxSecurityScanAnalysis]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 30;
        table.add_row(Row::from(vec![Cell::new("NAME"), Cell::new("DESCRIPTION")]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| vec![Cell::new(&project.filename), Cell::new(&project.desc)])
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxPasswordHashAnalysis {
    username: String,
    password: String,
}

impl LinuxPasswordHashAnalysis {
    pub fn get_table_from_list(list: &[LinuxPasswordHashAnalysis]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 30;
        table.add_row(Row::from(vec![
            Cell::new("USERNAME"),
            Cell::new("PASSWORD"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| vec![Cell::new(&project.username), Cell::new(&project.password)])
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxCryptoAnalysis {
    filename: String,
    r#type: String,
    subtype: String,
    pubsz: u16,
}

impl LinuxCryptoAnalysis {
    pub fn get_table_from_list(list: &[LinuxCryptoAnalysis]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 30;
        table.add_row(Row::from(vec![
            Cell::new("NAME"),
            Cell::new("TYPE"),
            Cell::new("SUBTYPE"),
            Cell::new("SIZE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    Cell::new(&project.filename),
                    Cell::new(&project.r#type),
                    Cell::new(&project.subtype),
                    Cell::new(project.pubsz),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxNvramAnalysis {
    exe: String,
    fun: String,
    name: String,
}

impl LinuxNvramAnalysis {
    pub fn get_table_from_list(list: &[LinuxNvramAnalysis]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 30;
        table.add_row(Row::from(vec![
            Cell::new("EXECUTABLE NAME"),
            Cell::new("FUNCTION TYPE"),
            Cell::new("NVRAM NAME"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    Cell::new(&project.exe),
                    Cell::new(&project.fun),
                    Cell::new(&project.name),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

#[derive(Debug, Deserialize)]
pub struct LinuxStaticCodeAnalysis {
    pub(crate) filename: String,
    pub(crate) flaws: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct LinuxStaticCodeAnalysisFlaws {
    pub(crate) line: String,
    pub(crate) descr: String,
    pub(crate) flaw_type: String,
}

#[derive(Debug, Serialize)]
pub struct LinuxStaticCode {
    pub(crate) filename: String,
    pub(crate) line: String,
    pub(crate) descr: String,
    pub(crate) flaw_type: String,
}

impl LinuxStaticCode {
    pub fn get_table_from_list(list: &[LinuxStaticCode]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 30;
        table.add_row(Row::from(vec![
            Cell::new("NAME"),
            Cell::new("LINE"),
            Cell::new("DESCRIPTION"),
            Cell::new("FLAW TYPE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    Cell::new(&project.filename),
                    Cell::new(&project.line),
                    Cell::new(&project.descr),
                    Cell::new(&project.flaw_type),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxKernelAnalysis {
    name: String,
    enabled: bool,
}

impl LinuxKernelAnalysis {
    pub fn get_table_from_list(list: &[LinuxKernelAnalysis]) -> String {
        let mut table = Table::new();
        table.add_row(Row::from(vec![Cell::new("FEATURE"), Cell::new("ENABLED")]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| vec![Cell::new(&project.name), Cell::new(project.enabled)])
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxSoftwareBOMAnalysis {
    filename: String,
    license: Option<String>,
    occurrences: u16,
    resolve: String,
}

impl LinuxSoftwareBOMAnalysis {
    pub fn get_table_from_list(list: &[LinuxSoftwareBOMAnalysis]) -> String {
        let mut table = Table::new();
        table.add_row(Row::from(vec![
            Cell::new("NAME"),
            Cell::new("RESOLVE TO"),
            Cell::new("OCCURENCES"),
            Cell::new("LICENSE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                let lic = project
                    .license
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                vec![
                    Cell::new(&project.filename),
                    Cell::new(&project.resolve),
                    Cell::new(project.occurrences),
                    Cell::new(lic),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

// CONTAINER Analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerProjectOverview {
    pub info: ContainerInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub arch: String,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub env: Option<serde_json::Value>,
    pub history: Option<String>,
}

impl ContainerProjectOverview {
    pub fn get_text_output(project: &ContainerProjectOverview) -> String {
        let name = project
            .info
            .os_name
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_default();
        let version = project
            .info
            .os_version
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_default();
        let arch = &project.info.arch;

        format!(
            "Name: {}\nVersion: {}\nArchitecture: {}",
            name, version, arch
        )
    }
}

// UEFI Analysis

#[derive(Debug, Serialize, Deserialize)]
pub struct UefiProjectOverview {
    pub info: UefiInfo,
    // pub project: Project,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UefiInfo {
    pub dxe_no: u32,
    pub pei_no: u32,
    pub manufacturer: String,
    pub s3mit: String,
}

impl UefiProjectOverview {
    pub fn get_text_output(project: &UefiProjectOverview) -> String {
        let manufacturer = &project.info.manufacturer;
        let dxe_no = &project.info.dxe_no;
        let pei_no = &project.info.pei_no;
        let s3mit = &project.info.s3mit;

        format!(
            "Manufacturer: {}\nDXE number: {}\nPEI number: {}\nS3 mitigation: {}",
            manufacturer, dxe_no, pei_no, s3mit
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UefiAccess {
    read: String,
    region: String,
    write: String,
}

impl UefiAccess {
    pub fn get_table_from_list(list: &[UefiAccess]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 30;
        table.add_row(Row::from(vec![
            Cell::new("REGION"),
            Cell::new("READ"),
            Cell::new("WRITE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    Cell::new(&project.region),
                    Cell::new(&project.read),
                    Cell::new(&project.write),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UefiIntelBootGuard {
    pub(crate) acm: String,
    pub(crate) rsa: Vec<UefiIntelBootGuardRsa>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UefiIntelBootGuardRsa {
    name: String,
    value: String,
}

impl UefiIntelBootGuardRsa {
    pub fn get_table_from_list(list: &[UefiIntelBootGuardRsa]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 70;
        table.add_row(Row::from(vec![Cell::new("NAME"), Cell::new("VALUE")]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| vec![Cell::new(&project.name), Cell::new(&project.value)])
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UefiSurface {
    pub name: String,
    pub r#type: String,
    pub value: String,
    pub guid: Uuid,
}

impl UefiSurface {
    pub fn get_table_from_list(list: &[UefiSurface]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 40;
        table.add_row(Row::from(vec![
            Cell::new("NAME"),
            Cell::new("TYPE"),
            Cell::new("GUID"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    Cell::new(&project.name),
                    Cell::new(&project.r#type),
                    Cell::new(project.guid),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UefiSecureBoot {
    pub(crate) certs: UefiSecureBootCerts,
    pub(crate) databases: UefiSecureBootDatabases,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct UefiSecureBootCerts {
    pub(crate) kek: Vec<UefiSecureBootData>,
    pub(crate) pk: UefiSecureBootData,
}

impl UefiSecureBootCerts {
    pub fn get_table_from_list(list: &[UefiSecureBootData], db: &str) -> String {
        let table = UefiSecureBootData::get_table_from_list(list, db);
        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UefiSecureBootDatabases {
    pub certs: UefiSecureBootDatabasesData,
    pub hashes: UefiSecureBootDatabasesData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UefiSecureBootDatabasesData {
    pub db: Vec<UefiSecureBootData>,
    pub dbx: Vec<UefiSecureBootData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UefiSecureBootData {
    pub first: String,
    pub second: String,
}

impl UefiSecureBootData {
    pub fn get_table_from_list(list: &[UefiSecureBootData], db: &str) -> Table {
        let mut table = Table::new();
        // table.max_column_width = 50;
        table.add_row(Row::from(vec![
            Cell::new("NAME"),
            Cell::new("ISSUED BY"),
            Cell::new("ISSUED TO"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    Cell::new(db),
                    Cell::new(&project.first),
                    Cell::new(&project.second),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table
        //table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UefiSecurityScan {
    pub guid: Uuid,
    pub module: String,
    pub name: String,
}

impl UefiSecurityScan {
    pub fn get_table_from_list(list: &[UefiSecurityScan]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 50;
        table.add_row(Row::from(vec![
            Cell::new("NAME"),
            Cell::new("MODULE"),
            Cell::new("GUID"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    Cell::new(&project.name),
                    Cell::new(&project.module),
                    Cell::new(project.guid),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UefiPeimDxe {
    pub name: String,
    pub filetype: String,
    pub format: String,
    pub machine: String,
    pub r#type: String,
    pub sign: Option<bool>,
    pub dependencies: Option<Vec<String>>,
}

impl UefiPeimDxe {
    pub fn get_table_from_list(list: &[UefiPeimDxe]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 50;
        table.add_row(Row::from(vec![
            Cell::new("NAME"),
            Cell::new("FILETYPE"),
            Cell::new("FORMAT"),
            Cell::new("MACHINE"),
            Cell::new("TYPE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    Cell::new(&project.name),
                    Cell::new(&project.filetype),
                    Cell::new(&project.format),
                    Cell::new(&project.machine),
                    Cell::new(&project.r#type),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.to_string()
    }
}

// VxWorks Analysis

#[derive(Debug, Serialize, Deserialize)]
pub struct VxworksProjectOverview {
    pub info: VxworksInfo,
    // pub project: Project,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VxworksInfo {
    pub functions_no: u32,
    pub symbols_no: u32,
    pub tasks_no: u32,
    pub word_size: u32,
    pub arch: String,
    pub endianness: String,
    pub kernel: Option<String>,
    pub capabilities: Option<serde_json::Value>,
    pub os: String,
}

impl VxworksProjectOverview {
    pub fn get_text_output(project: &VxworksProjectOverview) -> String {
        let os = &project.info.os;
        let arch = &project.info.arch;
        let functions_no = &project.info.functions_no;
        let tasks_no = &project.info.tasks_no;
        let symbols_no = &project.info.symbols_no;

        let kernel = project
            .info
            .kernel
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_default();

        format!(
            "Architecture: {}\nOS version: {}\nKernel version: {}\nFunctions: {}\nTasks: {}\nSymbols: {}",
            arch, os, kernel, functions_no, tasks_no, symbols_no
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VxworksData {
    offset: u32,
    size: u32,
    name: String,
}

impl VxworksData {
    pub fn get_table_from_list(list: &[VxworksData]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 50;
        table.add_row(Row::from(vec![
            Cell::new("NAME"),
            Cell::new("OFFSET"),
            Cell::new("SIZE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    Cell::new(&project.name),
                    Cell::new(project.offset),
                    Cell::new(project.size),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VxworksTask {
    task_name: String,
    task_addr: u32,
    fcn_name: String,
}

impl VxworksTask {
    pub fn get_table_from_list(list: &[VxworksTask]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 50;
        table.add_row(Row::from(vec![
            Cell::new("TASK NAME"),
            Cell::new("TASK ADDRESS"),
            Cell::new("FUNCTION NAME"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    Cell::new(&project.task_name),
                    Cell::new(project.task_addr),
                    Cell::new(&project.fcn_name),
                ]
            })
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.to_string()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VxworksCapability {
    name: String,
    caps: Vec<String>,
}

impl VxworksCapability {
    pub fn get_table_from_list(list: &[VxworksCapability]) -> String {
        let mut table = Table::new();
        // table.max_column_width = 50;
        table.add_row(Row::from(vec![
            Cell::new("NAME"),
            Cell::new("CAPABILITIES"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| vec![Cell::new(&project.name), Cell::new(project.caps.join(", "))])
            .map(Row::from)
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.to_string()
    }
}

// List projects in personal workspace
pub async fn list_projects<U: ApiServer>(api_server: &mut U) -> Result<Vec<Project>> {
    let projects = api_server.list_projects().await?;
    Ok(projects)
}

// Project overview
pub async fn overview<U: ApiServer>(
    api_server: &mut U,
    project_id: Uuid,
) -> Result<serde_json::Value> {
    let overview = api_server.overview(&project_id).await?;
    Ok(overview)
}

// Project overview
pub async fn report<U: ApiServer>(
    api_server: &mut U,
    project_id: Uuid,
    savepath: String,
) -> Result<String> {
    let report_path = Path::new(&savepath);

    if report_path.exists() {
        return Err(anyhow!("File {} already exists", report_path.display()));
    }
    api_server.report(&project_id, report_path).await?;

    Ok(savepath)
}

// Analysis result
pub async fn analysis<U: ApiServer>(
    api_server: &mut U,
    project_id: Uuid,
    analysis: &Analysis,
    page: i32,
    per_page: i32,
) -> Result<ProjectAnalysis> {
    let res = api_server
        .analysis(&project_id, analysis, page, per_page)
        .await?;
    Ok(res)
}

// Delete a project
pub async fn delete<U: ApiServer>(api_server: &mut U, project_id: Uuid) -> Result<()> {
    api_server.delete(&project_id).await?;
    Ok(())
}

#[derive(Debug)]
pub struct ProjectCreated {
    pub id: Uuid,
}

// Create a new project
pub async fn create<U: ApiServer>(
    fw_filepath: &str,
    fw_type: &str,
    fw_subtype: &str,
    name: &str,
    description: Option<&str>,
    organization: Option<&str>,
    api_server: &mut U,
) -> Result<ProjectCreated> {
    let fw_file = Path::new(fw_filepath);

    if !fw_file.exists() {
        return Err(anyhow!("File not exists: {}", fw_filepath));
    }

    if !fw_file.is_file() {
        return Err(anyhow!("Not a file: {}", fw_filepath));
    }

    let fw_file = File::open(fw_file).map_err(|_| anyhow!("Error opening file {}", fw_filepath))?;

    let fw_file_metadata = fw_file
        .metadata()
        .map_err(|_| anyhow!("Error accessing file metadata {}", fw_filepath))?;

    if fw_file_metadata.len() as usize > FILE_SIZE_LIMIT {
        return Err(anyhow!(
            "File size exceeds maximum file size of {} bytes",
            FILE_SIZE_LIMIT
        ));
    }

    let project_id = api_server
        .create(
            fw_filepath,
            fw_type,
            fw_subtype,
            name,
            description,
            organization,
        )
        .await?;

    Ok(ProjectCreated { id: project_id })
}
