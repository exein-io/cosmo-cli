use std::{fs::File, path::Path};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use term_table::{
    row::Row,
    table_cell::{Alignment, TableCell},
    Table, TableStyle,
};
use uuid::Uuid;

use crate::{api::ApiServer, cli::Analysis};

pub const FILE_SIZE_LIMIT: usize = 536870912; // 512 Mb

#[derive(Deserialize, Debug)]
pub struct ProjectIdDTO {
    pub id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Project {
    pub description: Option<String>,
    pub id: Uuid,
    pub name: String,
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
        table.style = TableStyle::simple();
        table.max_column_width = 40;
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("ID"),
            TableCell::new("DESCRIPTION"),
            TableCell::new("ORIGINAL NAME"),
            TableCell::new("ORGANIZATION NAME"),
            TableCell::new("SCORE"),
            TableCell::new("TYPE"),
            TableCell::new("SUBTYPE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                let desc = project
                    .description
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let org = project
                    .organization_name
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.id),
                    TableCell::new(desc),
                    TableCell::new(&project.original_name),
                    TableCell::new(org),
                    TableCell::new(&project.score),
                    TableCell::new(&project.project_type),
                    TableCell::new(&project.project_subtype),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
        table.max_column_width = 50;
        table.style = TableStyle::simple();
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new_with_alignment("HARDENING", 8, Alignment::Center),
            TableCell::new("SCORE"),
        ]));
        table.add_row(Row::new(vec![
            TableCell::new(""),
            TableCell::new("CANARY"),
            TableCell::new("FORTIFY"),
            TableCell::new("NX"),
            TableCell::new("PIE"),
            TableCell::new("RELRO"),
            TableCell::new("EXEC STACK"),
            TableCell::new("SUID"),
            TableCell::new("STRIPPED"),
            TableCell::new(""),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.filename),
                    TableCell::new(&project.canary),
                    TableCell::new(&project.fortify),
                    TableCell::new(&project.nx),
                    TableCell::new(&project.pie),
                    TableCell::new(&project.relro),
                    TableCell::new(&project.execstack),
                    TableCell::new(&project.suid),
                    TableCell::new(&project.stripped),
                    TableCell::new(&project.score),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
}

impl LinuxCveCheckAnalysis {
    pub fn get_table_from_list(list: &[LinuxCveCheckAnalysis]) -> String {
        let mut table = Table::new();
        table.style = TableStyle::simple();
        table.max_column_width = 30;
        table.add_row(Row::new(vec![
            TableCell::new("PRODUCT"),
            TableCell::new("VERSION"),
            TableCell::new("CVE ID"),
            TableCell::new("SEVERITY"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.product),
                    TableCell::new(&project.version),
                    TableCell::new(&project.cveid),
                    TableCell::new(&project.severity),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
        table.style = TableStyle::simple();
        table.max_column_width = 30;
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("DESCRIPTION"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.filename),
                    TableCell::new(&project.desc),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
        table.style = TableStyle::simple();
        table.max_column_width = 30;
        table.add_row(Row::new(vec![
            TableCell::new("USERNAME"),
            TableCell::new("PASSWORD"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.username),
                    TableCell::new(&project.password),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
        table.style = TableStyle::simple();
        table.max_column_width = 30;
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("TYPE"),
            TableCell::new("SUBTYPE"),
            TableCell::new("SIZE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.filename),
                    TableCell::new(&project.r#type),
                    TableCell::new(&project.subtype),
                    TableCell::new(&project.pubsz),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
        table.style = TableStyle::simple();
        table.max_column_width = 30;
        table.add_row(Row::new(vec![
            TableCell::new("EXECUTABLE NAME"),
            TableCell::new("FUNCTION TYPE"),
            TableCell::new("NVRAM NAME"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.exe),
                    TableCell::new(&project.fun),
                    TableCell::new(&project.name),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
        table.style = TableStyle::simple();
        table.max_column_width = 30;
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("LINE"),
            TableCell::new("DESCRIPTION"),
            TableCell::new("FLAW TYPE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.filename),
                    TableCell::new(&project.line),
                    TableCell::new(&project.descr),
                    TableCell::new(&project.flaw_type),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
        table.style = TableStyle::simple();
        table.add_row(Row::new(vec![
            TableCell::new("FEATURE"),
            TableCell::new("ENABLED"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.enabled),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
        table.style = TableStyle::simple();
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("RESOLVE TO"),
            TableCell::new("OCCURENCES"),
            TableCell::new("LICENSE"),
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
                    TableCell::new(&project.filename),
                    TableCell::new(&project.resolve),
                    TableCell::new(&project.occurrences),
                    TableCell::new(lic),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
    pub env: Option<String>,
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

        format!("Name: {}\nVersion: {}\nArchitecture: {}", name, version, arch)
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
        table.style = TableStyle::simple();
        table.max_column_width = 30;
        table.add_row(Row::new(vec![
            TableCell::new("REGION"),
            TableCell::new("READ"),
            TableCell::new("WRITE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.region),
                    TableCell::new(&project.read),
                    TableCell::new(&project.write),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
        table.style = TableStyle::simple();
        table.max_column_width = 70;
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("VALUE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.value),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
        table.style = TableStyle::simple();
        table.max_column_width = 40;
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("TYPE"),
            TableCell::new("GUID"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.r#type),
                    TableCell::new(&project.guid),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
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
        table.render()
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
    pub fn get_table_from_list<'a>(list: &'a [UefiSecureBootData], db: &'a str) -> Table<'a> {
        let mut table = Table::new();
        table.style = TableStyle::simple();
        table.max_column_width = 50;
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("ISSUED BY"),
            TableCell::new("ISSUED TO"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(db),
                    TableCell::new(&project.first),
                    TableCell::new(&project.second),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table
        //table.render()
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
        table.style = TableStyle::simple();
        table.max_column_width = 50;
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("MODULE"),
            TableCell::new("GUID"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.module),
                    TableCell::new(&project.guid),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.render()
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
        table.style = TableStyle::simple();
        table.max_column_width = 50;
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("FILETYPE"),
            TableCell::new("FORMAT"),
            TableCell::new("MACHINE"),
            TableCell::new("TYPE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.filetype),
                    TableCell::new(&project.format),
                    TableCell::new(&project.machine),
                    TableCell::new(&project.r#type),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.render()
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
        table.style = TableStyle::simple();
        table.max_column_width = 50;
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("OFFSET"),
            TableCell::new("SIZE"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.offset),
                    TableCell::new(&project.size),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.render()
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
        table.style = TableStyle::simple();
        table.max_column_width = 50;
        table.add_row(Row::new(vec![
            TableCell::new("TASK NAME"),
            TableCell::new("TASK ADDRESS"),
            TableCell::new("FUNCTION NAME"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.task_name),
                    TableCell::new(&project.task_addr),
                    TableCell::new(&project.fcn_name),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.render()
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
        table.style = TableStyle::simple();
        table.max_column_width = 50;
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("CAPABILITIES"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.caps.join(", ")),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.render()
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
