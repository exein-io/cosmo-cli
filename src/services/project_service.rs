use std::{error::Error, fs::File, path::Path};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::services::GenericError;

use super::super::ApiServer;
use term_table::{
    row::Row,
    table_cell::{Alignment, TableCell},
    Table, TableStyle,
};

pub const FILE_SIZE_LIMIT: usize = 536870912; // 512 Mb

#[derive(Deserialize, Debug)]
pub struct ProjectIdDTO {
    pub id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct Project {
    description: Option<String>,
    id: Uuid,
    name: String,
    original_name: String,
    score: f32,
    workspace_id: Uuid,
    project_type: String,
    project_subtype: String,
    creation_date: DateTime<Utc>,
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
            TableCell::new("SCORE"),
            TableCell::new("TYPE"),
            TableCell::new("SUBTYPE"),
        ]));

        let rows: Vec<Row> = list
            .into_iter()
            .map(|project| {
                let desc = project
                    .description
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.id),
                    TableCell::new(desc),
                    TableCell::new(&project.original_name),
                    TableCell::new(&project.score),
                    TableCell::new(&project.project_type),
                    TableCell::new(&project.project_subtype),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

// Linux/Container Analysis
#[derive(Debug, Deserialize)]
pub struct LinuxProjectOverview {
    kernel_security: Option<u16>,
    password_hash: u16,
    security_scan: u16,
    cve_check: LinuxProjectOverviewCveCheck,
    code: LinuxProjectOverviewCode,
    binary: LinuxProjectOverviewBinary,
    project: Project,
    info: LinuxInfo,
}

#[derive(Debug, Deserialize)]
pub struct LinuxInfo {
    arch: String,
    banner: Option<String>,
    kernel: Option<String>,
    kernelc: Option<String>,
    libc: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LinuxProjectOverviewCveCheck {
    severity: LinuxProjectOverviewSeverity,
}

#[derive(Debug, Deserialize)]
pub struct LinuxProjectOverviewCode {
    vulnerabilities: u16,
    files_affected: u16,
}

#[derive(Debug, Deserialize)]
pub struct LinuxProjectOverviewBinary {
    severity: LinuxProjectOverviewSeverity,
}

#[derive(Debug, Deserialize)]
pub struct LinuxProjectOverviewSeverity {
    low: u16,
    medium: u16,
    high: u16,
}

#[derive(Debug, Deserialize)]
pub struct ProjectAnalysis {
    pub(crate) name: String,
    pub(crate) fw_type: String,
    pub(crate) error: Option<String>,
    pub(crate) result: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct LinuxHardeningAnalysis {
    filename: String,
    r#type: String,
    score: u8,
    compiler: Option<String>,
    stripped: bool,
    suid: bool,
    execstack: bool,
    canary: bool,
    fortify: bool,
    nx: bool,
    pie: String,
    relro: String,
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
            .into_iter()
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
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

#[derive(Debug, Deserialize)]
pub struct LinuxCveCheckAnalysis {
    product: String,
    cveid: String,
    severity: String,
    patch: Option<String>,
}

impl LinuxCveCheckAnalysis {
    pub fn get_table_from_list(list: &[LinuxCveCheckAnalysis]) -> String {
        let mut table = Table::new();
        table.style = TableStyle::simple();
        table.max_column_width = 30;
        table.add_row(Row::new(vec![
            TableCell::new("PRODUCT"),
            TableCell::new("CVE ID"),
            TableCell::new("SEVERITY"),
        ]));

        let rows: Vec<Row> = list
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.product),
                    TableCell::new(&project.cveid),
                    TableCell::new(&project.severity),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

#[derive(Debug, Deserialize)]
pub struct LinuxSecurityScanAnalysis {
    filename: String,
    r#type: Vec<String>,
    desc: String,
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.filename),
                    TableCell::new(&project.desc),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

#[derive(Debug, Deserialize)]
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.username),
                    TableCell::new(&project.password),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

#[derive(Debug, Deserialize)]
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.filename),
                    TableCell::new(&project.r#type),
                    TableCell::new(&project.subtype),
                    TableCell::new(&project.pubsz),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

#[derive(Debug, Deserialize)]
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.exe),
                    TableCell::new(&project.fun),
                    TableCell::new(&project.name),
                ]
            })
            .map(|rtc| Row::new(rtc))
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

#[derive(Debug)]
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.filename),
                    TableCell::new(&project.line),
                    TableCell::new(&project.descr),
                    TableCell::new(&project.flaw_type),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

#[derive(Debug, Deserialize)]
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.enabled),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

#[derive(Debug, Deserialize)]
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
            .into_iter()
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
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

// UEFI Analysis

#[derive(Debug, Deserialize)]
pub struct UefiProjectOverview {
    info: UefiInfo,
    project: Project,
}

#[derive(Debug, Deserialize)]
pub struct UefiInfo {
    dxe_no: u32,
    pei_no: u32,
    manufacturer: String,
    s3mit: String,
}

#[derive(Debug, Deserialize)]
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.region),
                    TableCell::new(&project.read),
                    TableCell::new(&project.write),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

#[derive(Debug, Deserialize)]
pub struct UefiIntelBootGuard {
    pub(crate) acm: String,
    pub(crate) rsa: Vec<UefiIntelBootGuardRsa>,
}

#[derive(Debug, Deserialize)]
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.value),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

#[derive(Debug, Deserialize)]
pub struct UefiSurface {
    name: String,
    r#type: String,
    value: String,
    guid: Uuid,
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.r#type),
                    TableCell::new(&project.guid),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

#[derive(Debug, Deserialize)]
pub struct UefiSecureBoot {
    pub(crate) certs: UefiSecureBootCerts,
    pub(crate) databases: UefiSecureBootDatabases,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct UefiSecureBootCerts {
    pub(crate) kek: Vec<UefiSecureBootData>,
    pub(crate) pk: UefiSecureBootData,
}

impl UefiSecureBootCerts {
    pub fn get_table_from_list(list: &[UefiSecureBootData], db: &str) -> String {
        let table = UefiSecureBootData::get_table_from_list(&list, db);
        table.render()
    }
}

#[derive(Debug, Deserialize)]
pub struct UefiSecureBootDatabases {
    pub(crate) certs: UefiSecureBootDatabasesData,
    pub(crate) hashes: UefiSecureBootDatabasesData,
}

#[derive(Debug, Deserialize)]
pub struct UefiSecureBootDatabasesData {
    pub(crate) db: Vec<UefiSecureBootData>,
    pub(crate) dbx: Vec<UefiSecureBootData>,
}

#[derive(Debug, Deserialize)]
pub struct UefiSecureBootData {
    first: String,
    second: String,
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(db),
                    TableCell::new(&project.first),
                    TableCell::new(&project.second),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table
        //table.render()
    }
}

#[derive(Debug, Deserialize)]
pub struct UefiSecurityScan {
    guid: Uuid,
    module: String,
    name: String,
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.module),
                    TableCell::new(&project.guid),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.render()
    }
}

#[derive(Debug, Deserialize)]
pub struct UefiPeimDxe {
    name: String,
    filetype: String,
    format: String,
    machine: String,
    r#type: String,
    sign: Option<bool>,
    dependencies: Option<Vec<String>>,
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.filetype),
                    TableCell::new(&project.format),
                    TableCell::new(&project.machine),
                    TableCell::new(&project.r#type),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.render()
    }
}

// VxWorks Analysis

#[derive(Debug, Deserialize)]
pub struct VxworksProjectOverview {
    info: VxworksInfo,
    project: Project,
}

#[derive(Debug, Deserialize)]
pub struct VxworksInfo {
    functions_no: u32,
    symbols_no: u32,
    tasks_no: u32,
    word_size: u32,
    arch: String,
    endianness: String,
    kernel: Option<String>,
    capabilities: Option<serde_json::Value>,
    os: String,
}

#[derive(Debug, Deserialize)]
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.offset),
                    TableCell::new(&project.size),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.render()
    }
}

#[derive(Debug, Deserialize)]
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.task_name),
                    TableCell::new(&project.task_addr),
                    TableCell::new(&project.fcn_name),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.render()
    }
}

#[derive(Debug, Deserialize)]
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
            .into_iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.caps.join(", ")),
                ]
            })
            .map(|rtc| Row::new(rtc))
            .collect();

        for row in rows {
            table.add_row(row);
        }
        table.render()
    }
}

// List projects in personal workspace
pub async fn list_projects<U: ApiServer>(
    api_server: &mut U,
) -> Result<Vec<Project>, Box<dyn Error>> {
    let projects = api_server.list_projects().await?;
    Ok(projects)
}

// Project overview
pub async fn overview<U: ApiServer>(
    api_server: &mut U,
    project_id: Uuid,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let overview = api_server.overview(&project_id).await?;
    Ok(overview)
}

// Project overview
pub async fn report<U: ApiServer>(
    api_server: &mut U,
    project_id: Uuid,
    savepath: String,
) -> Result<String, Box<dyn Error>> {
    let report_path = Path::new(&savepath);

    if report_path.exists() {
        Err(GenericError(format!(
            "File {} already exists",
            report_path.display()
        )))?;
    }
    api_server.report(&project_id, &report_path).await?;

    Ok(savepath)
}

// Analysis result
pub async fn analysis<U: ApiServer>(
    api_server: &mut U,
    project_id: Uuid,
    analysis: &str,
    page: &str,
    per_page: &str,
) -> Result<ProjectAnalysis, Box<dyn Error>> {
    let res = api_server
        .analysis(&project_id, analysis, page, per_page)
        .await?;
    Ok(res)
}

// Delete a project
pub async fn delete<U: ApiServer>(
    api_server: &mut U,
    project_id: Uuid,
) -> Result<(), Box<dyn Error>> {
    api_server.delete(&project_id).await?;
    Ok(())
}

// Create a new project
pub async fn create<U: ApiServer>(
    fw_filepath: &str,
    fw_type: &str,
    fw_subtype: &str,
    name: &str,
    description: Option<&str>,
    api_server: &mut U,
) -> Result<Uuid, Box<dyn Error>> {
    let fw_file = Path::new(fw_filepath);

    if !fw_file.exists() {
        return Err(Box::new(GenericError(format!(
            "File not exists: {}",
            fw_filepath
        ))));
    }

    if !fw_file.is_file() {
        return Err(Box::new(GenericError(format!(
            "Not a file: {}",
            fw_filepath
        ))));
    }

    let fw_file = File::open(fw_file)
        .map_err(|_| GenericError(format!("Error opening file {}", fw_filepath)))?;

    let fw_file_metadata = fw_file
        .metadata()
        .map_err(|_| GenericError(format!("Error accessing file metadata {}", fw_filepath)))?;

    if fw_file_metadata.len() as usize > FILE_SIZE_LIMIT {
        return Err(Box::new(GenericError(format!(
            "File size exceeds maximum file size of {} bytes",
            FILE_SIZE_LIMIT
        ))));
    }

    let model_id = api_server
        .create(fw_filepath, fw_type, fw_subtype, name, description)
        .await?;

    Ok(model_id)
}
