use std::{error::Error, fs::File, path::Path};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::services::GenericError;

use super::super::ApiServer;
use term_table::{row::Row, table_cell::TableCell, Table, TableStyle};

pub const FILE_SIZE_LIMIT: usize = 104857600; // 100 Mb

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
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("ID"),
            TableCell::new("DESCRIPTION"),
            TableCell::new("ORIGINAL NAME"),
            TableCell::new("SCORE"),
            TableCell::new("TYPE"),
            TableCell::new("SUNTYPE"),
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
    kernel: String,
    kernelc: String,
    libc: String,
}

#[derive(Debug, Deserialize)]
pub struct LinuxProjectOverviewCveCheck {
    severity: LinuxProjectOverviewSeverity,
}

#[derive(Debug, Deserialize)]
pub struct LinuxProjectOverviewCode {
    vunerabilities: u16,
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

#[derive(Debug, Deserialize)]
pub struct LinuxCveCheckAnalysis {
    product: String,
    cveid: String,
    severity: String,
    patch: String,
}

#[derive(Debug, Deserialize)]
pub struct LinuxSecurityScanAnalysis {
    filename: String,
    r#type: Vec<String>,
    desc: String,
}

#[derive(Debug, Deserialize)]
pub struct LinuxPasswordHashAnalysis {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
pub struct LinuxCryptoAnalysis {
    filename: String,
    r#type: String,
    subtype: String,
    pubsz: u16,
}

#[derive(Debug, Deserialize)]
pub struct LinuxNvramAnalysis {
    exe: String,
    fun: String,
    name: String,
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

#[derive(Debug, Deserialize)]
pub struct LinuxKernelAnalysis {
    name: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct LinuxSoftwareBOMAnalysis {
    filename: String,
    license: Option<String>,
    occurrences: u16,
    resolve: String,
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

#[derive(Debug, Deserialize)]
pub struct UefiIntelBootGuard {
    acm: String,
    rsa: Vec<UefiIntelBootGuardRsa>,
}

#[derive(Debug, Deserialize)]
pub struct UefiIntelBootGuardRsa {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
pub struct UefiSurface {
    name: String,
    r#type: String,
    value: String,
    guid: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct UefiSecureBoot {
    certs: UefiSecureBootCerts,
    databases: UefiSecureBootDatabases,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct UefiSecureBootCerts {
    kek: Vec<UefiSecureBootData>,
    pk: UefiSecureBootData,
}

#[derive(Debug, Deserialize)]
pub struct UefiSecureBootDatabases {
    certs: UefiSecureBootDatabasesData,
    hashes: UefiSecureBootDatabasesData,
}

#[derive(Debug, Deserialize)]
pub struct UefiSecureBootDatabasesData {
    db: Vec<UefiSecureBootData>,
    dbx: Vec<UefiSecureBootData>,
}

#[derive(Debug, Deserialize)]
pub struct UefiSecureBootData {
    first: String,
    second: String,
}

#[derive(Debug, Deserialize)]
pub struct UefiSecurityScan {
    guid: Uuid,
    module: String,
    name: String,
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
/////////////////////////////////////////////////////////////////////
// TODO : no dyn error
// List projects in personal workspace
pub async fn list_projects<U: ApiServer>(
    api_server: &mut U,
) -> Result<Vec<Project>, Box<dyn Error>> {
    let projects = api_server.list_projects().await?;
    Ok(projects)
}

// TODO : no dyn error
// Project overview
pub async fn overview<U: ApiServer>(
    api_server: &mut U,
    project_id: Uuid,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let overview = api_server.overview(&project_id).await?;
    Ok(overview)
}

// TODO : no dyn error
// Analysis result
pub async fn analysis<U: ApiServer>(
    api_server: &mut U,
    project_id: Uuid,
    analysis: &str,
) -> Result<ProjectAnalysis, Box<dyn Error>> {
    let res = api_server.analysis(&project_id, analysis).await?;
    Ok(res)
}

// TODO : no dyn error
// Delete a project
pub async fn delete<U: ApiServer>(
    api_server: &mut U,
    project_id: Uuid,
) -> Result<(), Box<dyn Error>> {
    api_server.delete(&project_id).await?;
    Ok(())
}

// TODO : no dyn error
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
