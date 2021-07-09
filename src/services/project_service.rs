use std::{error::Error, fs::File, path::Path};

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

// WIP
#[derive(Debug, Deserialize)]
pub struct LinuxProjectOverview {
    kernel_security: u16,
    password_hash: u16,
    security_scan: u16,
    cve_check: LinuxProjectOverviewCveCheck,
    code: LinuxProjectOverviewCode,
    binary: LinuxProjectOverviewBinary,
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

/////////////////////////////////////////////////////////////////////7
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
