use async_trait::async_trait;
use semver::Version;
use serde::Deserialize;
use std::{fmt::Display, path::Path};
use uuid::Uuid;

use crate::{
    cli::Analysis,
    services::{
        apikey_service::ApiKeyData,
        organization_service::OrganizationData,
        project_service::{Project, ProjectAnalysis},
    },
};

mod http_server;

pub use http_server::HttpApiServer;

#[derive(Debug, Deserialize)]
pub struct LatestCliVersion {
    pub version: Version,
    pub changelog: String,
}

#[derive(Debug)]
pub enum ApiServerError {
    HttpRequestError(reqwest::Error),
    RequestError(String),
    ResponseError(String),
    ApiError(String),
}

impl From<reqwest::Error> for ApiServerError {
    fn from(err: reqwest::Error) -> Self {
        Self::HttpRequestError(err)
    }
}

impl Display for ApiServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiError(response) => write!(f, "Error from server: {}", response),
            Self::HttpRequestError(err) => {
                write!(f, "Error with http request. Reason: {}", err)
            }
            Self::RequestError(err) => write!(f, "Error with the request: {}", err),
            Self::ResponseError(err) => write!(f, "Error with the response: {}", err),
        }
    }
}
impl std::error::Error for ApiServerError {}

#[async_trait]
pub trait ApiServer {
    fn address(&self) -> &str;
    async fn updates_check(&self) -> Result<LatestCliVersion, ApiServerError>;
    async fn create(
        &mut self,
        fw_filepath: &str,
        fw_type: &str,
        fw_subtype: &str,
        name: &str,
        description: Option<&str>,
        organization: Option<&str>,
    ) -> Result<Uuid, ApiServerError>;
    async fn overview(&mut self, project_id: &Uuid) -> Result<serde_json::Value, ApiServerError>;
    async fn analysis(
        &mut self,
        project_id: &Uuid,
        analysis: &Analysis,
        page: i32,
        per_page: i32,
    ) -> Result<ProjectAnalysis, ApiServerError>;
    async fn delete(&mut self, project_id: &Uuid) -> Result<(), ApiServerError>;
    async fn report(&mut self, project_id: &Uuid, savepath: &Path) -> Result<(), ApiServerError>;
    async fn list_projects(&mut self) -> Result<Vec<Project>, ApiServerError>;
    async fn organization_create(
        &mut self,
        name: &str,
        description: &str,
    ) -> Result<(), ApiServerError>;
    async fn organization_list(&mut self) -> Result<Vec<OrganizationData>, ApiServerError>;
    async fn organization_delete(&mut self, id: &Uuid) -> Result<(), ApiServerError>;
    async fn apikey_create(&mut self) -> Result<ApiKeyData, ApiServerError>;
    async fn apikey_list(&mut self) -> Result<Option<ApiKeyData>, ApiServerError>;
    async fn apikey_delete(&mut self) -> Result<(), ApiServerError>;
}
