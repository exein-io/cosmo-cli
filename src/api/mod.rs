use crate::{
    project_service::Project,
    security::{AuthData, AuthError},
};
use async_trait::async_trait;
use semver::Version;
use serde::Deserialize;
use std::fmt::Display;
use uuid::Uuid;

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
    AuthenticationError(AuthError),
}

impl From<AuthError> for ApiServerError {
    fn from(err: AuthError) -> Self {
        Self::AuthenticationError(err)
    }
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
            Self::AuthenticationError(err) => write!(f, "{}", err),
        }
    }
}
impl std::error::Error for ApiServerError {}

#[async_trait(?Send)]
pub trait ApiServer {
    async fn authenticate(&mut self) -> Result<AuthData, AuthError>;
    async fn updates_check(&self) -> Result<LatestCliVersion, ApiServerError>;
    async fn create(
        &mut self,
        fw_filepath: &str,
        fw_type: &str,
        fw_subtype: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<Uuid, ApiServerError>;
    async fn overview(&mut self, project_id: &Uuid) -> Result<serde_json::Value, ApiServerError>;
    async fn list_projects(&mut self) -> Result<Vec<Project>, ApiServerError>;
    async fn logout(&mut self) -> Result<(), AuthError>;
}
