use async_trait::async_trait;
use lazy_static::lazy_static;
use reqwest::header::USER_AGENT;
use std::{collections::HashMap, fs::File, io::Write, path::Path};
use uuid::Uuid;

use crate::{
    cli::Analysis,
    services::{
        apikey_service::ApiKeyData,
        organization_service::OrganizationData,
        project_service::{Project, ProjectAnalysis, ProjectIdDTO},
    },
};

use super::{ApiServer, ApiServerError, LatestCliVersion};

lazy_static! {
    pub static ref CLI_USER_AGENT: String = format!("ExeinCosmoCLI/{}", crate::version());
}

const X_API_KEY: &str = "X-API-KEY";

const PROJECT_ROUTE_V1: &str = "/api/v1/projects";
const ORGANIZATION_ROUTE_V1: &str = "/api/v1/organizations";
const APIKEY_ROUTE_V1: &str = "/api/v1/api_key";
const UPDATES_ROUTE: &str = "/api/updates_check";

#[derive(Debug)]
pub struct HttpApiServer {
    address: String,
    apikey: String,
}

impl HttpApiServer {
    pub async fn new(address: String, apikey: String) -> Self {
        Self { address, apikey }
    }

    fn request(&self, path: &str, method: reqwest::Method) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.address, path);

        reqwest::Client::new()
            .request(method, &url)
            .header(USER_AGENT, &*CLI_USER_AGENT)
    }

    async fn authenticated_request(
        &mut self,
        path: &str,
        method: reqwest::Method,
        query: Option<&[(&str, &String)]>,
    ) -> Result<reqwest::RequestBuilder, ApiServerError> {
        let req = self
            .request(path, method)
            .query(&query)
            .header(X_API_KEY, &self.apikey);

        Ok(req)
    }
}

#[async_trait]
impl ApiServer for HttpApiServer {
    fn address(&self) -> &str {
        &self.address
    }
    async fn updates_check(&self) -> Result<LatestCliVersion, ApiServerError> {
        let response = self
            .request(UPDATES_ROUTE, reqwest::Method::GET)
            .send()
            .await?;
        let response_status = response.status();

        if response_status == reqwest::StatusCode::OK {
            let latest_version = response.json::<LatestCliVersion>().await?;
            Ok(latest_version)
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    async fn create(
        &mut self,
        fw_filepath: &str,
        fw_type: &str,
        fw_subtype: &str,
        name: &str,
        description: Option<&str>,
        organization: Option<&str>,
    ) -> Result<Uuid, ApiServerError> {
        let path = Path::new(&fw_filepath);
        if !path.exists() || path.is_dir() {
            return Err(ApiServerError::RequestError(format!(
                "File {} not found",
                path.display()
            )));
        }
        let fw_filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                ApiServerError::RequestError(format!(
                    "Problem with image filename: {}",
                    path.display()
                ))
            })?;

        // Prepare the file data
        let bytes = crate::read_bytes_from_file(fw_filepath).unwrap(); //TODO: unwrap?
        let part = reqwest::multipart::Part::bytes(bytes).file_name(fw_filename);

        // Create the form
        let mut form = reqwest::multipart::Form::new()
            .text("name", name.to_string())
            .text("type", fw_type.to_string())
            .text("subtype", fw_subtype.to_string())
            .part("file", part);

        if let Some(descr) = description {
            form = form.text("description", descr.to_string());
        }

        let org_id = match organization {
            Some(o) => o.to_string(),
            None => self
                .organization_list()
                .await?
                .into_iter()
                .find(|s| s.built_in)
                .ok_or_else(|| ApiServerError::RequestError("No organization found".to_string()))?
                .id
                .to_string(),
        };

        let path = format!("{}/{}/projects", ORGANIZATION_ROUTE_V1, org_id).to_string();

        let response = self
            .authenticated_request(&path, reqwest::Method::POST, None)
            .await?
            .multipart(form)
            .send()
            .await?;

        let response_status = response.status();

        if response_status == reqwest::StatusCode::OK {
            let dto = response.json::<ProjectIdDTO>().await?;
            Ok(dto.id)
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    async fn overview(&mut self, project_id: &Uuid) -> Result<serde_json::Value, ApiServerError> {
        let path = format!("{}/{}/overview", PROJECT_ROUTE_V1, project_id).to_string();

        let response = self
            .authenticated_request(&path, reqwest::Method::GET, None)
            .await?
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::OK {
            let overview = response.json().await?;
            Ok(overview)
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    async fn report(&mut self, project_id: &Uuid, savepath: &Path) -> Result<(), ApiServerError> {
        let path = format!("{}/{}/report", PROJECT_ROUTE_V1, project_id).to_string();

        let response = self
            .authenticated_request(&path, reqwest::Method::GET, None)
            .await?
            .send()
            .await?;

        let status = response.status();

        if status == reqwest::StatusCode::OK {
            let bytes = response.bytes().await?;
            let mut f = File::create(&savepath).map_err(|err| {
                ApiServerError::RequestError(format!(
                    "Error creating file to: {}. Reason: {}",
                    savepath.display(),
                    err
                ))
            })?;
            f.write_all(bytes.as_ref()).map_err(|err| {
                ApiServerError::RequestError(format!(
                    "Error writing data to file: {}. Reason: {}",
                    savepath.display(),
                    err
                ))
            })?;
            Ok(())
        } else {
            let body = response.text().await?;

            Err(ApiServerError::ApiError(body))
        }
    }

    async fn analysis(
        &mut self,
        project_id: &Uuid,
        analysis: &Analysis,
        page: i32,
        per_page: i32,
    ) -> Result<ProjectAnalysis, ApiServerError> {
        let path = format!("{}/{}/analysis/{}", PROJECT_ROUTE_V1, project_id, analysis).to_string();
        let query = [
            ("page", &page.to_string()),
            ("per_page", &per_page.to_string()),
        ];
        let response = self
            .authenticated_request(&path, reqwest::Method::GET, Some(&query))
            .await?
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::OK {
            let res = response.json().await?;
            Ok(res)
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    async fn delete(&mut self, project_id: &Uuid) -> Result<(), ApiServerError> {
        let path = format!("{}/{}", PROJECT_ROUTE_V1, project_id).to_string();

        let response = self
            .authenticated_request(&path, reqwest::Method::DELETE, None)
            .await?
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::OK {
            Ok(())
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    async fn list_projects(&mut self) -> Result<Vec<Project>, ApiServerError> {
        let organizations = self.organization_list().await?;

        let mut projects: Vec<Project> = vec![];
        for o in organizations {
            let path = format!("{}/{}/projects", ORGANIZATION_ROUTE_V1, o.id).to_string();

            let response = self
                .authenticated_request(&path, reqwest::Method::GET, None)
                .await?
                .send()
                .await?;

            if response.status() == reqwest::StatusCode::OK {
                let current_projects = response.json::<Vec<Project>>().await?;
                let current_projects = current_projects.into_iter().map(|mut x| {
                    x.organization_name = Some(o.name.clone());
                    x
                });
                projects.extend(current_projects);
            }
        }
        Ok(projects)
    }

    async fn organization_list(&mut self) -> Result<Vec<OrganizationData>, ApiServerError> {
        let response = self
            .authenticated_request(ORGANIZATION_ROUTE_V1, reqwest::Method::GET, None)
            .await?
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::OK {
            let orgs: Vec<OrganizationData> = response.json::<Vec<OrganizationData>>().await?;
            Ok(orgs)
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    async fn organization_create(
        &mut self,
        name: &str,
        description: &str,
    ) -> Result<(), ApiServerError> {
        // Create the form
        let mut form = HashMap::new();
        form.insert("name", name.to_string());
        form.insert("description", description.to_string());

        let response = self
            .authenticated_request(ORGANIZATION_ROUTE_V1, reqwest::Method::POST, None)
            .await?
            .json(&form)
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::CREATED {
            Ok(())
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    async fn organization_delete(&mut self, id: &Uuid) -> Result<(), ApiServerError> {
        let path = format!("{}/{}", ORGANIZATION_ROUTE_V1, id).to_string();

        let response = self
            .authenticated_request(&path, reqwest::Method::DELETE, None)
            .await?
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    async fn apikey_create(&mut self) -> Result<ApiKeyData, ApiServerError> {
        let response = self
            .authenticated_request(APIKEY_ROUTE_V1, reqwest::Method::POST, None)
            .await?
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::OK {
            let apikey = response.json().await?;
            Ok(apikey)
        } else if response.status() == reqwest::StatusCode::BAD_REQUEST {
            Err(ApiServerError::ApiError(
                "API key already present!".to_string(),
            ))
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    async fn apikey_list(&mut self) -> Result<Option<ApiKeyData>, ApiServerError> {
        let response = self
            .authenticated_request(APIKEY_ROUTE_V1, reqwest::Method::GET, None)
            .await?
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::OK {
            let apikey = response.json().await?;
            Ok(Some(apikey))
        } else if response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(None)
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    async fn apikey_delete(&mut self) -> Result<(), ApiServerError> {
        let response = self
            .authenticated_request(APIKEY_ROUTE_V1, reqwest::Method::DELETE, None)
            .await?
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::OK {
            Ok(())
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }
}
