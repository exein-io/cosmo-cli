use super::*;
use crate::{
    project_service::{Project, ProjectAnalysis, ProjectIdDTO},
    security::{AuthData, AuthError, AuthSystem},
    CLI_VERSION,
};
use async_trait::async_trait;
use lazy_static::lazy_static;
use reqwest::header::{AUTHORIZATION, USER_AGENT};
use std::{fs::File, io::Write, path::Path};
use uuid::Uuid;

lazy_static! {
    pub static ref CLI_USER_AGENT: String = format!(
        "ExeinCLI/{}", // TODO: possibile estrarre la distribuzione
        *CLI_VERSION
    );
}

const PROJECT_ROUTE_V1: &'static str = "/api/v1/projects";
const APIKEY_ROUTE_V1: &'static str = "/api/v1/api_key";
const UPDATES_ROUTE: &'static str = "/api/updates_check";

#[derive(Debug)]
pub struct HttpApiServer<U: AuthSystem> {
    host: String,
    port: String,
    tls: bool,
    auth_service: U,
}

impl<U: AuthSystem> HttpApiServer<U> {
    pub fn new(host: String, port: String, tls: bool, auth_service: U) -> Self {
        Self {
            host,
            port,
            tls,
            auth_service,
        }
    }

    pub async fn authenticate(&mut self) -> Result<AuthData, AuthError> {
        if let Ok(auth_data) = self.auth_service.logged_in().await {
            Ok(auth_data)
        } else {
            if let Ok(auth_data) = self.auth_service.refresh().await {
                Ok(auth_data)
            } else {
                let (email, password) = crate::read_username_and_password_from_stdin();
                self.auth_service.login(&email, &password).await
            }
        }
    }
    pub async fn logout(&mut self) -> Result<(), AuthError> {
        self.auth_service.logout().await
    }

    fn request(&self, path: &str, method: reqwest::Method) -> reqwest::RequestBuilder {
        let protocol = get_protocol(self.tls);
        let url = format!("{}://{}:{}{}", protocol, self.host, self.port, path);

        reqwest::Client::new()
            .request(method, &url)
            .header(USER_AGENT, &*CLI_USER_AGENT)
    }

    async fn authenticated_request(
        &mut self,
        path: &str,
        method: reqwest::Method,
        query: Option<&[(&str, &str)]>,
    ) -> Result<reqwest::RequestBuilder, ApiServerError> {
        let auth_data = self.authenticate().await?;
        let req = self
            .request(path, method)
            .query(&query)
            .header(AUTHORIZATION, format!("Bearer {}", auth_data.token));

        Ok(req)
    }
}

fn get_protocol(tls: bool) -> &'static str {
    if tls {
        "https"
    } else {
        "http"
    }
}

// Http
impl<U: AuthSystem> HttpApiServer<U> {
    pub async fn updates_check(&self) -> Result<LatestCliVersion, ApiServerError> {
        let response = self
            .request(UPDATES_ROUTE, reqwest::Method::GET)
            .send()
            .await?;
        let response_status = response.status();

        if response_status == http::StatusCode::OK {
            let latest_version = response.json::<LatestCliVersion>().await?;
            Ok(latest_version)
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    pub async fn create(
        &mut self,
        fw_filepath: &str,
        fw_type: &str,
        fw_subtype: &str,
        name: &str,
        description: Option<&str>,
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
            .map(|s| s.to_str())
            .flatten()
            .map(|s| s.to_string())
            .ok_or(ApiServerError::RequestError(format!(
                "Problem with image filename: {}",
                path.display()
            )))?;

        // Prepare the file data
        let bytes = super::super::read_bytes_from_file(fw_filepath).unwrap(); //TODO: unwrap?
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

        let response = self
            .authenticated_request(PROJECT_ROUTE_V1, reqwest::Method::POST, None)
            .await?
            .multipart(form)
            .send()
            .await?;

        let response_status = response.status();

        if response_status == http::StatusCode::OK {
            let dto = response.json::<ProjectIdDTO>().await?;
            Ok(dto.id)
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    pub async fn overview(
        &mut self,
        project_id: &Uuid,
    ) -> Result<serde_json::Value, ApiServerError> {
        let path = format!("{}/{}/overview", PROJECT_ROUTE_V1, project_id).to_string();

        let response = self
            .authenticated_request(&path, reqwest::Method::GET, None)
            .await?
            .send()
            .await?;
        if response.status() == http::StatusCode::OK {
            let overview = response.json().await?;
            Ok(overview)
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    pub async fn report(
        &mut self,
        project_id: &Uuid,
        savepath: &Path,
    ) -> Result<(), ApiServerError> {
        let path = format!("{}/{}/report", PROJECT_ROUTE_V1, project_id).to_string();

        let response = self
            .authenticated_request(&path, reqwest::Method::GET, None)
            .await?
            .send()
            .await?;

        let status = response.status();

        if status == http::StatusCode::OK {
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

    pub async fn analysis(
        &mut self,
        project_id: &Uuid,
        analysis: &str,
        page: &str,
        per_page: &str,
    ) -> Result<ProjectAnalysis, ApiServerError> {
        let path = format!("{}/{}/analysis/{}", PROJECT_ROUTE_V1, project_id, analysis).to_string();
        let query = [("page", page), ("per_page", per_page)];
        let response = self
            .authenticated_request(&path, reqwest::Method::GET, Some(&query))
            .await?
            .send()
            .await?;
        if response.status() == http::StatusCode::OK {
            let res = response.json().await?;
            Ok(res)
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    pub async fn delete(&mut self, project_id: &Uuid) -> Result<(), ApiServerError> {
        let path = format!("{}/{}", PROJECT_ROUTE_V1, project_id).to_string();

        let response = self
            .authenticated_request(&path, reqwest::Method::DELETE, None)
            .await?
            .send()
            .await?;
        if response.status() == http::StatusCode::OK {
            Ok(())
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    pub async fn list_projects(&mut self) -> Result<Vec<Project>, ApiServerError> {
        let response = self
            .authenticated_request(PROJECT_ROUTE_V1, reqwest::Method::GET, None)
            .await?
            .send()
            .await?;

        if response.status() == http::StatusCode::OK {
            let projects: Vec<Project> = response.json::<Vec<Project>>().await?;
            Ok(projects)
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    pub async fn apikey_create(&mut self) -> Result<ApiKeyData, ApiServerError> {
        let response = self
            .authenticated_request(APIKEY_ROUTE_V1, reqwest::Method::POST, None)
            .await?
            .send()
            .await?;

        if response.status() == http::StatusCode::OK {
            let apikey = response.json().await?;
            Ok(apikey)
        } else if response.status() == http::StatusCode::BAD_REQUEST {
            Err(ApiServerError::ApiError(
                "API key already present!".to_string(),
            ))
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    pub async fn apikey_list(&mut self) -> Result<Option<ApiKeyData>, ApiServerError> {
        let response = self
            .authenticated_request(APIKEY_ROUTE_V1, reqwest::Method::GET, None)
            .await?
            .send()
            .await?;

        if response.status() == http::StatusCode::OK {
            let apikey = response.json().await?;
            Ok(Some(apikey))
        } else if response.status() == http::StatusCode::NO_CONTENT {
            Ok(None)
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }

    pub async fn apikey_delete(&mut self) -> Result<(), ApiServerError> {
        let response = self
            .authenticated_request(APIKEY_ROUTE_V1, reqwest::Method::DELETE, None)
            .await?
            .send()
            .await?;

        if response.status() == http::StatusCode::OK {
            Ok(())
        } else {
            let body = response.text().await?;
            Err(ApiServerError::ApiError(body))
        }
    }
}

#[async_trait(?Send)]
impl<U: AuthSystem> ApiServer for HttpApiServer<U> {
    async fn updates_check(&self) -> Result<LatestCliVersion, ApiServerError> {
        self.updates_check().await
    }

    async fn create(
        &mut self,
        fw_filepath: &str,
        fw_type: &str,
        fw_subtype: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<Uuid, ApiServerError> {
        self.create(fw_filepath, fw_type, fw_subtype, name, description)
            .await
    }

    async fn overview(&mut self, project_id: &Uuid) -> Result<serde_json::Value, ApiServerError> {
        self.overview(project_id).await
    }

    async fn report(&mut self, project_id: &Uuid, savepath: &Path) -> Result<(), ApiServerError> {
        self.report(project_id, savepath).await
    }

    async fn analysis(
        &mut self,
        project_id: &Uuid,
        analysis: &str,
        page: &str,
        per_page: &str,
    ) -> Result<ProjectAnalysis, ApiServerError> {
        self.analysis(project_id, analysis, page, per_page).await
    }

    async fn delete(&mut self, project_id: &Uuid) -> Result<(), ApiServerError> {
        self.delete(project_id).await
    }

    async fn list_projects(&mut self) -> Result<Vec<Project>, ApiServerError> {
        self.list_projects().await
    }

    async fn authenticate(&mut self) -> Result<AuthData, AuthError> {
        self.authenticate().await
    }

    async fn login(&mut self) -> Result<(), AuthError> {
        self.login().await
    }
    
    async fn logout(&mut self) -> Result<(), AuthError> {
        self.logout().await
    }

    async fn apikey_create(&mut self) -> Result<ApiKeyData, ApiServerError> {
        self.apikey_create().await
    }

    async fn apikey_list(&mut self) -> Result<Option<ApiKeyData>, ApiServerError> {
        self.apikey_list().await
    }

    async fn apikey_delete(&mut self) -> Result<(), ApiServerError> {
        self.apikey_delete().await
    }
}
