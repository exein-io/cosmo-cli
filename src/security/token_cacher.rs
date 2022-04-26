use std::{fs, path::PathBuf};

use super::*;
use async_trait::async_trait;

#[derive(Debug)]
pub enum TokenCacherError {
    SharedMemoryError,
    PathError,
    ReadError(String),
    WriteError(String),
    DeleteError(String),
    VerifyError(jsonwebtoken::errors::Error),
}

impl From<jsonwebtoken::errors::Error> for TokenCacherError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        Self::VerifyError(error)
    }
}

impl std::fmt::Display for TokenCacherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self,) //TODO
    }
}

#[derive(Debug, Clone)]
pub struct TokenCacher<T: AuthSystem> {
    pub auth_service: T,
    pub token_path: PathBuf,
}

impl<T: AuthSystem> TokenCacher<T> {
    fn load_refresh_token(&self) -> Result<String, TokenCacherError> {
        fs::read_to_string(&self.token_path).map_err(|e| {
            TokenCacherError::ReadError(format!(
                "Error reading token from {}. Reason: {}",
                self.token_path.display(),
                e
            ))
        })
    }
    fn save_refresh_token(&self, refresh_token: &str) -> Result<(), TokenCacherError> {
        let parent = &self
            .token_path
            .parent()
            .ok_or(TokenCacherError::PathError)?;
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                TokenCacherError::WriteError(format!(
                    "Failed to create token cache parent folder {}. Reason: {}",
                    parent.display(),
                    e
                ))
            })?;
            log::debug!("Token cache parent folder successfully created");
        }
        fs::write(&self.token_path, refresh_token).map_err(|e| {
            TokenCacherError::WriteError(format!(
                "Failed to write token to {}. Reason: {}",
                self.token_path.display(),
                e
            ))
        })
    }
    fn delete_refresh_token(&self) -> Result<(), TokenCacherError> {
        if self.token_path.exists() {
            fs::remove_file(&self.token_path).map_err(|e| {
                TokenCacherError::DeleteError(format!(
                    "Failed delet token file {}. Reason: {}",
                    self.token_path.display(),
                    e
                ))
            })?;
        }
        Ok(())
    }
}

#[async_trait(?Send)]
impl<T: AuthSystem> AuthSystem for TokenCacher<T> {
    async fn logged_in(&mut self) -> Result<AuthData, AuthError> {
        let auth_data = self.auth_service.logged_in().await?;
        if auth_data.refreshed {
            if let Some(refresh_token) = &auth_data.refresh_token {
                if let Err(err) = self.save_refresh_token(refresh_token) {
                    log::warn!("Error caching refresh token. Reason {}", err.to_string());
                }
            }
        }
        Ok(auth_data)
    }
    async fn login(&mut self, email: &str, password: &str) -> Result<AuthData, AuthError> {
        let auth_data = self.auth_service.login(email, password).await?;
        if let Some(refresh_token) = &auth_data.refresh_token {
            if let Err(err) = self.save_refresh_token(refresh_token) {
                log::warn!("Error caching refresh token. Reason {}", err.to_string());
            }
        } else {
            log::warn!("No refresh token to cache");
        }
        Ok(auth_data)
    }
    async fn refresh(&mut self) -> Result<AuthData, AuthError> {
        match &self.auth_service.refresh().await {
            Ok(auth_data) => return Ok(auth_data.clone()),
            Err(err) => {
                if let AuthError::NoRefreshToken = err {
                    let refresh_token = self
                        .load_refresh_token()
                        .map_err(|err| AuthError::RefreshError(err.to_string()))?;
                    self.manual_refresh_with_token(&refresh_token).await
                } else {
                    Err(err.clone())
                }
            }
        }
    }
    async fn manual_refresh_with_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<AuthData, AuthError> {
        self.auth_service
            .manual_refresh_with_token(refresh_token)
            .await
    }
    async fn logout(&mut self) -> Result<(), AuthError> {
        self.auth_service.logout().await?;
        TokenCacher::delete_refresh_token(&self)
            .map_err(|err| AuthError::LogoutError(err.to_string()))
    }
}
