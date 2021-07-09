use async_trait::async_trait;

pub mod firebase;
pub mod token_cacher;

#[derive(Debug, Clone)]
pub struct AuthData {
    pub username: String,
    pub token: String,
    pub refresh_token: Option<String>,
    pub refreshed: bool,
}

#[derive(Debug, Clone)]
pub enum AuthError {
    LoginError(String),
    LogoutError(String),
    RefreshError(String),
    NoRefreshToken,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self,) //TODO
    }
}

impl std::error::Error for AuthError {}

#[async_trait(?Send)]
pub trait AuthSystem {
    async fn logged_in(&mut self) -> Result<AuthData, AuthError>;
    async fn login(&mut self, email: &str, password: &str) -> Result<AuthData, AuthError>;
    async fn refresh(&mut self) -> Result<AuthData, AuthError>;
    async fn manual_refresh_with_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<AuthData, AuthError>;
    async fn logout(&mut self) -> Result<(), AuthError>;
}
