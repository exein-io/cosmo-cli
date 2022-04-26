use super::*;
use async_trait::async_trait;
use jsonwebtoken::{DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error, time::SystemTime};

const FIREBASE_LOGIN_URL: &'static str =
    "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword";
const FIREBASE_REFRESH_URL: &'static str = "https://securetoken.googleapis.com/v1/token";
const TOKEN_EXPIRATION_LEEWAY: u64 = 60; // seconds

#[derive(Debug, Serialize)]
#[allow(non_snake_case)]
struct FirebaseLoginRequest<'a> {
    email: &'a str,
    password: &'a str,
    returnSecureToken: bool,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case)]
struct FirebaseRefreshRequest<'a> {
    refresh_token: &'a str,
    grant_type: &'a str, //	The refresh token's grant type, always "refresh_token"
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
pub struct FirebaseLoginResponse {
    pub kind: String,
    pub localId: String,
    pub email: String,
    pub displayName: String,
    pub idToken: String,
    pub registered: bool,
    pub refreshToken: String,
    pub expiresIn: String,
}

#[derive(Debug, Deserialize)]
pub struct FirebaseRefreshResponse {
    pub expires_in: String,
    pub token_type: String,
    pub refresh_token: String,
    pub id_token: String,
    pub user_id: String,
    pub project_id: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct FirebaseResponseError {
    pub error: FirebaseErrorDescription,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct FirebaseErrorDescription {
    pub code: i32,
    pub message: String,
    pub errors: Vec<HashMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirebaseClaims {
    pub name: Option<String>,
    pub iss: String,
    pub aud: String, // Audience (Who or what token is intended for). Always should be "exein-beta"
    pub auth_time: u64, // Time when authentication occurred
    pub user_id: String, // Same of Subject
    pub sub: String, // Subject (whom the token refers to)
    pub iat: u64,    // Issued at (seconds since Unix epochs)
    pub exp: u64,    // Expiration time (seconds since Unix epochs)
    pub email: String,
    pub email_verified: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirebaseAuthData {
    pub claims: FirebaseClaims,
    pub token: String,
    pub refresh_token: String,
    pub refreshed: bool,
}

#[derive(Debug, Clone)]
struct LastAuthData {
    pub claims: FirebaseClaims,
    pub token: String,
}

#[derive(Debug)]
pub enum FirebaseError {
    RequestError(String),
    ResponseError(FirebaseResponseError),
    LoggedOut,
    NoRefreshToken,
    ExpiredToken,
    TokenError(jsonwebtoken::errors::Error),
}

impl From<reqwest::Error> for FirebaseError {
    fn from(error: reqwest::Error) -> Self {
        Self::RequestError(error.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for FirebaseError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        Self::TokenError(error)
    }
}

impl std::fmt::Display for FirebaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self,) //TODO
    }
}

impl Error for FirebaseError {}

impl From<FirebaseAuthData> for AuthData {
    fn from(firebase_auth_data: FirebaseAuthData) -> Self {
        Self {
            username: firebase_auth_data
                .claims
                .name
                .unwrap_or(firebase_auth_data.claims.email),
            token: firebase_auth_data.token,
            refresh_token: Some(firebase_auth_data.refresh_token),
            refreshed: firebase_auth_data.refreshed,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Firebase {
    api_key: String,
    last_auth_data: Option<LastAuthData>,
    refresh_token: Option<String>,
    auto_refresh: bool,
}

impl Firebase {
    pub fn new(api_key: String, auto_refresh: bool) -> Self {
        Self {
            api_key,
            last_auth_data: None,
            refresh_token: None,
            auto_refresh,
        }
    }

    pub fn get_api_key(&self) -> &str {
        &self.api_key
    }

    pub fn set_refresh_token(&mut self, refresh_token: String) {
        self.refresh_token = Some(refresh_token)
    }

    pub async fn logged_in(&mut self) -> Result<FirebaseAuthData, FirebaseError> {
        let last_auth_data = match &self.last_auth_data {
            Some(value) => value,
            None => return Err(FirebaseError::LoggedOut),
        };
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let token_exp = last_auth_data.claims.exp;
        if token_exp < now || (token_exp - now) < TOKEN_EXPIRATION_LEEWAY {
            if self.auto_refresh {
                let mut new_auth_data = self.refresh().await?;
                new_auth_data.refreshed = true;
                Ok(new_auth_data)
            } else {
                Err(FirebaseError::ExpiredToken)
            }
        } else {
            Ok(FirebaseAuthData {
                claims: last_auth_data.claims.clone(),
                token: last_auth_data.token.clone(),
                refresh_token: self.refresh_token.clone().unwrap(), // Should be safe because refresh_token is tied to last_auth_data
                refreshed: false,
            })
        }
    }

    pub async fn login(
        &mut self,
        email: &str,
        password: &str,
    ) -> Result<FirebaseAuthData, FirebaseError> {
        let query = [("key", &self.api_key)];

        let request = FirebaseLoginRequest {
            email,
            password,
            returnSecureToken: true,
        };

        let client = reqwest::Client::new();

        let response = client
            .post(FIREBASE_LOGIN_URL)
            .query(&query)
            .json(&request)
            .send()
            .await?;

        if response.status() != reqwest::StatusCode::OK {
            let response_error = response.json::<FirebaseResponseError>().await?;
            let error = FirebaseError::ResponseError(response_error);
            return Err(error);
        }
        let login_response = response.json::<FirebaseLoginResponse>().await?;

        let token = login_response.idToken;
        let refresh_token = login_response.refreshToken;

        let claims = decode_firebase_token(&token)?;

        self.last_auth_data = Some(LastAuthData {
            claims: claims.clone(),
            token: token.clone(),
        });
        self.refresh_token = Some(refresh_token.clone());

        Ok(FirebaseAuthData {
            claims,
            token,
            refresh_token,
            refreshed: false,
        })
    }

    pub async fn refresh(&mut self) -> Result<FirebaseAuthData, FirebaseError> {
        if let Some(refresh_token) = self.refresh_token.clone() {
            self.manual_refresh_with_token(&refresh_token).await
        } else {
            Err(FirebaseError::NoRefreshToken)
        }
    }

    pub async fn manual_refresh_with_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<FirebaseAuthData, FirebaseError> {
        let query = [("key", &self.api_key)];

        let request = FirebaseRefreshRequest {
            refresh_token,
            grant_type: "refresh_token",
        };

        let client = reqwest::Client::new();
        let response = client
            .post(FIREBASE_REFRESH_URL)
            .query(&query)
            .json(&request)
            .send()
            .await?;
        if response.status() != reqwest::StatusCode::OK {
            let response_error = response.json::<FirebaseResponseError>().await?;
            let error = FirebaseError::ResponseError(response_error);
            return Err(error);
        }
        let refresh_response = response.json::<FirebaseRefreshResponse>().await?;
        let token = refresh_response.id_token;
        let refresh_token = refresh_response.refresh_token;

        let claims = decode_firebase_token(&token)?;

        self.last_auth_data = Some(LastAuthData {
            claims: claims.clone(),
            token: token.clone(),
        });
        self.refresh_token = Some(refresh_token.clone());

        Ok(FirebaseAuthData {
            claims,
            token,
            refresh_token,
            refreshed: false,
        })
    }

    fn logout(&mut self) {
        self.last_auth_data = None;
        self.refresh_token = None;
    }
}

fn decode_firebase_token(token: &str) -> Result<FirebaseClaims, jsonwebtoken::errors::Error> {
    let header = jsonwebtoken::decode_header(&token)?;
    let mut validation = Validation::default();
    validation.algorithms = vec![header.alg];
    validation.insecure_disable_signature_validation();
    let decoded = jsonwebtoken::decode::<FirebaseClaims>(
        token,
        &DecodingKey::from_secret("DUMMY_BECAUSE_VERIFICATION_TURNED_OFF".as_ref()),
        &validation,
    )?;
    Ok(decoded.claims)
}

#[async_trait(?Send)]
impl AuthSystem for Firebase {
    async fn logged_in(&mut self) -> Result<AuthData, AuthError> {
        let firebase_auth_data = Firebase::logged_in(self)
            .await
            .map_err(|err| AuthError::LoginError(err.to_string()))?;
        Ok(firebase_auth_data.into())
    }
    async fn login(&mut self, email: &str, password: &str) -> Result<AuthData, AuthError> {
        let firebase_auth_data = Firebase::login(self, email, password)
            .await
            .map_err(|err| AuthError::LoginError(err.to_string()))?;
        Ok(firebase_auth_data.into())
    }
    async fn refresh(&mut self) -> Result<AuthData, AuthError> {
        let firebase_auth_data = Firebase::refresh(self).await.map_err(|err| {
            if let FirebaseError::NoRefreshToken = err {
                AuthError::NoRefreshToken
            } else {
                AuthError::RefreshError(err.to_string())
            }
        })?;
        Ok(firebase_auth_data.into())
    }
    async fn manual_refresh_with_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<AuthData, AuthError> {
        let firebase_auth_data = Firebase::manual_refresh_with_token(self, refresh_token)
            .await
            .map_err(|err| AuthError::RefreshError(err.to_string()))?;
        Ok(firebase_auth_data.into())
    }
    async fn logout(&mut self) -> Result<(), AuthError> {
        Ok(Firebase::logout(self))
    }
}
