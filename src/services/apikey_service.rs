use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cli::CommandOutput;

use super::super::ApiServer;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]

pub struct ApiKeyData {
    pub api_key: Uuid,
    pub creation_date: DateTime<Utc>,
}

impl CommandOutput for ApiKeyData {
    fn text(&self) -> String {
        format!(
            "api key: {} created on {}",
            self.api_key, self.creation_date
        )
    }

    fn json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

//List API key
pub async fn list<U: ApiServer>(api_server: &mut U) -> Result<Option<ApiKeyData>> {
    let ak = api_server.apikey_list().await?;
    Ok(ak)
}

// Delete an API key
pub async fn delete<U: ApiServer>(api_server: &mut U) -> Result<()> {
    api_server.apikey_delete().await?;
    Ok(())
}

// Create a new API key
pub async fn create<U: ApiServer>(api_server: &mut U) -> Result<ApiKeyData> {
    let ak = api_server.apikey_create().await?;

    Ok(ak)
}
