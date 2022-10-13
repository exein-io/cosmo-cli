use crate::api::ApiServer;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use term_table::{row::Row, table_cell::TableCell, Table, TableStyle};
use uuid::Uuid;

#[derive(Deserialize, Serialize, Debug)]
pub struct OrganizationData {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub built_in: bool,
}

impl OrganizationData {
    pub fn get_table_from_list(list: &[OrganizationData]) -> String {
        let mut table = Table::new();
        table.style = TableStyle::simple();
        table.max_column_width = 40;
        table.add_row(Row::new(vec![
            TableCell::new("NAME"),
            TableCell::new("ID"),
            TableCell::new("DESCRIPTION"),
            TableCell::new("BUILT IN"),
        ]));

        let rows: Vec<Row> = list
            .iter()
            .map(|project| {
                vec![
                    TableCell::new(&project.name),
                    TableCell::new(&project.id),
                    TableCell::new(&project.description),
                    TableCell::new(&project.built_in),
                ]
            })
            .map(Row::new)
            .collect();

        for row in rows {
            table.add_row(row);
        }

        table.render()
    }
}

//List organizations
pub async fn list<U: ApiServer>(api_server: &mut U) -> Result<Vec<OrganizationData>> {
    let orgs = api_server.organization_list().await?;
    Ok(orgs)
}

// Delete an organization
pub async fn delete<U: ApiServer>(api_server: &mut U, id: Uuid) -> Result<()> {
    api_server.organization_delete(&id).await?;
    Ok(())
}

// Create a new organization
pub async fn create<U: ApiServer>(api_server: &mut U, name: &str, description: &str) -> Result<()> {
    api_server.organization_create(name, description).await?;

    Ok(())
}
