use anyhow::Result;
use mongodb::{options::{ClientOptions, UpdateOptions}, Client, Database};
use serde_json::Value;
use bson::{doc, to_document};

pub struct Storage {
    db: Database,
}

impl Storage {
    pub async fn new(uri: &str, db_name: &str) -> Result<Self> {
        let client_options = ClientOptions::parse(uri).await?;
        let client = Client::with_options(client_options)?;
        let db = client.database(db_name);
        Ok(Self { db })
    }

    /// Syncs a list of JSON items to a MongoDB collection.
    /// Performs an upsert based on the `unique_key` field (e.g., "id").
    pub async fn sync_collection(&self, collection_name: &str, unique_key: &str, items: Vec<Value>) -> Result<usize> {
        let collection = self.db.collection::<bson::Document>(collection_name);
        let mut updated_count = 0;

        for item in items {
            // 1. Convert JSON to BSON
            let mut bson_doc = to_document(&item)?;
            
            // Add a local timestamp for our own tracking
            bson_doc.insert("_synced_at", bson::DateTime::now());

            // 2. Extract the Unique Key
            if let Some(id_val) = bson_doc.get(unique_key) {
                // 3. Upsert
                let filter = doc! { unique_key: id_val.clone() };
                let update = doc! { "$set": bson_doc };
                let options = UpdateOptions::builder().upsert(true).build();

                collection.update_one(filter, update, options).await?;
                updated_count += 1;
            }
        }
        Ok(updated_count)
