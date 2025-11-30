mod headers;
mod storage;

use anyhow::Result;
use log::{debug, error, info, warn};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::env;
use std::time::Duration;
use tokio::time::sleep;

// CONSTANTS
const HOST: &str = "https://gateway-uk.wordsynk.com";
const BOOKING_ENDPOINT: &str = "/ws-booking/Bookings/Requirement";
const OFFER_ENDPOINT: &str = "/ws-offer/offers";
const POLL_INTERVAL_MS: u64 = 2000;

// MONGO CONFIG
const MONGO_URI: &str = "mongodb://localhost:27017";
const DB_NAME: &str = "wordsynk_live";

// Header Structure based on your dump
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PaginationHeader {
    current_page: u64,
    page_size: u64,
    total_count: u64,
    total_pages: u64,
    has_previous: bool,
    has_next: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    env_logger::init();
    dotenv::dotenv().ok();

    info!("🚜 WORDSYNK HARVESTER: Initializing Passive Sync...");

    // 1. Init Database
    let db = storage::Storage::new(MONGO_URI, DB_NAME).await?;
    info!("💾 Connected to MongoDB at {} [{}]", MONGO_URI, DB_NAME);

    // 2. Load Config
    let token = env::var("WORDSYNK_TOKEN").expect("WORDSYNK_TOKEN env var required");

    // IDs - STRICT MODE
    let super_user_id = env::var("SUPER_USER_ID").expect("SUPER_USER_ID env var required");
    let supplier_id = env::var("SUPPLIER_ID").expect("SUPPLIER_ID env var required");

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    loop {
        info!("🔄 Cycle Start...");

        // --- STEP 1: SYNC BOOKINGS (Primary Goal) ---
        // This archives your actual confirmed jobs.
        let booking_base_url = format!(
            "{}{}?superUserId={}&pageSize=1000&requirementSupplierId={}",
            HOST, BOOKING_ENDPOINT, super_user_id, supplier_id
        );

        if let Err(e) =
            sync_all_pages(&client, &token, &booking_base_url, "bookings", "id", &db).await
        {
            error!("❌ Sync Bookings Failed: {}", e);
        }

        // Micro-sleep to simulate app processing time
        sleep(Duration::from_millis(100)).await;

        // --- STEP 2: SYNC OFFERS (Secondary - Traffic Mimicry) ---
        // We query this purely to match the app's traffic pattern.
        // We DO NOT act on these offers, we just save them to history.
        let offer_base_url = format!(
            "{}{}?supplierId={}&isAvailable=true&isAccepted=false&isDeleted=false",
            HOST, OFFER_ENDPOINT, supplier_id
        );

        if let Err(e) = sync_all_pages(&client, &token, &offer_base_url, "offers", "id", &db).await
        {
            error!("❌ Sync Offers Failed: {}", e);
        }

        info!("💤 Cycle Complete. Sleeping {}ms...", POLL_INTERVAL_MS);
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

async fn sync_all_pages(
    client: &Client,
    token: &str,
    base_url: &str,
    collection: &str,
    unique_key: &str,
    db: &storage::Storage,
) -> Result<()> {
    let mut page = 1;
    let mut total_pages = 1;

    loop {
        let url = format!("{}&page={}", base_url, page);
        debug!("   -> Fetching {} Page {}", collection, page);

        let response = client
            .get(&url)
            .headers(headers::generate_mobile_headers(token))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("API Error {}: {}", url, response.status()));
        }

        // 1. Parse Pagination Header
        if let Some(header_val) = response.headers().get("X-Pagination") {
            if let Ok(header_str) = header_val.to_str() {
                match serde_json::from_str::<PaginationHeader>(header_str) {
                    Ok(ph) => {
                        total_pages = ph.total_pages;
                    }
                    Err(e) => warn!("      ⚠️ Failed to parse X-Pagination: {}", e),
                }
            }
        }

        // 2. Parse Body (Robust JSON Handling)
        let json: Value = response.json().await?;

        let items: Vec<Value> = if let Some(arr) = json.as_array() {
            arr.clone()
        } else if let Some(obj) = json.as_object() {
            // Fallback for wrapped responses (e.g. { "data": [...] })
            if let Some(data) = obj.get("data").and_then(|d| d.as_array()) {
                data.clone()
            } else {
                warn!("      ⚠️ JSON is not an array and has no 'data' field. Skipping.");
                vec![]
            }
        } else {
            vec![]
        };

        let count = items.len();

        // 3. Sync to DB
        if count > 0 {
            let synced = db.sync_collection(collection, unique_key, items).await?;
            info!(
                "      ✅ Archived {}/{} items (Page {})",
                synced, count, page
            );
        } else {
            debug!("      (Empty Page)");
        }

        page += 1;
        if page > total_pages {
            break;
        }
    }

    Ok(())
}
