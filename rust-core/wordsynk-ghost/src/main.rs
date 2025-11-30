mod headers;
mod storage;

use anyhow::Result;
use log::{info, error, debug, warn};
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

    info!("🚜 WORDSYNK SYNC ENGINE: Initializing...");

    // 1. Init Database
    let db = storage::Storage::new(MONGO_URI, DB_NAME).await?;
    info!("💾 Connected to MongoDB at {} [{}]", MONGO_URI, DB_NAME);

    // 2. Load Config
    let token = env::var("WORDSYNK_TOKEN").expect("WORDSYNK_TOKEN env var required");
    
    // IDs - STRICT MODE: No defaults to avoid ban risk.
    let super_user_id = env::var("SUPER_USER_ID").expect("SUPER_USER_ID env var required");
    let supplier_id = env::var("SUPPLIER_ID").expect("SUPPLIER_ID env var required");
    // Note: 'supplierRef' was not used in the verified Offers URL, so removing requirement for it unless needed later.

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    loop {
        // --- STEP 1: SYNC BOOKINGS (With Pagination) ---
        info!("🔄 Starting Sync Cycle...");
        
        let booking_base_url = format!(
            "{}{}?superUserId={}&pageSize=1000&requirementSupplierId={}", 
            HOST, BOOKING_ENDPOINT, super_user_id, supplier_id
        );
        
        // Using "id" as unique key based on provided JSON dump
        if let Err(e) = sync_all_pages(&client, &token, &booking_base_url, "bookings", "id", &db).await {
            error!("❌ Sync Bookings Failed: {}", e);
        }

        sleep(Duration::from_millis(100)).await;

        // --- STEP 2: SYNC OFFERS ---
        // Updated to user-provided pattern: /ws-offer/offers?supplierId=...
        let offer_base_url = format!(
            "{}{}?supplierId={}&isAvailable=true&isAccepted=false&isDeleted=false",
            HOST, OFFER_ENDPOINT, supplier_id
        );

        // Using "id" as unique key (standard assumption, verify with harvest if fails)
        if let Err(e) = sync_all_pages(&client, &token, &offer_base_url, "offers", "id", &db).await {
            error!("❌ Sync Offers Failed: {}", e);
        }

        info!("💤 Sleeping {}ms...", POLL_INTERVAL_MS);
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

async fn sync_all_pages(
    client: &Client, 
    token: &str, 
    base_url: &str, 
    collection: &str,
    unique_key: &str,
    db: &storage::Storage
) -> Result<()> {
    let mut page = 1;
    let mut total_pages = 1;

    loop {
        let url = format!("{}&page={}", base_url, page);
        debug!("   -> Fetching {} Page {}", collection, page);

        let response = client.get(&url)
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
                    },
                    Err(e) => warn!("      ⚠️ Failed to parse X-Pagination: {}", e),
                }
            }
        }

        // 2. Parse Body (Direct Array)
        let items: Vec<Value> = response.json().await?;
        let count = items.len();

        // 3. Sync to DB
        if count > 0 {
            let synced = db.sync_collection(collection, unique_key, items).await?;
            info!("      ✅ Synced {}/{} items from Page {}", synced, count, page);
        } else {
            debug!("      (Empty Page)");
        }

        // 4. Loop Logic
