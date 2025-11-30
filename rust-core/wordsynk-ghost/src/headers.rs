use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, ACCEPT, USER_AGENT, ACCEPT_ENCODING};

pub fn generate_mobile_headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();

    // 1. Authorization
    let auth_value = format!("Bearer {}", token);
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_value).unwrap());

    // 2. Mobile User Agent
    headers.insert(USER_AGENT, HeaderValue::from_static("okhttp/4.9.2"));

    // 3. Accept Headers
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
