#![no_std]
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Offer {
    pub id: String,
    pub price_gbp: f64,
    pub language_pair: String,
    pub miles: f64,
    pub postcode: String,
}

#[derive(Debug)]
pub struct Config {
    pub min_price_gbp: f64,
    pub languages: Vec<String>,
    pub max_miles: u32,
    pub blacklist_postcodes: Vec<String>,
    pub dry_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_price_gbp: 70.0,
            languages: vec!["Polish".to_string()],
            max_miles: 60,
            blacklist_postcodes: vec![],
            dry_run: true,
        }
    }
}

pub struct DecisionEngine {
    config: Config,
}

impl DecisionEngine {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn should_claim(&self, offer: &Offer) -> bool {
        if self.config.dry_run {
            return false;
        }

        if offer.price_gbp < self.config.min_price_gbp {
            return false;
        }

        if !self.config.languages.iter().any(|l| offer.language_pair.contains(l)) {
            return false;
        }

        if offer.miles as u32 > self.config.max_miles {
            return false;
        }

        if self.config.blacklist_postcodes.iter().any(|pc| offer.postcode.starts_with(pc)) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_filtering() {
        let config = Config::default();
        let engine = DecisionEngine::new(config);

        let good = Offer {
            id: "123".to_string(),
            price_gbp: 85.0,
            language_pair: "English to Polish".to_string(),
            miles: 30.0,
            postcode: "SW1A".to_string(),
        };
        assert!(!engine.should_claim(&good)); // dry_run = true

        let mut cfg = Config::default();
        cfg.dry_run = false;
        let engine = DecisionEngine::new(cfg);
        assert!(engine.should_claim(&good));
    }
}
