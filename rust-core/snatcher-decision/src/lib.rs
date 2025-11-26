// Standard library fully enabled – we need String, Vec, vec!
use serde::Deserialize;
use std::string::String;
use std::vec::Vec;

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
            languages: vec!["Polish".into()],
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

        if !self.config.languages.iter().any(|l| {
            offer
                .language_pair
                .to_lowercase()
                .contains(&l.to_lowercase())
        }) {
            return false;
        }

        if offer.miles as u32 > self.config.max_miles {
            return false;
        }

        if self
            .config
            .blacklist_postcodes
            .iter()
            .any(|pc| offer.postcode.starts_with(pc))
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_offer() -> Offer {
        Offer {
            id: "TEST123".into(),
            price_gbp: 85.0,
            language_pair: "English to Polish".into(),
            miles: 25.0,
            postcode: "SW1A 1AA".into(),
        }
    }

    #[test]
    fn dry_run_always_rejects() {
        let engine = DecisionEngine::new(Config::default());
        assert!(!engine.should_claim(&sample_offer()));
    }

    #[test]
    fn accepts_good_job_when_live() {
        let mut cfg = Config::default();
        cfg.dry_run = false;
        let engine = DecisionEngine::new(cfg);
        assert!(engine.should_claim(&sample_offer()));
    }

    #[test]
    fn rejects_too_cheap() {
        let mut cfg = Config::default();
        cfg.dry_run = false;
        cfg.min_price_gbp = 100.0;
        let engine = DecisionEngine::new(cfg);

        let mut offer = sample_offer();
        offer.price_gbp = 95.0;
        assert!(!engine.should_claim(&offer));
    }

    #[test]
    fn rejects_wrong_language() {
        let mut cfg = Config::default();
        cfg.dry_run = false;
        cfg.languages = vec!["Romanian".into()];
        let engine = DecisionEngine::new(cfg);

        assert!(!engine.should_claim(&sample_offer()));
    }

    #[test]
    fn rejects_too_far() {
        let mut cfg = Config::default();
        cfg.dry_run = false;
        cfg.max_miles = 20;
        let engine = DecisionEngine::new(cfg);

        let mut offer = sample_offer();
        offer.miles = 35.0;
        assert!(!engine.should_claim(&offer));
    }

    #[test]
    fn rejects_blacklisted_postcode() {
        let mut cfg = Config::default();
        cfg.dry_run = false;
        cfg.blacklist_postcodes = vec!["SW1A".into()];
        let engine = DecisionEngine::new(cfg);

        assert!(!engine.should_claim(&sample_offer()));
    }

    #[test]
    fn multi_language_support() {
        let mut cfg = Config::default();
        cfg.dry_run = false;
        cfg.languages = vec!["Polish".into(), "Lithuanian".into()];
        let engine = DecisionEngine::new(cfg);

        let mut offer = sample_offer();
        offer.language_pair = "French to Lithuanian".into();
        assert!(engine.should_claim(&offer));
    }

    #[test]
    fn case_insensitive_language_match() {
        let mut cfg = Config::default();
        cfg.dry_run = false;
        cfg.languages = vec!["polish".into()];
        let engine = DecisionEngine::new(cfg);

        assert!(engine.should_claim(&sample_offer())); // contains "Polish"
    }

    #[test]
    fn postcode_prefix_blacklist() {
        let mut cfg = Config::default();
        cfg.dry_run = false;
        cfg.blacklist_postcodes = vec!["SW".into()];
        let engine = DecisionEngine::new(cfg);

        assert!(!engine.should_claim(&sample_offer())); // starts with "SW"
    }
}
