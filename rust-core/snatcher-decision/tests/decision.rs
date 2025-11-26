use snatcher_decision::{Config, DecisionEngine, Offer};

#[test]
fn price_filter() {
    let mut cfg = Config::default();
    cfg.dry_run = false;
    cfg.min_price_gbp = 100.0;
    let engine = DecisionEngine::new(cfg);

    let offer = Offer {
        id: "1".into(),
        price_gbp: 99.0,
        language_pair: "English to Polish".into(),
        miles: 10.0,
        postcode: "L1".into(),
    };
    assert!(!engine.should_claim(&offer));
}

#[test]
fn language_filter() {
    let mut cfg = Config::default();
    cfg.dry_run = false;
    cfg.languages = vec!["Romanian".to_string()];
    let engine = DecisionEngine::new(cfg);

    let offer = Offer {
        id: "1".into(),
        price_gbp: 120.0,
        language_pair: "English to Polish".into(),
        miles: 10.0,
        postcode: "L1".into(),
    };
    assert!(!engine.should_claim(&offer));
}

#[test]
fn full_accept() {
    let mut cfg = Config::default();
    cfg.dry_run = false;
    let engine = DecisionEngine::new(cfg);

    let offer = Offer {
        id: "1".into(),
        price_gbp: 85.0,
        language_pair: "English to Polish".into(),
        miles: 25.0,
        postcode: "SW1A".into(),
    };
    assert!(engine.should_claim(&offer));
}
