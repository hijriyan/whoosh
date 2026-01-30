use crate::router::matcher::Matcher;
use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tldextract_rs::{Source, SuffixList, TLDExtract};

// Define the type for a rule parser factory
pub type RouterRuleParser = Arc<
    dyn Fn(&mut &str) -> std::result::Result<Box<dyn Matcher>, winnow::error::ContextError>
        + Send
        + Sync,
>;

// Global registry for custom router rules using ArcSwap for lock-free reads
static ROUTER_REGISTRY: Lazy<ArcSwap<Vec<RouterRuleParser>>> =
    Lazy::new(|| ArcSwap::from_pointee(Vec::new()));

static HOST_REGISTRY: Lazy<ArcSwap<Vec<String>>> = Lazy::new(|| ArcSwap::from_pointee(Vec::new()));

static TLDEXTRACTOR: Lazy<Mutex<TLDExtract>> = Lazy::new(|| {
    let source = Source::Snapshot;
    let suffix = SuffixList::new(source, false, None);
    let extractor = TLDExtract::new(suffix, true).unwrap();
    Mutex::new(extractor)
});

/// Register a custom router rule parser
pub fn register_router_rule<F>(parser: F)
where
    F: Fn(&mut &str) -> std::result::Result<Box<dyn Matcher>, winnow::error::ContextError>
        + Send
        + Sync
        + 'static,
{
    let registry = &ROUTER_REGISTRY;
    let parser = Arc::new(parser);
    // rcu (Read-Copy-Update) allows atomic updates without locking readers
    registry.rcu(move |old| {
        let mut new = (**old).clone();
        new.push(parser.clone());
        new
    });
}

/// Try to parse input using registered custom rules
pub fn parse_custom_rules(
    input: &mut &str,
) -> std::result::Result<Box<dyn Matcher>, winnow::error::ContextError> {
    let registry = &ROUTER_REGISTRY;
    let parsers = registry.load();

    let mut last_err = None;
    // Iterate through registered parsers and return the first match
    for parser in parsers.iter() {
        let mut temp_input = *input;
        match parser(&mut temp_input) {
            Ok(matcher) => {
                *input = temp_input;
                return Ok(matcher);
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    if let Some(err) = last_err {
        Err(err)
    } else {
        Err(winnow::error::ContextError::default())
    }
}

pub fn register_hosts<I>(hosts: I)
where
    I: IntoIterator<Item = String>,
{
    let mut extractor = TLDEXTRACTOR.lock().unwrap();

    let mut incoming: Vec<String> = Vec::new();
    for host in hosts {
        if host.is_empty() {
            continue;
        }
        match extractor.extract(&host) {
            Ok(extracted) => {
                let has_domain = extracted
                    .domain
                    .as_ref()
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
                let has_suffix = extracted
                    .suffix
                    .as_ref()
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
                if has_domain && has_suffix {
                    incoming.push(host);
                } else {
                    log::warn!("Skipping invalid host '{}' - no valid TLD found", host);
                }
            }
            Err(e) => {
                log::warn!(
                    "Skipping invalid host '{}' - TLD extraction failed: {}",
                    host,
                    e
                );
            }
        }
    }

    if incoming.is_empty() {
        return;
    }

    let registry = &HOST_REGISTRY;
    registry.rcu(move |old| {
        let mut set: HashSet<String> = old.iter().cloned().collect();
        for host in &incoming {
            set.insert(host.clone());
        }
        set.into_iter().collect::<Vec<String>>()
    });
}

pub fn get_registered_hosts() -> Vec<String> {
    HOST_REGISTRY.load().to_vec()
}

#[cfg(test)]
mod tests {
    use super::{get_registered_hosts, register_hosts};

    #[test]
    fn host_registry_collects_hosts() {
        register_hosts(vec![
            "a.example.com".to_string(),
            "b.example.com".to_string(),
        ]);
        let hosts = get_registered_hosts();
        assert!(hosts.contains(&"a.example.com".to_string()));
        assert!(hosts.contains(&"b.example.com".to_string()));
    }

    #[test]
    fn host_registry_filters_invalid_tlds() {
        register_hosts(vec![
            "valid.example.com".to_string(),
            "invalid.tldnotexist".to_string(),
            "notadomain".to_string(),
            "test.co.uk".to_string(),
        ]);
        let hosts = get_registered_hosts();
        assert!(hosts.contains(&"valid.example.com".to_string()));
        assert!(hosts.contains(&"test.co.uk".to_string()));
        // Invalid TLDs should be filtered out
        assert!(!hosts.contains(&"invalid.tldnotexist".to_string()));
        assert!(!hosts.contains(&"notadomain".to_string()));
    }
}
