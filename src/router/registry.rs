use nom::IResult;
use crate::router::matcher::Matcher;
use std::collections::HashSet;
use std::sync::{Arc, OnceLock, Mutex};
use arc_swap::ArcSwap;
use tldextract_rs::{TLDExtract, SuffixList, Source};

// Define the type for a rule parser factory
// Use Arc instead of Box to allow cloning the Vec for ArcSwap (COW)
pub type RouterRuleParser = Arc<dyn Fn(&str) -> IResult<&str, Box<dyn Matcher>> + Send + Sync>;

// Global registry for custom router rules using ArcSwap for lock-free reads
static ROUTER_REGISTRY: OnceLock<ArcSwap<Vec<RouterRuleParser>>> = OnceLock::new();
static HOST_REGISTRY: OnceLock<ArcSwap<Vec<String>>> = OnceLock::new();
static TLDEXTRACTOR: OnceLock<Mutex<TLDExtract>> = OnceLock::new();

fn get_registry() -> &'static ArcSwap<Vec<RouterRuleParser>> {
    ROUTER_REGISTRY.get_or_init(|| ArcSwap::from_pointee(Vec::new()))
}

fn get_host_registry() -> &'static ArcSwap<Vec<String>> {
    HOST_REGISTRY.get_or_init(|| ArcSwap::from_pointee(Vec::new()))
}

fn get_tld_extractor() -> &'static Mutex<TLDExtract> {
    TLDEXTRACTOR.get_or_init(|| {
        let source = Source::Snapshot;
        let suffix = SuffixList::new(source, false, None);
        let extractor = TLDExtract::new(suffix, true).unwrap();
        Mutex::new(extractor)
    })
}

/// Register a custom router rule parser
pub fn register_router_rule<F>(parser: F)
where
    F: Fn(&str) -> IResult<&str, Box<dyn Matcher>> + Send + Sync + 'static,
{
    let registry = get_registry();
    let parser = Arc::new(parser);
    // rcu (Read-Copy-Update) allows atomic updates without locking readers
    registry.rcu(move |old| {
        let mut new = (**old).clone();
        new.push(parser.clone());
        new
    });
}

/// Try to parse input using registered custom rules
pub fn parse_custom_rules(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let registry = get_registry();
    let parsers = registry.load();
    
    // Iterate through registered parsers and return the first match
    for parser in parsers.iter() {
        if let Ok((remaining, matcher)) = parser(input) {
            return Ok((remaining, matcher));
        }
    }
    
    // If no custom parser matches, return error
    // We use ErrorKind::Tag as a generic "no match" error
    Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)))
}

pub fn register_hosts<I>(hosts: I)
where
    I: IntoIterator<Item = String>,
{
    let mut extractor = get_tld_extractor().lock().unwrap();
    
    let mut incoming: Vec<String> = Vec::new();
    for host in hosts {
        if host.is_empty() {
            continue;
        }
        match extractor.extract(&host) {
            Ok(extracted) => {
                let has_domain = extracted.domain.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
                let has_suffix = extracted.suffix.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
                if has_domain && has_suffix {
                    incoming.push(host);
                } else {
                    log::warn!("Skipping invalid host '{}' - no valid TLD found", host);
                }
            }
            Err(e) => {
                log::warn!("Skipping invalid host '{}' - TLD extraction failed: {}", host, e);
            }
        }
    }
    
    if incoming.is_empty() {
        return;
    }
    
    let registry = get_host_registry();
    registry.rcu(move |old| {
        let mut set: HashSet<String> = old.iter().cloned().collect();
        for host in &incoming {
            set.insert(host.clone());
        }
        let mut next: Vec<String> = set.into_iter().collect();
        next.sort();
        next
    });
}

pub fn get_registered_hosts() -> Vec<String> {
    get_host_registry().load().to_vec()
}

#[cfg(test)]
mod tests {
    use super::{register_hosts, get_registered_hosts};

    #[test]
    fn host_registry_collects_hosts() {
        register_hosts(vec!["a.example.com".to_string(), "b.example.com".to_string()]);
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
