use pingora::http::RequestHeader;
use std::fmt::Debug;
use regex::Regex;
use std::sync::{Arc, OnceLock};
use dashmap::DashMap;

pub trait Matcher: Send + Sync + Debug {
    fn matches(&self, req: &RequestHeader) -> bool;
}

// Global regex compilation cache
static REGEX_CACHE: OnceLock<DashMap<String, Arc<Regex>>> = OnceLock::new();

fn get_regex_cache() -> &'static DashMap<String, Arc<Regex>> {
    REGEX_CACHE.get_or_init(|| DashMap::new())
}

pub fn compile_cached_regex(pattern: &str) -> Result<Arc<Regex>, regex::Error> {
    let cache = get_regex_cache();
    
    // Fast path: check if already compiled
    if let Some(cached) = cache.get(pattern) {
        return Ok(cached.clone());
    }
    
    // Slow path: compile and cache
    match Regex::new(pattern) {
        Ok(regex) => {
            let arc_regex = Arc::new(regex);
            cache.insert(pattern.to_string(), arc_regex.clone());
            Ok(arc_regex)
        }
        Err(e) => Err(e)
    }
}

#[derive(Debug)]
pub struct HostMatcher {
    pub host: String,
}

impl Matcher for HostMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        req.uri.host().map(|h| h == self.host).unwrap_or(false)
            || req.headers.get("Host").map(|h| h == self.host.as_str()).unwrap_or(false)
    }
}

#[derive(Debug)]
pub struct HostRegexpMatcher {
    pub regex: Regex,
}

impl Matcher for HostRegexpMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        req.uri.host().map(|h| self.regex.is_match(h)).unwrap_or(false)
            || req.headers.get("Host").and_then(|h| h.to_str().ok()).map(|h| self.regex.is_match(h)).unwrap_or(false)
    }
}

#[derive(Debug)]
pub struct PathMatcher {
    pub path: String,
}

impl Matcher for PathMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        req.uri.path() == self.path
    }
}

#[derive(Debug)]
pub struct PathRegexpMatcher {
    pub regex: Regex,
}

impl Matcher for PathRegexpMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        self.regex.is_match(req.uri.path())
    }
}

#[derive(Debug)]
pub struct PathPrefixMatcher {
    pub prefix: String,
}

impl Matcher for PathPrefixMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        req.uri.path().starts_with(&self.prefix)
    }
}

#[derive(Debug)]
pub struct MethodMatcher {
    pub method: String,
}

impl Matcher for MethodMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        req.method.as_str() == self.method
    }
}

#[derive(Debug)]
pub struct HeaderRegexpMatcher {
    pub name: String,
    pub regex: Regex,
}

impl Matcher for HeaderRegexpMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        req.headers.get(&self.name)
            .and_then(|v| v.to_str().ok())
            .map(|v| self.regex.is_match(v))
            .unwrap_or(false)
    }
}

#[derive(Debug)]
pub struct QueryRegexpMatcher {
    pub key: String,
    pub regex: Regex,
}

impl Matcher for QueryRegexpMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        let uri_str = req.uri.to_string();
        // Since we are proxying, we might have absolute or relative URI.
        // Url::parse requires absolute URL.
        let base_url = "http://placeholder.com";
        let full_url = if uri_str.starts_with('/') {
            format!("{}{}", base_url, uri_str)
        } else {
            uri_str.clone()
        };

        if let Ok(url) = url::Url::parse(&full_url) {
            for (k, v) in url.query_pairs() {
                if k == self.key && self.regex.is_match(&v) {
                    return true;
                }
            }
        }
        false
    }
}

#[derive(Debug)]
pub struct AndMatcher {
    pub left: Box<dyn Matcher>,
    pub right: Box<dyn Matcher>,
}

impl Matcher for AndMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        self.left.matches(req) && self.right.matches(req)
    }
}

#[derive(Debug)]
pub struct OrMatcher {
    pub left: Box<dyn Matcher>,
    pub right: Box<dyn Matcher>,
}

impl Matcher for OrMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        self.left.matches(req) || self.right.matches(req)
    }
}

#[derive(Debug)]
pub struct NotMatcher {
    pub matcher: Box<dyn Matcher>,
}

impl Matcher for NotMatcher {
    fn matches(&self, req: &RequestHeader) -> bool {
        !self.matcher.matches(req)
    }
}
