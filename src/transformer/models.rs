use pingora::http::{RequestHeader, ResponseHeader};
use http::{HeaderName, HeaderValue};
use std::fmt::Debug;
use url::Url;

pub trait RequestTransformer: Send + Sync + Debug {
    fn transform_request(&self, _req: &mut RequestHeader) {}
}

pub trait ResponseTransformer: Send + Sync + Debug {
    fn transform_response(&self, _res: &mut ResponseHeader) {}
}

// --- Header Transformers ---

#[derive(Debug)]
pub struct ReplaceHeader {
    pub name: HeaderName,
    pub value: HeaderValue,
}

impl RequestTransformer for ReplaceHeader {
    fn transform_request(&self, req: &mut RequestHeader) {
        // insert_header replaces any existing values for this header name
        let _ = req.insert_header(self.name.clone(), self.value.clone());
    }
}

impl ResponseTransformer for ReplaceHeader {
    fn transform_response(&self, res: &mut ResponseHeader) {
        let _ = res.insert_header(self.name.clone(), self.value.clone());
    }
}

#[derive(Debug)]
pub struct AppendHeader {
    pub name: HeaderName,
    pub value: HeaderValue,
}

impl RequestTransformer for AppendHeader {
    fn transform_request(&self, req: &mut RequestHeader) {
        let _ = req.append_header(self.name.clone(), self.value.clone());
    }
}

impl ResponseTransformer for AppendHeader {
    fn transform_response(&self, res: &mut ResponseHeader) {
        let _ = res.append_header(self.name.clone(), self.value.clone());
    }
}

#[derive(Debug)]
pub struct DeleteHeader {
    pub name: HeaderName,
}

impl RequestTransformer for DeleteHeader {
    fn transform_request(&self, req: &mut RequestHeader) {
        let _ = req.remove_header(&self.name);
    }
}

impl ResponseTransformer for DeleteHeader {
    fn transform_response(&self, res: &mut ResponseHeader) {
        let _ = res.remove_header(&self.name);
    }
}

// --- Query Transformers (Request Only) ---

#[derive(Debug)]
pub struct ReplaceQuery {
    pub key: String,
    pub value: String,
}

// Base URL for relative path resolution
const BASE_URL: &str = "http://placeholder.com";

impl RequestTransformer for ReplaceQuery {
    fn transform_request(&self, req: &mut RequestHeader) {
        // Pingora's RequestHeader stores URI in `req.uri`
        // We need to parse it, modify query, and write it back.
        // NOTE: RequestHeader::uri is http::Uri.
        
        // Convert http::Uri to url::Url (needs base for relative paths)
        let uri_str = req.uri.to_string();
        // Since we are proxying, we might have absolute or relative URI.
        // Url::parse requires absolute URL.
        // Simple heuristic: if it starts with slash, prepend base.
        let full_url = if uri_str.starts_with('/') {
            format!("{}{}", BASE_URL, uri_str)
        } else {
            uri_str.clone()
        };

        if let Ok(mut url) = Url::parse(&full_url) {
            // Modify query pairs
            let mut pairs: Vec<(String, String)> = url.query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .filter(|(k, _)| k != &self.key) // Remove existing
                .collect();
            
            pairs.push((self.key.clone(), self.value.clone()));
            
            // Rebuild query string
            url.query_pairs_mut().clear().extend_pairs(pairs);
            
            // Extract path and query to update http::Uri
            let new_path_and_query = if let Some(query) = url.query() {
                format!("{}?{}", url.path(), query)
            } else {
                url.path().to_string()
            };

            // Update request URI
            // Note: This is a bit expensive but necessary for query manipulation
             if let Ok(new_uri) = new_path_and_query.parse::<http::Uri>() {
                req.set_uri(new_uri);
            }
        }
    }
}

#[derive(Debug)]
pub struct AppendQuery {
    pub key: String,
    pub value: String,
}

impl RequestTransformer for AppendQuery {
    fn transform_request(&self, req: &mut RequestHeader) {
        let uri_str = req.uri.to_string();
        let full_url = if uri_str.starts_with('/') {
            format!("{}{}", BASE_URL, uri_str)
        } else {
            uri_str.clone()
        };

        if let Ok(mut url) = Url::parse(&full_url) {
            url.query_pairs_mut().append_pair(&self.key, &self.value);
            
            let new_path_and_query = if let Some(query) = url.query() {
                format!("{}?{}", url.path(), query)
            } else {
                url.path().to_string()
            };

             if let Ok(new_uri) = new_path_and_query.parse::<http::Uri>() {
                req.set_uri(new_uri);
            }
        }
    }
}

#[derive(Debug)]
pub struct DeleteQuery {
    pub key: String,
}

impl RequestTransformer for DeleteQuery {
    fn transform_request(&self, req: &mut RequestHeader) {
        let uri_str = req.uri.to_string();
        let full_url = if uri_str.starts_with('/') {
            format!("{}{}", BASE_URL, uri_str)
        } else {
            uri_str.clone()
        };

        if let Ok(mut url) = Url::parse(&full_url) {
             let pairs: Vec<(String, String)> = url.query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .filter(|(k, _)| k != &self.key)
                .collect();
            
            url.query_pairs_mut().clear().extend_pairs(pairs);
            
            let new_path_and_query = if let Some(query) = url.query() {
                format!("{}?{}", url.path(), query)
            } else {
                url.path().to_string()
            };

             if let Ok(new_uri) = new_path_and_query.parse::<http::Uri>() {
                req.set_uri(new_uri);
            }
        }
    }
}

// --- Chain Transformer ---

#[derive(Debug)]
pub struct ChainRequestTransformer {
    pub transformers: Vec<Box<dyn RequestTransformer>>,
}

impl RequestTransformer for ChainRequestTransformer {
    fn transform_request(&self, req: &mut RequestHeader) {
        for t in &self.transformers {
            t.transform_request(req);
        }
    }
}

#[derive(Debug)]
pub struct ChainResponseTransformer {
    pub transformers: Vec<Box<dyn ResponseTransformer>>,
}

impl ResponseTransformer for ChainResponseTransformer {
    fn transform_response(&self, res: &mut ResponseHeader) {
        for t in &self.transformers {
            t.transform_response(res);
        }
    }
}
