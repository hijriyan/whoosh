use std::fmt;

#[derive(Debug)]
pub enum WhooshError {
    Config(String),
    Upstream(String),
    Proxy(String),
    Tls(String),
    Acme(String),
    Io(std::io::Error),
    Network(String),
    Other(String),
}

impl std::error::Error for WhooshError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WhooshError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for WhooshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WhooshError::Config(msg) => write!(f, "Configuration error: {}", msg),
            WhooshError::Upstream(msg) => write!(f, "Upstream error: {}", msg),
            WhooshError::Proxy(msg) => write!(f, "Proxy error: {}", msg),
            WhooshError::Tls(msg) => write!(f, "TLS error: {}", msg),
            WhooshError::Acme(msg) => write!(f, "ACME error: {}", msg),
            WhooshError::Io(err) => write!(f, "I/O error: {}", err),
            WhooshError::Network(msg) => write!(f, "Network error: {}", msg),
            WhooshError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl From<std::io::Error> for WhooshError {
    fn from(err: std::io::Error) -> Self {
        WhooshError::Io(err)
    }
}

impl From<Box<dyn std::error::Error>> for WhooshError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        WhooshError::Other(err.to_string())
    }
}

impl From<String> for WhooshError {
    fn from(s: String) -> Self {
        WhooshError::Other(s)
    }
}

impl From<&str> for WhooshError {
    fn from(s: &str) -> Self {
        WhooshError::Other(s.to_string())
    }
}
