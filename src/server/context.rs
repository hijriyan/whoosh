use crate::transformer::ResponseTransformer;
use arc_swap::ArcSwap;
use bytes::BytesMut;
use flate2::Decompress;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

pub struct RouteContext {
    pub upstream_name: Option<String>,
    pub response_transformer: Option<Arc<dyn ResponseTransformer>>,
    pub is_upgrade: bool,
    pub ws_client_buf: BytesMut,
    pub ws_upstream_buf: BytesMut,
    pub rewrite_host: Option<String>,
    pub start_time: std::time::Instant,
    pub upstream_start_time: Option<std::time::Instant>,
    pub ws_client_decompressor: Option<Decompress>,
    pub ws_upstream_decompressor: Option<Decompress>,
}

impl RouteContext {
    /// Create a new RouteContext with optimized buffer sizes
    pub fn new() -> Self {
        Self {
            upstream_name: None,
            response_transformer: None,
            is_upgrade: false,
            // Pre-allocate reasonable buffer sizes for WebSocket frames
            ws_client_buf: BytesMut::with_capacity(4096),
            ws_upstream_buf: BytesMut::with_capacity(4096),
            rewrite_host: None,
            start_time: std::time::Instant::now(),
            upstream_start_time: None,
            ws_client_decompressor: None,
            ws_upstream_decompressor: None,
        }
    }

    /// Clear websocket buffers for reuse
    pub fn clear_ws_buffers(&mut self) {
        self.ws_client_buf.clear();
        self.ws_upstream_buf.clear();
    }
}

#[derive(Clone)]
pub struct AppCtx {
    data: Arc<ArcSwap<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>>,
}

impl AppCtx {
    pub fn new() -> Self {
        Self {
            data: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }

    pub fn insert<T: Any + Send + Sync>(&self, value: T) {
        let value = Arc::new(value) as Arc<dyn Any + Send + Sync>;
        self.data.rcu(move |old| {
            let mut next = (**old).clone();
            next.insert(TypeId::of::<T>(), value.clone());
            next
        });
    }

    pub fn get<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        let data = self.data.load();
        let value = data.get(&TypeId::of::<T>()).cloned()?;
        Arc::downcast::<T>(value).ok()
    }

    pub fn remove<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        let mut removed: Option<Arc<dyn Any + Send + Sync>> = None;
        self.data.rcu(|old| {
            let mut next = (**old).clone();
            removed = next.remove(&TypeId::of::<T>());
            next
        });
        removed.and_then(|value| Arc::downcast::<T>(value).ok())
    }
}

impl Default for AppCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::AppCtx;

    #[test]
    fn app_ctx_insert_get_remove() {
        let ctx = AppCtx::new();

        assert!(ctx.get::<usize>().is_none());
        ctx.insert(12usize);
        assert_eq!(*ctx.get::<usize>().unwrap(), 12);

        ctx.insert(24usize);
        assert_eq!(*ctx.get::<usize>().unwrap(), 24);

        let removed = ctx.remove::<usize>().unwrap();
        assert_eq!(*removed, 24);
        assert!(ctx.get::<usize>().is_none());
    }

    #[test]
    fn app_ctx_handles_multiple_types() {
        let ctx = AppCtx::new();

        ctx.insert(10usize);
        ctx.insert("whoosh".to_string());

        assert_eq!(*ctx.get::<usize>().unwrap(), 10);
        assert_eq!(&*ctx.get::<String>().unwrap(), "whoosh");
    }

    #[test]
    fn app_ctx_remove_missing_returns_none() {
        let ctx = AppCtx::new();
        assert!(ctx.remove::<u64>().is_none());
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CustomData {
        id: u32,
        label: String,
    }

    #[test]
    fn app_ctx_store_custom_struct() {
        let ctx = AppCtx::new();
        let data = CustomData {
            id: 7,
            label: "alpha".to_string(),
        };

        ctx.insert(data);

        let stored = ctx.get::<CustomData>().unwrap();
        assert_eq!(stored.id, 7);
    }
}
