// Copyright (c) 2026 OpenStack Foundation
//! Dynamic Paste-style filter plugin registry.
//!
//! Python Swift loads third-party middleware via Paste Deploy entry points
//! (`egg:pkg#filter`). Rust cannot load arbitrary Python eggs; this module
//! provides the **product surface** for unlimited filter names:
//!
//! 1. **Built-in factories** — registered by name at startup.
//! 2. **Conf map** — `[filter:name] use = paste.passthrough` or
//!    `plugin = named_passthrough` / custom registered factory.
//! 3. **Default for unknown pipeline names** — [`NamedPassthrough`] so any
//!    third-party name is a claimable slot (never silently skipped when
//!    `plugin_default = passthrough`).
//!
//! Operators register in-process factories via [`PluginRegistry::register`].

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::passthrough::NamedPassthrough;
use crate::Middleware;

/// Factory that builds a middleware instance from conf section items.
pub type PluginFactory =
    Arc<dyn Fn(&str, &HashMap<String, String>) -> Arc<dyn Middleware> + Send + Sync>;

/// Global-ish registry of filter name → factory (cloneable Arc store).
#[derive(Clone, Default)]
pub struct PluginRegistry {
    inner: Arc<RwLock<HashMap<String, PluginFactory>>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        let reg = Self::default();
        // Built-in: named passthrough for any claimable third-party slot.
        reg.register(
            "paste.passthrough",
            Arc::new(|name, _| Arc::new(NamedPassthrough::new(name)) as Arc<dyn Middleware>),
        );
        reg.register(
            "named_passthrough",
            Arc::new(|name, _| Arc::new(NamedPassthrough::new(name)) as Arc<dyn Middleware>),
        );
        reg.register(
            "egg:swift#passthrough",
            Arc::new(|name, _| Arc::new(NamedPassthrough::new(name)) as Arc<dyn Middleware>),
        );
        reg
    }

    pub fn register(&self, use_key: &str, factory: PluginFactory) {
        if let Ok(mut g) = self.inner.write() {
            g.insert(use_key.to_ascii_lowercase(), factory);
        }
    }

    pub fn get(&self, use_key: &str) -> Option<PluginFactory> {
        self.inner
            .read()
            .ok()?
            .get(&use_key.to_ascii_lowercase())
            .cloned()
    }

    /// Build filter for pipeline `name` using conf `use` / `plugin` keys.
    ///
    /// Falls back to NamedPassthrough when `default_passthrough` is true.
    pub fn build(
        &self,
        name: &str,
        conf_items: &HashMap<String, String>,
        default_passthrough: bool,
    ) -> Option<(Arc<dyn Middleware>, String)> {
        let use_key = conf_items
            .get("use")
            .or_else(|| conf_items.get("plugin"))
            .or_else(|| conf_items.get("paste.filter_factory"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if !use_key.is_empty() {
            if let Some(factory) = self.get(&use_key) {
                let mw = factory(name, conf_items);
                return Some((mw, format!("plugin '{name}' via use={use_key}")));
            }
            // Unknown use= — still claimable passthrough if default on.
            if default_passthrough {
                return Some((
                    Arc::new(NamedPassthrough::new(name)),
                    format!(
                        "plugin '{name}' unknown use={use_key}; NamedPassthrough fallback"
                    ),
                ));
            }
            return None;
        }
        if default_passthrough {
            return Some((
                Arc::new(NamedPassthrough::new(name)),
                format!("plugin '{name}' registered as NamedPassthrough (third-party slot)"),
            ));
        }
        None
    }

    pub fn registered_keys(&self) -> Vec<String> {
        self.inner
            .read()
            .map(|g| g.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Process-wide default registry (lazy).
pub fn global_registry() -> &'static PluginRegistry {
    use std::sync::OnceLock;
    static REG: OnceLock<PluginRegistry> = OnceLock::new();
    REG.get_or_init(PluginRegistry::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_name_default_passthrough() {
        let reg = PluginRegistry::new();
        let conf = HashMap::new();
        let (_mw, note) = reg.build("my_custom_filter", &conf, true).unwrap();
        assert!(note.contains("NamedPassthrough"));
        assert!(note.contains("my_custom_filter"));
    }

    #[test]
    fn use_paste_passthrough() {
        let reg = PluginRegistry::new();
        let mut conf = HashMap::new();
        conf.insert("use".into(), "paste.passthrough".into());
        let (_mw, note) = reg.build("third_party_x", &conf, false).unwrap();
        assert!(note.contains("paste.passthrough"));
        assert!(note.contains("third_party_x"));
    }

    #[test]
    fn custom_factory_registered() {
        let reg = PluginRegistry::new();
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag2 = Arc::clone(&flag);
        reg.register(
            "egg:myplugin#filter",
            Arc::new(move |name, _| {
                flag2.store(true, std::sync::atomic::Ordering::SeqCst);
                Arc::new(NamedPassthrough::new(format!("wrapped-{name}")))
            }),
        );
        let mut conf = HashMap::new();
        conf.insert("use".into(), "egg:myplugin#filter".into());
        let (_mw, note) = reg.build("foo", &conf, false).unwrap();
        assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
        assert!(note.contains("egg:myplugin#filter"));
    }

    #[test]
    fn no_default_returns_none() {
        let reg = PluginRegistry::new();
        assert!(reg.build("nope", &HashMap::new(), false).is_none());
    }
}
