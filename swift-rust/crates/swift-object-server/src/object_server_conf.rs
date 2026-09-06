// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Object-server conf lookup shared by the binary and listen overlay.
//!
//! Isolated `/etc/g6-rust/object-server/{1..4}.conf` writes `mount_check =
//! false` and `disable_fallocate = true`. Field G6 on `57b7456` still 507'd
//! REPLICATE/SSYNC with an empty `Drive:` on plain dirs. The binary only
//! consulted `[app:object-server]` then `[DEFAULT]`; a Paste-style
//! `[object-server]` section was dropped on the floor and the Rust default
//! `mount_check=true` won.

use swift_core::config::{config_true_value, SwiftConfig};

/// Sections isolated SAIO / G6 files actually use, in override order.
pub const OBJECT_SERVER_CONF_SECTIONS: [&str; 3] =
    ["app:object-server", "object-server", "DEFAULT"];

/// `57b7456` / `7444bb6` main.rs lookup: app section, then DEFAULT only.
pub fn object_server_conf_get_app_or_default(conf: &SwiftConfig, key: &str) -> Option<String> {
    conf.get("app:object-server", key)
        .ok()
        .flatten()
        .or_else(|| conf.get("DEFAULT", key).ok().flatten())
}

/// Resolve a knob from `[app:object-server]`, `[object-server]`, or `[DEFAULT]`.
pub fn object_server_conf_get(conf: &SwiftConfig, key: &str) -> Option<String> {
    for section in OBJECT_SERVER_CONF_SECTIONS {
        if let Ok(Some(value)) = conf.get(section, key) {
            return Some(value);
        }
    }
    None
}

/// Python `config_true_value` with a default when the key is absent.
pub fn object_server_conf_flag(conf: &SwiftConfig, key: &str, default: bool) -> bool {
    object_server_conf_get(conf, key)
        .map(|value| config_true_value(value.trim()))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> SwiftConfig {
        SwiftConfig::parse_lenient(text, &[], false).unwrap()
    }

    #[test]
    fn mount_check_false_in_default_loads() {
        let conf = parse(
            "[DEFAULT]\n\
             bind_port = 16220\n\
             devices = /srv/2/node\n\
             mount_check = false\n\
             disable_fallocate = true\n\
             [app:object-server]\n\
             use = egg:swift#object\n",
        );
        assert!(!object_server_conf_flag(&conf, "mount_check", true));
        assert!(object_server_conf_flag(&conf, "disable_fallocate", false));
        assert_eq!(
            object_server_conf_get(&conf, "devices").as_deref(),
            Some("/srv/2/node")
        );
    }

    #[test]
    fn mount_check_false_in_app_section_loads() {
        let conf = parse(
            "[DEFAULT]\nbind_port = 16220\n\
             [app:object-server]\nmount_check = False\ndisable_fallocate = true\n",
        );
        assert!(!object_server_conf_flag(&conf, "mount_check", true));
        assert!(!object_server_conf_get_app_or_default(&conf, "mount_check")
            .map(|v| config_true_value(v.trim()))
            .unwrap_or(true));
    }

    /// Field-shaped hole: knobs only under `[object-server]`. Legacy
    /// app-or-DEFAULT lookup misses them and keeps `mount_check=true`.
    #[test]
    fn mount_check_false_only_under_object_server_section_loads() {
        let conf = parse(
            "[DEFAULT]\n\
             bind_port = 16220\n\
             devices = /srv/2/node\n\
             [app:object-server]\n\
             use = egg:swift#object\n\
             [object-server]\n\
             mount_check = false\n\
             disable_fallocate = true\n",
        );
        assert!(
            object_server_conf_get_app_or_default(&conf, "mount_check").is_none(),
            "legacy get(app).or(DEFAULT) must miss [object-server]-only knobs"
        );
        assert!(
            object_server_conf_get_app_or_default(&conf, "mount_check")
                .map(|v| config_true_value(v.trim()))
                .unwrap_or(true),
            "legacy defaulted mount_check to true — field 507 on plain dirs"
        );
        assert!(
            !object_server_conf_flag(&conf, "mount_check", true),
            "isolated [object-server] mount_check=false must win"
        );
        assert!(object_server_conf_flag(&conf, "disable_fallocate", false));
    }

    #[test]
    fn missing_mount_check_keeps_python_default_true() {
        let conf = parse("[DEFAULT]\nbind_port = 16220\n[app:object-server]\n");
        assert!(object_server_conf_flag(&conf, "mount_check", true));
        assert!(!object_server_conf_flag(&conf, "disable_fallocate", false));
    }
}
