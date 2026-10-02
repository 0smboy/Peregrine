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
//!
//! Field `1682fdb` confirmed those knobs in object-server startup INFO
//! (`mount_check=false`, in-window 507=0). The leftover is
//! `Manager.once` during `_test_rebuild_scenario`: the reconstructor
//! still defaulted `SWIFT_DIR` from the env only and treated `once` as
//! exactly `argv[2]`.

use std::path::Path;

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

/// Manager.once typically `Popen([server, conf, 'once'])`. Field wrappers
/// and `--once` put the token in another slot; `argv[2] == "once"` only
/// missed those and left the daemon looping until Manager killed it.
pub fn once_flag_from_args<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .skip(1)
        .any(|a| matches!(a.as_ref(), "once" | "--once"))
}

/// `/etc/g6-rust/object-server/1.conf` → `/etc/g6-rust`.
pub fn swift_dir_from_object_server_conf_path(conf_path: Option<&str>) -> Option<String> {
    let path = Path::new(conf_path?);
    let parent = path.parent()?;
    if parent.file_name()?.to_str()? != "object-server" {
        return None;
    }
    let root = parent.parent()?;
    let value = root.to_str()?;
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

/// Rings + listen overlay directory.
///
/// Field `1682fdb` read `SWIFT_DIR` only and defaulted `/etc/swift`. Isolated
/// Manager.once launches `/etc/g6-rust/object-server/*.conf` (which already
/// has `swift_dir = /etc/g6-rust`) without always exporting the env, so the
/// overlay stayed empty (`listen_overlay=0`) during the probe heal window
/// while a later `SWIFT_DIR=/etc/g6-rust` once could `rebuilt>0`.
///
/// Order: non-empty env → conf `swift_dir` → parent of `object-server/` →
/// `/etc/swift`. `source` is `env` / `conf` / `conf_path` / `default`.
pub fn resolve_swift_dir(
    conf: &SwiftConfig,
    conf_path: Option<&str>,
    env_swift_dir: Option<&str>,
) -> (String, &'static str) {
    if let Some(env) = env_swift_dir {
        let trimmed = env.trim();
        if !trimmed.is_empty() {
            return (trimmed.to_string(), "env");
        }
    }
    if let Some(from_conf) = object_server_conf_get(conf, "swift_dir") {
        let trimmed = from_conf.trim();
        if !trimmed.is_empty() {
            return (trimmed.to_string(), "conf");
        }
    }
    if let Some(inferred) = swift_dir_from_object_server_conf_path(conf_path) {
        return (inferred, "conf_path");
    }
    ("/etc/swift".to_string(), "default")
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

    /// `1682fdb` reconstructor `get("app:object-server")` then DEFAULT missed
    /// isolated `[object-server] devices=` the same way mount_check did.
    #[test]
    fn devices_only_under_object_server_section_loads() {
        let conf = parse(
            "[DEFAULT]\n\
             bind_port = 16230\n\
             [app:object-server]\n\
             use = egg:swift#object\n\
             [object-server]\n\
             devices = /srv/3/node\n",
        );
        assert!(
            object_server_conf_get_app_or_default(&conf, "devices").is_none(),
            "legacy reconstructor get(app).or(DEFAULT) missed [object-server] devices"
        );
        assert_eq!(
            object_server_conf_get(&conf, "devices").as_deref(),
            Some("/srv/3/node")
        );
    }

    #[test]
    fn once_flag_accepts_once_and_long_opt_in_any_slot_after_argv0() {
        assert!(
            once_flag_from_args([
                "swift-object-reconstructor",
                "/etc/g6-rust/object-server/1.conf",
                "once"
            ]),
            "Manager.once Popen([server, conf, once])"
        );
        assert!(once_flag_from_args([
            "swift-object-reconstructor",
            "/etc/g6-rust/object-server/1.conf",
            "--once"
        ]));
        assert!(once_flag_from_args([
            "swift-object-reconstructor",
            "--once",
            "/etc/g6-rust/object-server/1.conf"
        ]));
        assert!(
            !once_flag_from_args([
                "swift-object-reconstructor",
                "/etc/g6-rust/object-server/1.conf"
            ]),
            "daemon argv without once must stay looping"
        );
        assert!(!once_flag_from_args(["swift-object-reconstructor"]));
        assert!(
            !once_flag_from_args(["once", "/etc/g6-rust/object-server/1.conf"]),
            "argv[0] named once is not a run-once flag"
        );
    }

    #[test]
    fn resolve_swift_dir_prefers_env_then_conf_then_object_server_parent() {
        let empty = parse("[DEFAULT]\nbind_port = 16230\n[app:object-server]\n");
        assert_eq!(
            resolve_swift_dir(&empty, None, None),
            ("/etc/swift".to_string(), "default"),
            "1682fdb hole: no env and no conf key defaulted /etc/swift"
        );
        assert_eq!(
            resolve_swift_dir(&empty, Some("/etc/g6-rust/object-server/1.conf"), None),
            ("/etc/g6-rust".to_string(), "conf_path")
        );
        let with_key = parse(
            "[DEFAULT]\n\
             swift_dir = /etc/g6-rust\n\
             [object-server]\n\
             devices = /srv/3/node\n",
        );
        assert_eq!(
            resolve_swift_dir(&with_key, Some("/etc/g6-rust/object-server/3.conf"), None),
            ("/etc/g6-rust".to_string(), "conf")
        );
        assert_eq!(
            resolve_swift_dir(
                &with_key,
                Some("/etc/g6-rust/object-server/3.conf"),
                Some("/explicit/swift")
            ),
            ("/explicit/swift".to_string(), "env"),
            "non-empty SWIFT_DIR still wins when an operator exports it"
        );
        assert_eq!(
            resolve_swift_dir(&empty, Some("/etc/g6-rust/object-server.conf"), None),
            ("/etc/swift".to_string(), "default"),
            "a root object-server.conf is not the SAIO object-server/ dir"
        );
    }
}
