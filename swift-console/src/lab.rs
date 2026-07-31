//! The Lab surface: tools that explain the cluster rather than operate it.
//!
//! Files / Deploy / Monitor answer "what is there" and "what is happening now".
//! Lab answers "why, and what if" — ring simulation, policy economics, object
//! forensics, fault experiments. Different verbs, different time horizons, and
//! (from Chaos Arcade onward) a different mutation risk, which is why it is its
//! own top-level surface rather than a corner of Monitor.
//!
//! Adding a tool is one `TOOLS` entry plus one route.

// The Lab surface registry; per-tool gates are used as each tool lands.
#![allow(dead_code)]

use crate::session;
use crate::util::esc;
use crate::AppState;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use std::sync::Arc;

pub struct LabTool {
    pub id: &'static str,
    /// An i18n key, not display text — the registry is rendered into the
    /// side-nav and the index card on every Lab page, so a literal here
    /// leaks English into both no matter what the language switch says.
    pub title: &'static str,
    pub href: &'static str,
    /// Also an i18n key.
    pub blurb: &'static str,
    /// Which delivery wave this lands in; anything not yet built renders as a
    /// visibly unfinished card rather than a dead link.
    pub ready: bool,
}

pub const TOOLS: &[LabTool] = &[
    LabTool {
        id: "ring",
        title: "lab.tool.ring.title",
        href: "/lab/ring",
        blurb: "lab.tool.ring.blurb",
        ready: true,
    },
    LabTool {
        id: "policy",
        title: "lab.tool.policy.title",
        href: "/lab/policy",
        blurb: "lab.tool.policy.blurb",
        ready: true,
    },
    LabTool {
        id: "capsule",
        title: "lab.tool.capsule.title",
        href: "/lab/capsule",
        blurb: "lab.tool.capsule.blurb",
        ready: true,
    },
    LabTool {
        id: "tombstone",
        title: "lab.tool.tombstone.title",
        href: "/lab/tombstone",
        blurb: "lab.tool.tombstone.blurb",
        ready: true,
    },
    LabTool {
        id: "shadow",
        title: "lab.tool.shadow.title",
        href: "/lab/shadow",
        blurb: "lab.tool.shadow.blurb",
        ready: true,
    },
    LabTool {
        id: "chaos",
        title: "lab.tool.chaos.title",
        href: "/lab/chaos",
        blurb: "lab.tool.chaos.blurb",
        ready: true,
    },
    LabTool {
        id: "nodes",
        title: "lab.tool.nodes.title",
        href: "/lab/nodes",
        blurb: "lab.tool.nodes.blurb",
        ready: true,
    },
    LabTool {
        id: "warehouse",
        title: "lab.tool.warehouse.title",
        href: "/lab/warehouse",
        blurb: "lab.tool.warehouse.blurb",
        ready: true,
    },
    LabTool {
        id: "debt",
        title: "lab.tool.debt.title",
        href: "/lab/debt",
        blurb: "lab.tool.debt.blurb",
        ready: true,
    },
];

pub fn tool(id: &str) -> Option<&'static LabTool> {
    TOOLS.iter().find(|t| t.id == id)
}

/// Lab sub-nav for the sidebar. Reuses the bucket-list markup so navigation
/// needs no new CSS.
pub fn side_lab(lang: &str, active: &str) -> String {
    let mut items = String::new();
    for t in TOOLS {
        let cls = if t.id == active { "bkt active" } else { "bkt" };
        let tail = if t.ready {
            String::new()
        } else {
            format!("<span class=\"bkt-m\">{}</span>", crate::i18n::t(lang, "lab.soon"))
        };
        items.push_str(&format!(
            "<a class=\"{cls}\" href=\"{href}\"><span class=\"bkt-n\">{title}</span>{tail}</a>",
            href = t.href,
            title = esc(crate::i18n::t(lang, t.title)),
        ));
    }
    let lab = crate::i18n::t(lang, "lab.title");
    format!(
        r#"<div class="side-sec">
  <div class="side-h"><span>{lab}</span></div>
  <div class="bkt-list">{items}</div>
</div>"#
    )
}

/// A Lab page needs a session, and the surface must be switched on.
pub fn require_lab(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(String, session::Session), Response> {
    let (sid, sess) = session::from_headers(&state.sessions, headers)
        .ok_or_else(|| Redirect::to("/login").into_response())?;
    if !state.cfg.lab_enabled {
        return Err((axum::http::StatusCode::NOT_FOUND, "lab is not enabled").into_response());
    }
    Ok((sid, sess))
}

/// Same gate for JSON endpoints.
pub fn require_lab_api(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(String, session::Session), Response> {
    let (sid, sess) = session::from_headers(&state.sessions, headers).ok_or_else(|| {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "session required"})),
        )
            .into_response()
    })?;
    if !state.cfg.lab_enabled {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({"error": "lab is not enabled"})),
        )
            .into_response());
    }
    Ok((sid, sess))
}
