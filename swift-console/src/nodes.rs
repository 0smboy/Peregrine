//! Cluster node access: run a command on one node, on all of them, or on the
//! console host itself, and fold the results into something a page can render.
//!
//! Every Lab feature needs this — Object Capsule probes each replica, Tombstone
//! Museum lists on-disk files per node, Chaos Arcade injects and undoes faults —
//! so it exists once rather than five times. `admin.rs` was the first consumer
//! (its rolling tempauth apply) and now shares this implementation.
//!
//! Reads are unrestricted. **Mutations go through [`mutate`]**, which refuses
//! unless the feature is switched on in config *and* every path the script
//! touches lies under the configured lab root, records an undo script, and
//! auto-reverts anything past its TTL. That guard is built here, once, so no
//! feature can quietly grow its own back door.

// Built as the shared foundation: the fan-out and guarded-mutation paths are
// consumed by RingScope, Object Capsule, Tombstone Museum and Chaos Arcade as
// each lands. Kept together so no feature grows its own transport.
#![allow(dead_code)]

use crate::AppState;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// One cluster node across all three network planes. Declared in the console
/// config; the storage plane is the one the console reaches nodes on.
#[derive(Deserialize, Clone, Debug)]
pub struct NodeCfg {
    pub name: String,
    pub storage_ip: String,
    #[serde(default)]
    pub replication_ip: String,
    #[serde(default)]
    pub public_ip: String,
    #[serde(default = "d_one")]
    pub region: u64,
    #[serde(default = "d_one")]
    pub zone: u64,
    #[serde(default = "d_devices")]
    pub devices: Vec<String>,
}
fn d_one() -> u64 {
    1
}
fn d_devices() -> Vec<String> {
    vec!["d1".to_string()]
}

/// Configured nodes. Falls back to the flat `proxy_nodes` IP list that the
/// Tenants & Users admin already used, so an older config still works.
pub fn all(state: &Arc<AppState>) -> Vec<NodeCfg> {
    if !state.cfg.cluster_nodes.is_empty() {
        return state.cfg.cluster_nodes.clone();
    }
    state
        .cfg
        .proxy_nodes
        .iter()
        .enumerate()
        .map(|(i, ip)| NodeCfg {
            name: ip.clone(),
            storage_ip: ip.clone(),
            replication_ip: String::new(),
            public_ip: String::new(),
            region: 1,
            zone: (i + 1) as u64,
            devices: d_devices(),
        })
        .collect()
}

/// The addresses to reach each node's proxy on, for cluster-wide config
/// rollouts.
///
/// Derived from `cluster_nodes` rather than read from the flat `proxy_nodes`
/// list, because a second hand-maintained roster is a second thing to forget:
/// `proxy_nodes` still named three nodes after a fourth joined the cluster, so
/// a rolling tempauth apply would have written three proxies and left the
/// fourth serving a different user list. Same reasoning as
/// `ringlab::ring_devices`, which takes the device inventory from the ring
/// rather than from the config.
///
/// Falls back to the flat list when no cluster nodes are configured, so an
/// older config still works.
pub fn proxy_nodes(state: &Arc<AppState>) -> Vec<String> {
    if state.cfg.cluster_nodes.is_empty() {
        return state.cfg.proxy_nodes.clone();
    }
    all(state)
        .into_iter()
        .map(|n| if n.storage_ip.is_empty() { n.name } else { n.storage_ip })
        .collect()
}

pub fn by_name(state: &Arc<AppState>, name: &str) -> Option<NodeCfg> {
    all(state).into_iter().find(|n| n.name == name)
}

/// Resolve any of the three plane addresses to a node. Ring devices carry
/// storage-plane IPs and log lines carry whichever plane emitted them, so this
/// is what lets every surface show one human node name.
pub fn by_ip(state: &Arc<AppState>, ip: &str) -> Option<NodeCfg> {
    let ip = ip.split(':').next().unwrap_or(ip);
    all(state).into_iter().find(|n| {
        n.storage_ip == ip || n.replication_ip == ip || n.public_ip == ip || n.name == ip
    })
}

/// A human label for an address: the node name when known, else the address.
pub fn label(state: &Arc<AppState>, ip: &str) -> String {
    by_ip(state, ip)
        .map(|n| n.name)
        .unwrap_or_else(|| ip.to_string())
}

// ------------------------------------------------------------- transport

/// The ssh address for a node: its storage-plane IP, or the name itself when
/// the config is the older flat list.
fn addr(state: &Arc<AppState>, node: &str) -> String {
    by_name(state, node)
        .map(|n| {
            if n.storage_ip.is_empty() {
                n.name
            } else {
                n.storage_ip
            }
        })
        .unwrap_or_else(|| node.to_string())
}

pub fn ssh_cmd(state: &Arc<AppState>, node: &str) -> Command {
    let mut c = Command::new("ssh");
    c.args([
        "-i",
        &state.cfg.ssh_key,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        &format!("root@{}", addr(state, node)),
    ]);
    c
}

pub async fn run(state: &Arc<AppState>, node: &str, remote: &str) -> Result<String, String> {
    let o = ssh_cmd(state, node)
        .arg(remote)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
    }
}

/// Run a remote command with `stdin` piped in (config writes, scenario JSON).
pub async fn run_in(
    state: &Arc<AppState>,
    node: &str,
    remote: &str,
    stdin: &[u8],
) -> Result<String, String> {
    let mut child = ssh_cmd(state, node)
        .arg(remote)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    {
        let mut si = child.stdin.take().ok_or("no stdin")?;
        si.write_all(stdin).await.map_err(|e| e.to_string())?;
    }
    let o = child.wait_with_output().await.map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
    }
}

/// Run a binary on the console host itself. Takes argv, never a shell string,
/// so a path or scenario can never be reinterpreted as a command.
pub async fn local(argv: &[&str], stdin: Option<&[u8]>) -> Result<String, String> {
    let (bin, rest) = argv.split_first().ok_or("empty argv")?;
    let mut c = Command::new(bin);
    c.args(rest);
    if stdin.is_some() {
        c.stdin(Stdio::piped());
    }
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().map_err(|e| format!("{bin}: {e}"))?;
    if let Some(data) = stdin {
        let mut si = child.stdin.take().ok_or("no stdin")?;
        si.write_all(data).await.map_err(|e| e.to_string())?;
    }
    let o = child.wait_with_output().await.map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
    }
}

// ------------------------------------------------------------- fan-out

#[derive(Serialize, Clone, Debug)]
pub struct NodeResult {
    pub node: String,
    pub ok: bool,
    pub out: String,
    pub err: String,
    pub ms: u64,
}

async fn one(state: &Arc<AppState>, node: String, remote: String) -> NodeResult {
    let t0 = Instant::now();
    let r = run(state, &node, &remote).await;
    let ms = t0.elapsed().as_millis() as u64;
    match r {
        Ok(out) => NodeResult { node, ok: true, out, err: String::new(), ms },
        Err(err) => NodeResult { node, ok: false, out: String::new(), err, ms },
    }
}

/// The same command on every node, concurrently. Never fails as a whole: an
/// unreachable node is one `ok: false` row, because a diagnostic that refuses
/// to render when one node is down is useless exactly when it is needed.
pub async fn fan_out(state: &Arc<AppState>, remote: &str) -> Vec<NodeResult> {
    let names: Vec<String> = all(state).into_iter().map(|n| n.name).collect();
    fan_out_on(state, &names, remote).await
}

pub async fn fan_out_on(
    state: &Arc<AppState>,
    names: &[String],
    remote: &str,
) -> Vec<NodeResult> {
    let jobs: Vec<(String, String)> = names
        .iter()
        .map(|n| (n.clone(), remote.to_string()))
        .collect();
    fan_out_each(state, jobs).await
}

/// A different command per node — Object Capsule probes a different device
/// path on each one.
pub async fn fan_out_each(
    state: &Arc<AppState>,
    jobs: Vec<(String, String)>,
) -> Vec<NodeResult> {
    let futs = jobs
        .into_iter()
        .map(|(node, remote)| one(state, node, remote));
    futures_util::future::join_all(futs).await
}

// ------------------------------------------------------------- guarded writes

/// What a mutation is allowed to touch. Only `LabContainer` is reachable from
/// the Lab surface; the others exist so the deploy-side paths are named rather
/// than implicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    LabContainer,
    ProxyConf,
    ServiceUnit,
}

pub struct Mutation<'a> {
    pub node: &'a str,
    pub scope: Scope,
    /// The change to apply.
    pub script: &'a str,
    /// How to put it back. Recorded before the change is made.
    pub undo: &'a str,
    pub reason: &'a str,
    pub ttl_secs: u64,
}

#[derive(Serialize, Clone, Debug)]
pub struct JournalEntry {
    pub id: String,
    pub node: String,
    pub scope: Scope,
    pub reason: String,
    pub undo: String,
    pub at: u64,
    pub expires: u64,
    pub undone: bool,
}

pub type Journal = std::sync::Mutex<Vec<JournalEntry>>;

pub fn new_journal() -> Journal {
    std::sync::Mutex::new(Vec::new())
}

/// Every path a lab mutation touches must sit under the configured lab root.
/// Checked on the literal script text: a script that cannot be shown to stay
/// inside the sandbox is refused rather than guessed about.
fn within_lab_root(script: &str, root: &str) -> Result<(), String> {
    if root.is_empty() {
        return Err("no lab_root configured".into());
    }
    for tok in script.split_whitespace() {
        if tok.starts_with('/') && !tok.starts_with(root) {
            return Err(format!("path {tok} is outside the lab root {root}"));
        }
    }
    Ok(())
}

/// Apply a guarded change. Refuses unless lab mutations are enabled and the
/// scope guard passes; records the undo first so a crash mid-apply still
/// leaves a way back.
pub async fn mutate(state: &Arc<AppState>, m: Mutation<'_>) -> Result<JournalEntry, String> {
    if !state.cfg.lab_mutations {
        return Err("lab mutations are disabled".into());
    }
    if m.scope == Scope::LabContainer {
        within_lab_root(m.script, &state.cfg.lab_root)?;
        within_lab_root(m.undo, &state.cfg.lab_root)?;
    }
    let now = crate::util::now_secs();
    let entry = JournalEntry {
        id: crate::util::rand_hex(8),
        node: m.node.to_string(),
        scope: m.scope,
        reason: m.reason.to_string(),
        undo: m.undo.to_string(),
        at: now,
        expires: now + m.ttl_secs.max(30),
        undone: false,
    };
    // Journal before acting: an undo we never recorded is an undo we cannot do.
    state.journal.lock().unwrap().push(entry.clone());
    eprintln!(
        "lab-mutation node={} scope={:?} reason={} id={}",
        entry.node, entry.scope, entry.reason, entry.id
    );
    run(state, m.node, m.script).await?;
    Ok(entry)
}

pub async fn undo(state: &Arc<AppState>, id: &str) -> Result<(), String> {
    let entry = {
        let j = state.journal.lock().unwrap();
        j.iter().find(|e| e.id == id && !e.undone).cloned()
    };
    let entry = entry.ok_or("no such pending mutation")?;
    run(state, &entry.node, &entry.undo).await?;
    let mut j = state.journal.lock().unwrap();
    if let Some(e) = j.iter_mut().find(|e| e.id == id) {
        e.undone = true;
    }
    Ok(())
}

/// Revert anything past its TTL. Runs on a timer so a fault always heals even
/// if the operator closes the tab mid-experiment.
pub async fn sweep(state: &Arc<AppState>) {
    let now = crate::util::now_secs();
    let due: Vec<String> = {
        let j = state.journal.lock().unwrap();
        j.iter()
            .filter(|e| !e.undone && e.expires <= now)
            .map(|e| e.id.clone())
            .collect()
    };
    for id in due {
        if let Err(e) = undo(state, &id).await {
            eprintln!("lab-mutation sweep: could not undo {id}: {e}");
        } else {
            eprintln!("lab-mutation sweep: auto-undid {id} (ttl expired)");
        }
    }
}

pub fn pending(state: &Arc<AppState>) -> Vec<JournalEntry> {
    state
        .journal
        .lock()
        .unwrap()
        .iter()
        .filter(|e| !e.undone)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_root_guard_allows_paths_inside_and_refuses_outside() {
        let root = "/srv/node/d1/objects/_lab";
        assert!(within_lab_root("rm -rf /srv/node/d1/objects/_lab/123", root).is_ok());
        // Relative tokens and flags are not paths and must not trip the guard.
        assert!(within_lab_root("systemctl stop swift-object-replicator", root).is_ok());
        // Anything absolute outside the sandbox is refused.
        let err = within_lab_root("rm -rf /srv/node/d1/objects/7", root).unwrap_err();
        assert!(err.contains("outside the lab root"), "{err}");
        assert!(within_lab_root("rm -rf /etc/swift", root).is_err());
    }

    #[test]
    fn lab_root_guard_refuses_when_unconfigured() {
        assert!(within_lab_root("rm -rf /anything", "").is_err());
    }
}
