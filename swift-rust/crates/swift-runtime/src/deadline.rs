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

//! Typed deadlines. There is no generic `Timeout(60)` (AGENTS.md §19).
//!
//! [`BodyIdleDeadline`] is progress-aware (a received chunk refreshes the idle
//! window). [`UploadLifetimeDeadline`] is the total upload lifetime and is
//! never refreshed by progress. They are different types.

use std::fmt;
use std::time::{Duration, Instant};

/// Discriminant for a typed deadline. Not a substitute for the distinct
/// structs: [`BodyIdleDeadline`] and [`UploadLifetimeDeadline`] cannot be
/// used interchangeably.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeadlineKind {
    Header,
    KeepAliveIdle,
    /// Progress-aware body idle. Distinct from [`DeadlineKind::UploadLifetime`].
    BodyIdle,
    ClientWrite,
    BackendConnect,
    BackendRead,
    BackendWrite,
    /// Total upload lifetime. Distinct from [`DeadlineKind::BodyIdle`].
    UploadLifetime,
    Replication,
    Shutdown,
}

impl DeadlineKind {
    pub const ALL: [DeadlineKind; 10] = [
        DeadlineKind::Header,
        DeadlineKind::KeepAliveIdle,
        DeadlineKind::BodyIdle,
        DeadlineKind::ClientWrite,
        DeadlineKind::BackendConnect,
        DeadlineKind::BackendRead,
        DeadlineKind::BackendWrite,
        DeadlineKind::UploadLifetime,
        DeadlineKind::Replication,
        DeadlineKind::Shutdown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            DeadlineKind::Header => "header",
            DeadlineKind::KeepAliveIdle => "keep_alive_idle",
            DeadlineKind::BodyIdle => "body_idle",
            DeadlineKind::ClientWrite => "client_write",
            DeadlineKind::BackendConnect => "backend_connect",
            DeadlineKind::BackendRead => "backend_read",
            DeadlineKind::BackendWrite => "backend_write",
            DeadlineKind::UploadLifetime => "upload_lifetime",
            DeadlineKind::Replication => "replication",
            DeadlineKind::Shutdown => "shutdown",
        }
    }
}

impl fmt::Display for DeadlineKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

macro_rules! absolute_deadline {
    ($(#[$meta:meta])* $name:ident, $kind:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name {
            at: Instant,
        }

        impl $name {
            pub fn from_timeout(timeout: Duration) -> Self {
                Self {
                    at: Instant::now() + timeout,
                }
            }

            pub fn from_instant(at: Instant) -> Self {
                Self { at }
            }

            pub fn at(self) -> Instant {
                self.at
            }

            pub const fn kind(self) -> DeadlineKind {
                DeadlineKind::$kind
            }

            pub fn is_expired(&self) -> bool {
                Instant::now() >= self.at
            }

            pub fn remaining(&self) -> Duration {
                self.at.saturating_duration_since(Instant::now())
            }
        }
    };
}

absolute_deadline!(
    /// HTTP header-read deadline (`header_read_timeout` / slowloris bound).
    HeaderDeadline,
    Header
);
absolute_deadline!(
    /// Idle keep-alive wait between requests on one connection.
    KeepAliveIdleDeadline,
    KeepAliveIdle
);
absolute_deadline!(
    /// Deadline to complete a client socket write.
    ClientWriteDeadline,
    ClientWrite
);
absolute_deadline!(
    /// Backend connect timeout (`conn_timeout`).
    BackendConnectDeadline,
    BackendConnect
);
absolute_deadline!(
    /// Backend read timeout (`node_timeout` analog for reads).
    BackendReadDeadline,
    BackendRead
);
absolute_deadline!(
    /// Backend write timeout.
    BackendWriteDeadline,
    BackendWrite
);
absolute_deadline!(
    /// Replication / SSYNC session deadline.
    ReplicationDeadline,
    Replication
);
absolute_deadline!(
    /// Graceful-shutdown drain deadline.
    ShutdownDeadline,
    Shutdown
);

/// Progress-aware body-idle deadline.
///
/// Receiving a body chunk **refreshes** this window ([`Self::refresh_on_progress`]).
/// This is not [`UploadLifetimeDeadline`]: a slow client that still dribbles
/// bytes will refresh BodyIdle and still hit the upload lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyIdleDeadline {
    at: Instant,
    idle: Duration,
}

impl BodyIdleDeadline {
    pub fn from_timeout(idle: Duration) -> Self {
        Self {
            at: Instant::now() + idle,
            idle,
        }
    }

    pub fn idle_window(self) -> Duration {
        self.idle
    }

    pub fn at(self) -> Instant {
        self.at
    }

    pub const fn kind(self) -> DeadlineKind {
        DeadlineKind::BodyIdle
    }

    /// Refresh because progress was made (a chunk arrived or was written).
    pub fn refresh_on_progress(&mut self) {
        self.at = Instant::now() + self.idle;
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.at
    }

    pub fn remaining(&self) -> Duration {
        self.at.saturating_duration_since(Instant::now())
    }
}

/// Total upload lifetime (`max_upload_time`).
///
/// Not progress-aware: unlike [`BodyIdleDeadline`], chunks do not refresh this
/// clock. The two types are not interchangeable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadLifetimeDeadline {
    at: Instant,
}

impl UploadLifetimeDeadline {
    pub fn from_timeout(lifetime: Duration) -> Self {
        Self {
            at: Instant::now() + lifetime,
        }
    }

    pub fn from_instant(at: Instant) -> Self {
        Self { at }
    }

    pub fn at(self) -> Instant {
        self.at
    }

    pub const fn kind(self) -> DeadlineKind {
        DeadlineKind::UploadLifetime
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.at
    }

    pub fn remaining(&self) -> Duration {
        self.at.saturating_duration_since(Instant::now())
    }
}

/// Per-request set of typed deadlines. Fields are distinct types so BodyIdle
/// cannot be stored in the UploadLifetime slot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeadlineBudget {
    pub header: Option<HeaderDeadline>,
    pub keep_alive_idle: Option<KeepAliveIdleDeadline>,
    pub body_idle: Option<BodyIdleDeadline>,
    pub client_write: Option<ClientWriteDeadline>,
    pub backend_connect: Option<BackendConnectDeadline>,
    pub backend_read: Option<BackendReadDeadline>,
    pub backend_write: Option<BackendWriteDeadline>,
    pub upload_lifetime: Option<UploadLifetimeDeadline>,
    pub replication: Option<ReplicationDeadline>,
    pub shutdown: Option<ShutdownDeadline>,
}

impl DeadlineBudget {
    pub fn new() -> Self {
        Self::default()
    }

    /// Refresh BodyIdle only. UploadLifetime is left untouched.
    pub fn refresh_body_idle(&mut self) {
        if let Some(deadline) = self.body_idle.as_mut() {
            deadline.refresh_on_progress();
        }
    }

    pub fn is_kind_expired(&self, kind: DeadlineKind) -> bool {
        match kind {
            DeadlineKind::Header => self.header.map(|d| d.is_expired()).unwrap_or(false),
            DeadlineKind::KeepAliveIdle => self
                .keep_alive_idle
                .map(|d| d.is_expired())
                .unwrap_or(false),
            DeadlineKind::BodyIdle => self.body_idle.map(|d| d.is_expired()).unwrap_or(false),
            DeadlineKind::ClientWrite => self.client_write.map(|d| d.is_expired()).unwrap_or(false),
            DeadlineKind::BackendConnect => self
                .backend_connect
                .map(|d| d.is_expired())
                .unwrap_or(false),
            DeadlineKind::BackendRead => self.backend_read.map(|d| d.is_expired()).unwrap_or(false),
            DeadlineKind::BackendWrite => {
                self.backend_write.map(|d| d.is_expired()).unwrap_or(false)
            }
            DeadlineKind::UploadLifetime => self
                .upload_lifetime
                .map(|d| d.is_expired())
                .unwrap_or(false),
            DeadlineKind::Replication => self.replication.map(|d| d.is_expired()).unwrap_or(false),
            DeadlineKind::Shutdown => self.shutdown.map(|d| d.is_expired()).unwrap_or(false),
        }
    }

    /// Earliest configured expiry, if any. Used for the next timer arm.
    pub fn next_expiry(&self) -> Option<(DeadlineKind, Instant)> {
        let slots: [(DeadlineKind, Option<Instant>); 10] = [
            (DeadlineKind::Header, self.header.map(|d| d.at())),
            (
                DeadlineKind::KeepAliveIdle,
                self.keep_alive_idle.map(|d| d.at()),
            ),
            (DeadlineKind::BodyIdle, self.body_idle.map(|d| d.at())),
            (DeadlineKind::ClientWrite, self.client_write.map(|d| d.at())),
            (
                DeadlineKind::BackendConnect,
                self.backend_connect.map(|d| d.at()),
            ),
            (DeadlineKind::BackendRead, self.backend_read.map(|d| d.at())),
            (
                DeadlineKind::BackendWrite,
                self.backend_write.map(|d| d.at()),
            ),
            (
                DeadlineKind::UploadLifetime,
                self.upload_lifetime.map(|d| d.at()),
            ),
            (DeadlineKind::Replication, self.replication.map(|d| d.at())),
            (DeadlineKind::Shutdown, self.shutdown.map(|d| d.at())),
        ];
        slots
            .into_iter()
            .filter_map(|(kind, at)| at.map(|at| (kind, at)))
            .min_by_key(|(_, at)| *at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;
    use std::thread;

    #[test]
    fn all_ten_kinds_exist_and_body_idle_is_not_upload_lifetime() {
        assert_eq!(DeadlineKind::ALL.len(), 10);
        assert_ne!(DeadlineKind::BodyIdle, DeadlineKind::UploadLifetime);
        assert_ne!(
            TypeId::of::<BodyIdleDeadline>(),
            TypeId::of::<UploadLifetimeDeadline>()
        );
        assert_ne!(
            BodyIdleDeadline::from_timeout(Duration::from_secs(1)).kind(),
            UploadLifetimeDeadline::from_timeout(Duration::from_secs(1)).kind()
        );
    }

    #[test]
    fn each_struct_reports_its_kind() {
        assert_eq!(
            HeaderDeadline::from_timeout(Duration::from_secs(1)).kind(),
            DeadlineKind::Header
        );
        assert_eq!(
            KeepAliveIdleDeadline::from_timeout(Duration::from_secs(1)).kind(),
            DeadlineKind::KeepAliveIdle
        );
        assert_eq!(
            BodyIdleDeadline::from_timeout(Duration::from_secs(1)).kind(),
            DeadlineKind::BodyIdle
        );
        assert_eq!(
            ClientWriteDeadline::from_timeout(Duration::from_secs(1)).kind(),
            DeadlineKind::ClientWrite
        );
        assert_eq!(
            BackendConnectDeadline::from_timeout(Duration::from_secs(1)).kind(),
            DeadlineKind::BackendConnect
        );
        assert_eq!(
            BackendReadDeadline::from_timeout(Duration::from_secs(1)).kind(),
            DeadlineKind::BackendRead
        );
        assert_eq!(
            BackendWriteDeadline::from_timeout(Duration::from_secs(1)).kind(),
            DeadlineKind::BackendWrite
        );
        assert_eq!(
            UploadLifetimeDeadline::from_timeout(Duration::from_secs(1)).kind(),
            DeadlineKind::UploadLifetime
        );
        assert_eq!(
            ReplicationDeadline::from_timeout(Duration::from_secs(1)).kind(),
            DeadlineKind::Replication
        );
        assert_eq!(
            ShutdownDeadline::from_timeout(Duration::from_secs(1)).kind(),
            DeadlineKind::Shutdown
        );
    }

    #[test]
    fn body_idle_refresh_on_progress_extends_deadline() {
        let mut idle = BodyIdleDeadline::from_timeout(Duration::from_millis(200));
        let first = idle.at();
        thread::sleep(Duration::from_millis(20));
        idle.refresh_on_progress();
        assert!(idle.at() > first);
        assert!(!idle.is_expired());
    }

    #[test]
    fn refresh_body_idle_does_not_move_upload_lifetime() {
        let mut budget = DeadlineBudget::new();
        budget.body_idle = Some(BodyIdleDeadline::from_timeout(Duration::from_millis(200)));
        budget.upload_lifetime = Some(UploadLifetimeDeadline::from_timeout(Duration::from_secs(
            60,
        )));
        let life_at = budget.upload_lifetime.unwrap().at();
        let idle_at = budget.body_idle.unwrap().at();
        thread::sleep(Duration::from_millis(20));
        budget.refresh_body_idle();
        assert_eq!(budget.upload_lifetime.unwrap().at(), life_at);
        assert!(budget.body_idle.unwrap().at() > idle_at);
    }

    #[test]
    fn zero_timeout_is_expired() {
        let d = HeaderDeadline::from_instant(Instant::now());
        assert!(d.is_expired() || d.remaining() == Duration::ZERO);
    }

    fn take_idle(_: BodyIdleDeadline) {}
    fn take_lifetime(_: UploadLifetimeDeadline) {}

    #[test]
    fn body_idle_and_upload_lifetime_are_distinct_parameters() {
        take_idle(BodyIdleDeadline::from_timeout(Duration::from_secs(1)));
        take_lifetime(UploadLifetimeDeadline::from_timeout(Duration::from_secs(
            60,
        )));
    }
}
