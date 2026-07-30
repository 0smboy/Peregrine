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

//! Fire-and-forget StatsD metrics, the Rust counterpart of
//! `swift.common.statsd_client.StatsdClient`.
//!
//! One UDP socket is bound at construction and the target address is
//! resolved once; every send error is ignored, exactly like the Python
//! client. An empty host disables the client entirely (all methods are
//! no-ops), matching Swift's default of no `log_statsd_host`.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;

/// A UDP StatsD client. Disabled (every method is a no-op) when
/// constructed with an empty host.
#[derive(Debug)]
pub struct StatsdClient {
    socket: Option<UdpSocket>,
    target: Option<SocketAddr>,
    /// Either empty or `"<prefix>."`, precomputed so metric lines are a
    /// single format away.
    prefix: String,
}

impl StatsdClient {
    /// Bind one ephemeral UDP socket and resolve `host:port` once. An empty
    /// `host` yields a disabled client; a bind or resolution failure yields
    /// a client that silently drops every metric (fire and forget).
    pub fn new(host: &str, port: u16, prefix: &str) -> Arc<StatsdClient> {
        let prefix = if prefix.is_empty() {
            String::new()
        } else {
            format!("{prefix}.")
        };
        if host.is_empty() {
            return Arc::new(StatsdClient {
                socket: None,
                target: None,
                prefix,
            });
        }
        let socket = UdpSocket::bind("0.0.0.0:0").ok();
        let target = (host, port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addresses| addresses.next());
        Arc::new(StatsdClient {
            socket,
            target,
            prefix,
        })
    }

    fn enabled(&self) -> bool {
        self.socket.is_some() && self.target.is_some()
    }

    fn send(&self, payload: &str) {
        if let (Some(socket), Some(target)) = (&self.socket, &self.target) {
            let _ = socket.send_to(payload.as_bytes(), target);
        }
    }

    /// Emit `prefix.metric:1|c`.
    pub fn increment(&self, metric: &str) {
        self.update_stats(metric, 1);
    }

    /// Emit `prefix.metric:N|c`.
    pub fn update_stats(&self, metric: &str, n: i64) {
        if !self.enabled() {
            return;
        }
        self.send(&format!("{}{}:{}|c", self.prefix, metric, n));
    }

    /// Emit `prefix.metric:MS|ms`.
    pub fn timing(&self, metric: &str, ms: f64) {
        if !self.enabled() {
            return;
        }
        self.send(&format!("{}{}:{}|ms", self.prefix, metric, ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn receiver() -> (UdpSocket, u16) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let port = socket.local_addr().unwrap().port();
        (socket, port)
    }

    fn recv_line(socket: &UdpSocket) -> String {
        let mut buffer = [0u8; 512];
        let read = socket.recv(&mut buffer).unwrap();
        String::from_utf8(buffer[..read].to_vec()).unwrap()
    }

    #[test]
    fn datagram_lines_match_the_statsd_wire_format() {
        let (socket, port) = receiver();
        let client = StatsdClient::new("127.0.0.1", port, "object-replicator");

        client.increment("attempts");
        assert_eq!(recv_line(&socket), "object-replicator.attempts:1|c");

        client.update_stats("partitions", 12);
        assert_eq!(recv_line(&socket), "object-replicator.partitions:12|c");

        client.update_stats("delta", -3);
        assert_eq!(recv_line(&socket), "object-replicator.delta:-3|c");

        client.timing("partition.update.timing", 23.5);
        assert_eq!(
            recv_line(&socket),
            "object-replicator.partition.update.timing:23.5|ms"
        );
    }

    #[test]
    fn empty_prefix_omits_the_leading_dot() {
        let (socket, port) = receiver();
        let client = StatsdClient::new("127.0.0.1", port, "");
        client.increment("attempts");
        assert_eq!(recv_line(&socket), "attempts:1|c");
    }

    #[test]
    fn empty_host_disables_the_client() {
        let client = StatsdClient::new("", 8125, "swift");
        assert!(client.socket.is_none());
        assert!(client.target.is_none());
        // No panic, no send: fire and forget on a disabled client.
        client.increment("attempts");
        client.update_stats("partitions", 7);
        client.timing("t", 1.25);
    }
}
