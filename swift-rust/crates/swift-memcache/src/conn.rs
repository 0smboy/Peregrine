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

//! The pluggable connection layer.
//!
//! [`MemcacheConn`] is the seam the client talks through: it sends a fully
//! framed memcached command and returns the complete framed response. The
//! real implementation ([`TcpConn`]) speaks the text protocol over a
//! [`TcpStream`]; unit tests inject an in-memory fake instead.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::DEFAULT_MEMCACHED_PORT;

/// A single connection to one memcached server.
///
/// `request` writes an already-encoded command (e.g.
/// `b"get <hash>\r\n"`) and returns the server's complete response as bytes
/// (e.g. `b"VALUE <hash> 2 5\r\nhello\r\nEND\r\n"`). Implementors own the
/// framing: they must read exactly one complete reply, no more and no less,
/// so the client can parse it without touching the socket.
pub trait MemcacheConn {
    /// Send `cmd` and return the full response frame.
    fn request(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>>;
}

/// A real TCP connection speaking the memcached text protocol.
pub struct TcpConn {
    reader: BufReader<TcpStream>,
}

impl TcpConn {
    /// Connect to `server` (`host`, `host:port`, `[ipv6]`, or `[ipv6]:port`),
    /// defaulting to [`DEFAULT_MEMCACHED_PORT`]. `connect_timeout` bounds the
    /// TCP handshake; `io_timeout` bounds each subsequent read/write.
    ///
    /// Mirrors `MemcacheConnPool.create`: `TCP_NODELAY` is enabled.
    pub fn connect(
        server: &str,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> io::Result<TcpConn> {
        let (host, port) = parse_socket_string(server, DEFAULT_MEMCACHED_PORT)?;
        let mut last_err = io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses resolved");
        for addr in (host.as_str(), port).to_socket_addrs()? {
            match TcpStream::connect_timeout(&addr, connect_timeout) {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    stream.set_read_timeout(Some(io_timeout))?;
                    stream.set_write_timeout(Some(io_timeout))?;
                    return Ok(TcpConn {
                        reader: BufReader::new(stream),
                    });
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

impl MemcacheConn for TcpConn {
    fn request(&mut self, cmd: &[u8]) -> io::Result<Vec<u8>> {
        {
            let sock = self.reader.get_mut();
            sock.write_all(cmd)?;
            sock.flush()?;
        }
        read_response(&mut self.reader)
    }
}

/// Read exactly one complete memcached text-protocol response frame.
///
/// The framing rules we need: every reply is a sequence of `\r\n`-terminated
/// lines. A `VALUE <key> <flags> <bytes>` header is followed by exactly
/// `<bytes>` bytes of data and a trailing `\r\n`; the `get` family streams
/// zero or more such blocks terminated by an `END` line. Every other reply
/// (`STORED`, `NOT_STORED`, `DELETED`, `NOT_FOUND`, a bare integer from
/// `incr`/`decr`, or an error line) is a single line.
pub(crate) fn read_response<R: BufRead>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_start = out.len();
        let n = reader.read_until(b'\n', &mut out)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed mid-response",
            ));
        }
        let line = trim_crlf(&out[line_start..]);
        let keyword = first_token(line);
        if keyword.eq_ignore_ascii_case(b"VALUE") {
            // A data block follows: read <bytes> + the trailing CRLF.
            let size = value_block_size(line).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "malformed VALUE header")
            })?;
            let mut block = vec![0u8; size + 2];
            reader.read_exact(&mut block)?;
            out.extend_from_slice(&block);
            // Loop back for the next VALUE line or the terminating END.
        } else {
            // END, or any single-line reply: the frame is complete.
            return Ok(out);
        }
    }
}

/// The `<bytes>` field (index 3) of a `VALUE <key> <flags> <bytes>` header.
fn value_block_size(line: &[u8]) -> Option<usize> {
    let mut fields = line.split(|&b| b == b' ').filter(|f| !f.is_empty());
    let size = fields.nth(3)?;
    std::str::from_utf8(size).ok()?.parse().ok()
}

fn first_token(line: &[u8]) -> &[u8] {
    line.split(|&b| b == b' ')
        .find(|f| !f.is_empty())
        .unwrap_or(&[])
}

fn trim_crlf(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

/// Split a `server` string into `(host, port)`, defaulting the port.
///
/// Port of `swift.common.utils.parse_socket_string`: supports a bare host,
/// `host:port`, a bracketed IPv6 literal `[::1]` / `[::1]:port`, and a bare
/// IPv6 literal (more than one colon, no brackets -> host with default port).
pub(crate) fn parse_socket_string(server: &str, default_port: u16) -> io::Result<(String, u16)> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, m.to_string());
    let s = server.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| bad("unbalanced brackets in socket string"))?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| bad("invalid port in socket string"))?,
            None if after.is_empty() => default_port,
            None => return Err(bad("trailing junk after bracketed host")),
        };
        return Ok((host.to_string(), port));
    }
    if s.matches(':').count() == 1 {
        let (host, port) = s.split_once(':').unwrap();
        let port = if port.is_empty() {
            default_port
        } else {
            port.parse()
                .map_err(|_| bad("invalid port in socket string"))?
        };
        return Ok((host.to_string(), port));
    }
    // Bare host (no colon) or bare IPv6 literal (many colons, no brackets).
    Ok((s.to_string(), default_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_socket_string_variants() {
        assert_eq!(
            parse_socket_string("127.0.0.1", 11211).unwrap(),
            ("127.0.0.1".to_string(), 11211)
        );
        assert_eq!(
            parse_socket_string("127.0.0.1:11", 11211).unwrap(),
            ("127.0.0.1".to_string(), 11)
        );
        assert_eq!(
            parse_socket_string("[::1]:2020", 11211).unwrap(),
            ("::1".to_string(), 2020)
        );
        assert_eq!(
            parse_socket_string("[::1]", 11211).unwrap(),
            ("::1".to_string(), 11211)
        );
        // bare IPv6 without brackets -> whole thing is the host
        assert_eq!(
            parse_socket_string("fe80::1", 11211).unwrap(),
            ("fe80::1".to_string(), 11211)
        );
        assert!(parse_socket_string("127.0.0.1:bogus", 11211).is_err());
    }

    #[test]
    fn read_response_frames_a_value() {
        let raw = b"VALUE abc 2 5\r\nhello\r\nEND\r\n";
        let mut cur = io::Cursor::new(raw.to_vec());
        assert_eq!(read_response(&mut cur).unwrap(), raw);
    }

    #[test]
    fn read_response_frames_single_line() {
        let mut cur = io::Cursor::new(b"STORED\r\n".to_vec());
        assert_eq!(read_response(&mut cur).unwrap(), b"STORED\r\n");
    }

    #[test]
    fn read_response_handles_crlf_in_value_data() {
        // The 7-byte payload contains its own CRLF; framing must not split on it.
        let raw = b"VALUE abc 0 7\r\na\r\nb\r\nc\r\nEND\r\n";
        let mut cur = io::Cursor::new(raw.to_vec());
        assert_eq!(read_response(&mut cur).unwrap(), raw);
    }
}
