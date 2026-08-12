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

//! Streaming multipart-MIME document parsing, the wire format of the
//! backend multiphase object PUT (`swift.common.utils.
//! iter_multipart_mime_documents` + `parse_mime_headers`): documents
//! separated by `\r\n--<boundary>\r\n`, terminated by
//! `\r\n--<boundary>--`, each document = RFC-822-ish headers, blank
//! line, body. The parser is pull-based and never buffers a document
//! body - object data flows through it in bounded chunks.

use std::io::Read;

const MAX_HEADER_LINE: usize = 8 * 1024;
const MAX_PART_HEADERS: usize = 32;
/// Internal look-ahead buffer target; also the largest single read.
const FILL_CHUNK: usize = 64 * 1024;

/// Pull-parser over a multipart stream. Call [`MimeDocs::next_document`]
/// to advance to the next part (draining any unread remainder of the
/// current one) and get its headers; then `Read` the part body from the
/// parser itself (EOF at the part boundary).
pub struct MimeDocs {
    reader: Box<dyn Read + Send>,
    /// `\r\n--<boundary>` - the separator between parts.
    delim: Vec<u8>,
    buf: Vec<u8>,
    /// buf[pos..] is unconsumed.
    pos: usize,
    /// Upstream returned EOF.
    upstream_eof: bool,
    state: State,
}

#[derive(PartialEq)]
enum State {
    /// Before the first `--<boundary>` line.
    Start,
    /// Positioned inside a part body.
    InPart,
    /// Consumed the final `--<boundary>--`.
    Finished,
}

impl MimeDocs {
    pub fn new(reader: Box<dyn Read + Send>, boundary: &[u8]) -> MimeDocs {
        let mut delim = b"\r\n--".to_vec();
        delim.extend_from_slice(boundary);
        MimeDocs {
            reader,
            delim,
            buf: Vec::new(),
            pos: 0,
            upstream_eof: false,
            state: State::Start,
        }
    }

    /// Advance to the next document: drain the current body (if any),
    /// consume the boundary line, and return the part's headers.
    /// `None` once the terminal `--<boundary>--` was seen.
    pub fn next_document(&mut self) -> std::io::Result<Option<Vec<(String, String)>>> {
        match self.state {
            State::Finished => return Ok(None),
            State::Start => {
                // Skip any leading blank lines, then require `--<boundary>`
                // (iter_multipart_mime_documents' starting-boundary check).
                loop {
                    let line = self.read_line()?;
                    if line == b"\r\n" || line == b"\n" {
                        continue;
                    }
                    let stripped = trim_crlf(&line);
                    if stripped != &self.delim[2..] {
                        return Err(bad("invalid starting boundary"));
                    }
                    break;
                }
                self.state = State::InPart;
            }
            State::InPart => {
                // Drain the rest of the current body through the boundary.
                let mut sink = [0u8; FILL_CHUNK];
                while self.read(&mut sink)? > 0 {}
                // read() stopped at the delimiter: consume it, then peek the
                // tail. `--` marks the terminal boundary (which may end the
                // stream with no trailing newline); anything else must be a
                // bare line ending before the next part's headers.
                self.consume(self.delim.len())?;
                while self.available().len() < 2 && !self.upstream_eof {
                    self.fill()?;
                }
                if self.available().starts_with(b"--") {
                    self.state = State::Finished;
                    return Ok(None);
                }
                let rest = self.read_line()?;
                if trim_crlf(&rest) != b"" {
                    return Err(bad("garbage after mime boundary"));
                }
            }
        }
        // Parse this part's headers.
        let mut headers = Vec::new();
        loop {
            let line = self.read_line()?;
            let line = trim_crlf(&line);
            if line.is_empty() {
                break;
            }
            if headers.len() >= MAX_PART_HEADERS {
                return Err(bad("too many mime part headers"));
            }
            let text = String::from_utf8_lossy(line);
            if let Some((name, value)) = text.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }
        Ok(Some(headers))
    }

    /// Refill the look-ahead buffer; true if any bytes were added.
    fn fill(&mut self) -> std::io::Result<bool> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let old = self.buf.len();
        let mut chunk = [0u8; FILL_CHUNK];
        let n = self.reader.read(&mut chunk)?;
        if n == 0 {
            self.upstream_eof = true;
            return Ok(false);
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(self.buf.len() > old)
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn consume(&mut self, n: usize) -> std::io::Result<()> {
        while self.available().len() < n {
            if !self.fill()? {
                return Err(truncated());
            }
        }
        self.pos += n;
        Ok(())
    }

    /// Read one `\n`-terminated line (bounded), consuming it.
    fn read_line(&mut self) -> std::io::Result<Vec<u8>> {
        loop {
            if let Some(idx) = self.available().iter().position(|b| *b == b'\n') {
                if idx + 1 > MAX_HEADER_LINE {
                    return Err(bad("mime line too long"));
                }
                let line = self.available()[..=idx].to_vec();
                self.pos += idx + 1;
                return Ok(line);
            }
            if self.available().len() > MAX_HEADER_LINE {
                return Err(bad("mime line too long"));
            }
            if !self.fill()? {
                return Err(truncated());
            }
        }
    }
}

impl Read for MimeDocs {
    /// Read the CURRENT document's body; `Ok(0)` at the part boundary
    /// (the delimiter itself is left unconsumed for `next_document`).
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.state != State::InPart || out.is_empty() {
            return Ok(0);
        }
        loop {
            let avail = self.available();
            if let Some(idx) = find(avail, &self.delim) {
                if idx == 0 {
                    return Ok(0); // positioned exactly at the delimiter
                }
                let n = idx.min(out.len());
                out[..n].copy_from_slice(&avail[..n]);
                self.pos += n;
                return Ok(n);
            }
            // No delimiter in view: serve what is safe (a delimiter could
            // straddle the buffer edge, so hold back its maximum prefix).
            let safe = avail.len().saturating_sub(self.delim.len() - 1);
            if safe > 0 {
                let n = safe.min(out.len());
                out[..n].copy_from_slice(&avail[..n]);
                self.pos += n;
                return Ok(n);
            }
            if !self.fill()? {
                // A part must end at a boundary; EOF inside a body is a
                // truncated stream.
                return Err(truncated());
            }
        }
    }
}

fn trim_crlf(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn bad(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string())
}

fn truncated() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "truncated mime document stream",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn docs(stream: &[u8], boundary: &[u8]) -> MimeDocs {
        MimeDocs::new(Box::new(Cursor::new(stream.to_vec())), boundary)
    }

    fn read_body(m: &mut MimeDocs) -> Vec<u8> {
        let mut out = Vec::new();
        m.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn parses_the_multiphase_put_shape() {
        // Exactly what MIMEPutter sends: object body doc, footer doc with
        // Content-MD5, non-terminal tail, then the commit doc + terminal.
        let stream = b"--bnd\r\nX-Document: object body\r\n\r\nOBJECT DATA\
                       \r\n--bnd\r\nX-Document: object metadata\r\nContent-MD5: 1234\r\n\r\n{\"Etag\":\"x\"}\
                       \r\n--bnd\r\nX-Document: put commit\r\n\r\nput_commit_confirmation\
                       \r\n--bnd--";
        let mut m = docs(stream, b"bnd");
        let h1 = m.next_document().unwrap().unwrap();
        assert_eq!(
            h1,
            vec![("X-Document".to_string(), "object body".to_string())]
        );
        assert_eq!(read_body(&mut m), b"OBJECT DATA");

        let h2 = m.next_document().unwrap().unwrap();
        assert_eq!(h2[0].1, "object metadata");
        assert_eq!(h2[1], ("Content-MD5".to_string(), "1234".to_string()));
        assert_eq!(read_body(&mut m), b"{\"Etag\":\"x\"}");

        let h3 = m.next_document().unwrap().unwrap();
        assert_eq!(h3[0].1, "put commit");
        assert_eq!(read_body(&mut m), b"put_commit_confirmation");

        assert!(m.next_document().unwrap().is_none());
        assert!(m.next_document().unwrap().is_none()); // stays finished
    }

    #[test]
    fn next_document_drains_an_unread_body() {
        let stream =
            b"--b\r\nA: 1\r\n\r\nlong body we never read\r\n--b\r\nB: 2\r\n\r\nsecond\r\n--b--";
        let mut m = docs(stream, b"b");
        m.next_document().unwrap().unwrap();
        // skip straight to the next part without reading the body
        let h2 = m.next_document().unwrap().unwrap();
        assert_eq!(h2, vec![("B".to_string(), "2".to_string())]);
        assert_eq!(read_body(&mut m), b"second");
        assert!(m.next_document().unwrap().is_none());
    }

    #[test]
    fn body_bytes_containing_boundary_prefixes_survive() {
        // Body full of \r\n-- sequences that are NOT the delimiter.
        let body = b"\r\n--not\r\n--bx\r\n--".repeat(500);
        let mut stream = b"--bound\r\nH: v\r\n\r\n".to_vec();
        stream.extend_from_slice(&body);
        stream.extend_from_slice(b"\r\n--bound--");
        let mut m = docs(&stream, b"bound");
        m.next_document().unwrap().unwrap();
        assert_eq!(read_body(&mut m), body);
        assert!(m.next_document().unwrap().is_none());
    }

    #[test]
    fn leading_blank_lines_are_skipped_and_bad_boundary_rejected() {
        let mut m = docs(b"\r\n\r\n--b\r\nH: v\r\n\r\nx\r\n--b--", b"b");
        assert!(m.next_document().unwrap().is_some());
        assert_eq!(read_body(&mut m), b"x");

        let mut m = docs(b"--WRONG\r\n\r\n", b"b");
        assert!(m.next_document().is_err());
    }

    #[test]
    fn truncation_is_an_error_not_eof() {
        let mut m = docs(b"--b\r\nH: v\r\n\r\nbody without terminat", b"b");
        m.next_document().unwrap().unwrap();
        let mut out = Vec::new();
        let err = m.read_to_end(&mut out).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn empty_document_bodies_parse() {
        let mut m = docs(b"--b\r\nA: 1\r\n\r\n\r\n--b\r\nB: 2\r\n\r\n\r\n--b--", b"b");
        m.next_document().unwrap().unwrap();
        assert_eq!(read_body(&mut m), b"");
        let h = m.next_document().unwrap().unwrap();
        assert_eq!(h[0].0, "B");
        assert_eq!(read_body(&mut m), b"");
        assert!(m.next_document().unwrap().is_none());
    }
}
