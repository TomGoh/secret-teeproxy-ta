//! Bounded HTTP/1.1 response framing. Business body bytes are never rewritten.
use std::collections::VecDeque;

use serde_json::json;

use crate::relay::{Header, MAX_PENDING, RelayError};

pub(crate) const MAX_HEADER: usize = 4096;
const MAX_INFORMATIONAL: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Framing {
    Headers,
    Length(u64),
    Eof,
    ChunkSize,
    ChunkData(u64),
    ChunkCrlf,
    Trailers,
    Complete,
}

pub(crate) struct ResponseParser {
    input: Vec<u8>,
    pub(crate) body: VecDeque<u8>,
    pub(crate) head: Option<Vec<u8>>,
    framing: Framing,
    pub(crate) received_body: u64,
    started: bool,
    invalid: bool,
    informational: usize,
    trailer_bytes: usize,
}

impl ResponseParser {
    pub(crate) fn new() -> Self {
        Self {
            input: Vec::new(),
            body: VecDeque::new(),
            head: None,
            framing: Framing::Headers,
            received_body: 0,
            started: false,
            invalid: false,
            informational: 0,
            trailer_bytes: 0,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        (MAX_PENDING - self.input.len()).min(MAX_PENDING - self.body.len())
    }

    pub(crate) fn complete(&self) -> bool {
        self.framing == Framing::Complete
    }

    pub(crate) fn framing(&self) -> &'static str {
        if self.invalid {
            "invalid"
        } else if self.complete() {
            "complete"
        } else if self.started {
            "in_progress"
        } else {
            "not_started"
        }
    }

    pub(crate) fn clear(&mut self) {
        self.input = Vec::new();
        self.body = VecDeque::new();
        self.head = None;
    }

    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<(), RelayError> {
        if bytes.len() > self.capacity() {
            return Err(RelayError::http_limit());
        }
        self.started |= !bytes.is_empty();
        self.input.extend_from_slice(bytes);
        let result = self.parse();
        self.invalid |= result.is_err();
        result
    }

    pub(crate) fn eof(&mut self) -> Result<(), RelayError> {
        self.feed(&[])?;
        if self.framing == Framing::Eof && self.input.is_empty() {
            self.framing = Framing::Complete;
        }
        if self.complete() {
            Ok(())
        } else {
            self.invalid = true;
            Err(RelayError::http())
        }
    }

    fn parse(&mut self) -> Result<(), RelayError> {
        loop {
            match self.framing {
                Framing::Headers => {
                    let Some(end) = boundary(&self.input, b"\r\n\r\n") else {
                        if self.input.len() > MAX_HEADER {
                            return Err(RelayError::http_limit());
                        }
                        return Ok(());
                    };
                    if end + 4 > MAX_HEADER {
                        return Err(RelayError::http_limit());
                    }
                    let raw = self.input.drain(..end + 4).collect::<Vec<_>>();
                    self.parse_head(&raw[..end])?;
                }
                Framing::Length(remaining) => {
                    let copied = self.copy_body(remaining);
                    let left = remaining - copied as u64;
                    self.framing = if left == 0 {
                        Framing::Complete
                    } else {
                        Framing::Length(left)
                    };
                    if copied == 0 && left > 0 {
                        return Ok(());
                    }
                }
                Framing::Eof => {
                    self.copy_body(u64::MAX);
                    return Ok(());
                }
                Framing::ChunkSize => {
                    let Some(end) = boundary(&self.input, b"\r\n") else {
                        if self.input.len() > 1024 {
                            return Err(RelayError::http_limit());
                        }
                        return Ok(());
                    };
                    if end > 1024 {
                        return Err(RelayError::http_limit());
                    }
                    let line = self.input.drain(..end + 2).collect::<Vec<_>>();
                    let size = parse_chunk_size(&line[..end])?;
                    self.framing = if size == 0 {
                        Framing::Trailers
                    } else {
                        Framing::ChunkData(size)
                    };
                }
                Framing::ChunkData(remaining) => {
                    let copied = self.copy_body(remaining);
                    let left = remaining - copied as u64;
                    self.framing = if left == 0 {
                        Framing::ChunkCrlf
                    } else {
                        Framing::ChunkData(left)
                    };
                    if copied == 0 && left > 0 {
                        return Ok(());
                    }
                }
                Framing::ChunkCrlf => {
                    if self.input.len() < 2 {
                        return Ok(());
                    }
                    if !self.input.starts_with(b"\r\n") {
                        return Err(RelayError::http());
                    }
                    self.input.drain(..2);
                    self.framing = Framing::ChunkSize;
                }
                Framing::Trailers => {
                    let Some(end) = boundary(&self.input, b"\r\n") else {
                        if self.input.len() + self.trailer_bytes > MAX_HEADER {
                            return Err(RelayError::http_limit());
                        }
                        return Ok(());
                    };
                    self.trailer_bytes += end + 2;
                    if self.trailer_bytes > MAX_HEADER {
                        return Err(RelayError::http_limit());
                    }
                    let line = self.input.drain(..end + 2).collect::<Vec<_>>();
                    if end == 0 {
                        self.framing = Framing::Complete;
                    } else {
                        let header = parse_header(&line[..end])?;
                        if matches!(
                            header.name.as_str(),
                            "content-length" | "transfer-encoding" | "host" | "content-encoding"
                        ) {
                            return Err(RelayError::http());
                        }
                    }
                }
                Framing::Complete => {
                    if !self.input.is_empty() {
                        return Err(RelayError::http());
                    }
                    return Ok(());
                }
            }
        }
    }

    fn copy_body(&mut self, remaining: u64) -> usize {
        let count = self
            .input
            .len()
            .min(MAX_PENDING - self.body.len())
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        self.body.extend(self.input.drain(..count));
        self.received_body += count as u64;
        count
    }

    fn parse_head(&mut self, raw: &[u8]) -> Result<(), RelayError> {
        if raw.iter().enumerate().any(|(index, &byte)| {
            (byte == b'\n' && (index == 0 || raw[index - 1] != b'\r'))
                || (byte == b'\r' && raw.get(index + 1) != Some(&b'\n'))
        }) {
            return Err(RelayError::http());
        }
        let mut lines = raw.split(|&byte| byte == b'\n');
        let status_line = lines.next().ok_or_else(RelayError::http)?;
        let status_line = status_line.strip_suffix(b"\r").unwrap_or(status_line);
        if status_line.len() < 12
            || !matches!(&status_line[..9], b"HTTP/1.1 " | b"HTTP/1.0 ")
            || !status_line[9..12].iter().all(u8::is_ascii_digit)
            || (status_line.len() > 12 && status_line[12] != b' ')
            || status_line.iter().any(|&b| b < 32 && b != b'\t')
        {
            return Err(RelayError::http());
        }
        let status = std::str::from_utf8(&status_line[9..12])
            .unwrap()
            .parse::<u16>()
            .map_err(|_| RelayError::http())?;
        if !(100..=599).contains(&status) || status == 101 {
            return Err(RelayError::http());
        }
        let mut headers = Vec::new();
        let mut length = None;
        let mut chunked = false;
        for line in lines {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let header = parse_header(line)?;
            match header.name.as_str() {
                "content-length" => {
                    if length.is_some()
                        || header.value.is_empty()
                        || !header.value.bytes().all(|b| b.is_ascii_digit())
                    {
                        return Err(RelayError::http());
                    }
                    length = Some(
                        header
                            .value
                            .parse::<u64>()
                            .map_err(|_| RelayError::http())?,
                    );
                }
                "transfer-encoding" => {
                    if chunked || !header.value.eq_ignore_ascii_case("chunked") {
                        return Err(RelayError::http());
                    }
                    chunked = true;
                }
                "content-encoding" if !header.value.eq_ignore_ascii_case("identity") => {
                    return Err(RelayError::content_encoding());
                }
                _ => {}
            }
            headers.push(header);
            if headers.len() > 128 {
                return Err(RelayError::http_limit());
            }
        }
        if length.is_some() && chunked {
            return Err(RelayError::http());
        }
        if status < 200 {
            if length.is_some() || chunked {
                return Err(RelayError::http());
            }
            self.informational += 1;
            if self.informational > MAX_INFORMATIONAL {
                return Err(RelayError::http_limit());
            }
            return Ok(());
        }
        let encoded = serde_json::to_vec(&json!({"status":status,"headers":headers}))
            .map_err(|_| RelayError::internal())?;
        if encoded.len() > MAX_HEADER {
            return Err(RelayError::http_limit());
        }
        self.head = Some(encoded);
        self.framing = if status == 204 || status == 304 {
            if chunked || (status == 204 && length.is_some()) {
                return Err(RelayError::http());
            }
            Framing::Complete
        } else if chunked {
            Framing::ChunkSize
        } else if let Some(length) = length {
            Framing::Length(length)
        } else {
            Framing::Eof
        };
        Ok(())
    }
}

fn boundary(bytes: &[u8], delimiter: &[u8]) -> Option<usize> {
    bytes
        .windows(delimiter.len())
        .position(|window| window == delimiter)
}

pub(crate) fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn parse_header(line: &[u8]) -> Result<Header, RelayError> {
    let split = line
        .iter()
        .position(|&byte| byte == b':')
        .ok_or_else(RelayError::http)?;
    if split == 0 || !line[..split].iter().copied().all(token) {
        return Err(RelayError::http());
    }
    let value = &line[split + 1..];
    if value
        .iter()
        .any(|&byte| byte < 32 && byte != b'\t' || byte == 127)
    {
        return Err(RelayError::http());
    }
    let value = std::str::from_utf8(value)
        .map_err(|_| RelayError::http())?
        .trim_matches([' ', '\t']);
    Ok(Header {
        name: String::from_utf8(line[..split].to_ascii_lowercase()).unwrap(),
        value: value.into(),
    })
}

fn parse_chunk_size(line: &[u8]) -> Result<u64, RelayError> {
    let end = line
        .iter()
        .position(|&byte| byte == b';')
        .unwrap_or(line.len());
    if end == 0 || end > 16 || !line[..end].iter().all(u8::is_ascii_hexdigit) {
        return Err(RelayError::http());
    }
    let mut extension = &line[end..];
    while !extension.is_empty() {
        extension = extension.strip_prefix(b";").ok_or_else(RelayError::http)?;
        let name_end = extension
            .iter()
            .position(|&b| !token(b))
            .unwrap_or(extension.len());
        if name_end == 0 {
            return Err(RelayError::http());
        }
        extension = &extension[name_end..];
        if extension.starts_with(b"=") {
            extension = &extension[1..];
            if extension.starts_with(b"\"") {
                extension = &extension[1..];
                loop {
                    let (&byte, rest) = extension.split_first().ok_or_else(RelayError::http)?;
                    extension = rest;
                    if byte == b'"' {
                        break;
                    }
                    if byte == b'\\' {
                        let (&escaped, rest) =
                            extension.split_first().ok_or_else(RelayError::http)?;
                        if !(32..=126).contains(&escaped) {
                            return Err(RelayError::http());
                        }
                        extension = rest;
                    } else if !(32..=126).contains(&byte) {
                        return Err(RelayError::http());
                    }
                }
            } else {
                let value_end = extension
                    .iter()
                    .position(|&b| !token(b))
                    .unwrap_or(extension.len());
                if value_end == 0 {
                    return Err(RelayError::http());
                }
                extension = &extension[value_end..];
            }
        }
    }
    u64::from_str_radix(std::str::from_utf8(&line[..end]).unwrap(), 16)
        .map_err(|_| RelayError::http())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_chunked_preserves_body_and_trailers() {
        let mut parser = ResponseParser::new();
        for byte in b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=\"a;b\"\r\na\nb\r\n2\r\n{}\r\n0\r\nX-Trailer: yes\r\n\r\n" {
            parser.feed(&[*byte]).unwrap();
        }
        assert!(parser.complete());
        assert_eq!(parser.body.into_iter().collect::<Vec<_>>(), b"a\nb{}");
    }

    #[test]
    fn rejects_ambiguous_and_encoded_responses() {
        for raw in [
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nx",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\nx\r\n",
            "HTTP/1.1 200 OK\r\nBad : yes\r\n\r\n",
        ] {
            assert!(ResponseParser::new().feed(raw.as_bytes()).is_err(), "{raw}");
        }
    }

    #[test]
    fn header_limit_matches_advertised_four_kib_budget() {
        let mut parser = ResponseParser::new();
        let oversized = format!(
            "HTTP/1.1 200 OK\r\nX-Large: {}\r\n\r\n",
            "x".repeat(MAX_HEADER)
        );
        assert_eq!(
            parser.feed(oversized.as_bytes()).unwrap_err().code,
            "E_HTTP_LIMIT"
        );
        let mut parser = ResponseParser::new();
        // JSON escaping can exceed the encoded cap before raw headers exceed it.
        let encoded_oversized = format!(
            "HTTP/1.1 200 OK\r\nX-Large: {}\r\nContent-Length: 0\r\n\r\n",
            "\\".repeat(MAX_HEADER / 2)
        );
        assert!(encoded_oversized.len() < MAX_HEADER);
        assert_eq!(
            parser.feed(encoded_oversized.as_bytes()).unwrap_err().code,
            "E_HTTP_LIMIT"
        );
    }

    #[test]
    fn truncated_fixed_or_chunked_is_failure_and_eof_requires_eof() {
        for raw in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n".as_slice(),
        ] {
            let mut parser = ResponseParser::new();
            parser.feed(raw).unwrap();
            assert!(parser.eof().is_err());
        }
        let mut parser = ResponseParser::new();
        parser.feed(b"HTTP/1.1 200 OK\r\n\r\nx").unwrap();
        parser.feed(&[]).unwrap();
        assert!(!parser.complete());
        parser.eof().unwrap();
        assert!(parser.complete());
    }
}
