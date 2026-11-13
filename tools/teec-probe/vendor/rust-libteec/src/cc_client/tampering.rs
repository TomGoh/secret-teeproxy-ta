// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd.

//! Test-only TLS 1.2 record-aware read injection, below decryption.

use std::{
    io::{self, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use mbedtls::{error::codes, ssl::io::Io};

const HEADER_LEN: usize = 5;
const APPLICATION_DATA: u8 = 23;
const EXPLICIT_NONCE_LEN: usize = 8;
const TAG_LEN: usize = 16;
const MAX_PLAINTEXT_LEN: usize = 16 * 1024;

pub(crate) struct TamperingStream<T> {
    inner: T,
    header: [u8; HEADER_LEN],
    header_used: usize,
    body_len: usize,
    body_used: usize,
    pending_offset: Option<usize>,
    /// Shared with the client so the total survives dropping the TLS I/O on close.
    injections: Arc<AtomicUsize>,
}

impl<T> TamperingStream<T> {
    /// Builds a stream that records injections into `injections`.
    pub(crate) fn with_counter(inner: T, injections: Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            header: [0; HEADER_LEN],
            header_used: 0,
            body_len: 0,
            body_used: 0,
            pending_offset: None,
            injections,
        }
    }

    #[cfg(test)]
    pub(crate) fn new(inner: T) -> Self {
        Self::with_counter(inner, Arc::new(AtomicUsize::new(0)))
    }

    pub(crate) fn arm(&mut self, ciphertext_offset: usize) -> io::Result<()> {
        if ciphertext_offset >= MAX_PLAINTEXT_LEN || self.pending_offset.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid or already armed injection",
            ));
        }
        if self.header_used != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "injection must start at a record boundary",
            ));
        }
        self.pending_offset = Some(ciphertext_offset);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn injections(&self) -> usize {
        self.injections.load(Ordering::Relaxed)
    }

    fn inspect(&mut self, mut bytes: &mut [u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.header_used < HEADER_LEN {
                let count = (HEADER_LEN - self.header_used).min(bytes.len());
                self.header[self.header_used..self.header_used + count]
                    .copy_from_slice(&bytes[..count]);
                self.header_used += count;
                bytes = &mut bytes[count..];
                if self.header_used < HEADER_LEN {
                    continue;
                }
                self.body_len = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                self.body_used = 0;
                if self.body_len == 0 {
                    self.header_used = 0;
                    continue;
                }
            }
            let count = (self.body_len - self.body_used).min(bytes.len());
            if self.header[0] == APPLICATION_DATA
                && let Some(offset) = self.pending_offset
            {
                // TLS 1.2 GCM payload is explicit nonce || ciphertext || tag.
                // Never corrupt framing, nonce or tag and call it ciphertext.
                let target = EXPLICIT_NONCE_LEN + offset;
                if self.header[1..3] != [3, 3]
                    || self.body_len <= EXPLICIT_NONCE_LEN + TAG_LEN
                    || target >= self.body_len - TAG_LEN
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "target is outside TLS 1.2 GCM ciphertext",
                    ));
                }
                if (self.body_used..self.body_used + count).contains(&target) {
                    bytes[target - self.body_used] ^= 1;
                    self.pending_offset = None;
                    self.injections.fetch_add(1, Ordering::Relaxed);
                }
            }
            self.body_used += count;
            bytes = &mut bytes[count..];
            if self.body_used == self.body_len {
                self.header_used = 0;
            }
        }
        Ok(())
    }
}

impl<T: Read> Read for TamperingStream<T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(bytes)?;
        self.inspect(&mut bytes[..count])?;
        Ok(count)
    }
}

impl<T: Write> Write for TamperingStream<T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// AnyIo preserves the typed mbedTLS error at Context::recv; its std::io Read
// implementation turns that error into a string, losing the exact MAC code.
impl<T: Read + Write> Io for TamperingStream<T> {
    fn recv(&mut self, bytes: &mut [u8]) -> mbedtls::Result<usize> {
        loop {
            match self.read(bytes) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Err(codes::SslWantRead.into());
                }
                Err(_) => return Err(codes::NetRecvFailed.into()),
                Ok(count) => return Ok(count),
            }
        }
    }

    fn send(&mut self, bytes: &[u8]) -> mbedtls::Result<usize> {
        loop {
            match self.write(bytes) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Err(codes::SslWantWrite.into());
                }
                Err(_) => return Err(codes::NetSendFailed.into()),
                Ok(count) => return Ok(count),
            }
        }
    }
}

#[cfg(test)]
#[path = "tampering_tests.rs"]
mod tests;
