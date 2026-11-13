// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd.

//! Opt-in TLS 1.2 SM4-GCM ciphertext injection for regression tests.
//!
//! Enabling `attack-test` only makes this separate client available. It never
//! installs global hooks, changes ordinary TEEC clients, or arms injection on
//! initialization. This client uses the production VSOCK/ECDH/TOFU/TLS policy.

use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use mbedtls::{
    error::codes,
    ssl::{
        CipherSuite, Context,
        io::{AnyIo, Io},
    },
};
use teec_protocol::{PacketHeader, PacketType};
use virga::client::VirgeClient;

use crate::cc_client::{client::connect_and_configure, tampering::TamperingStream};

/// A separate client whose raw TLS reads can be explicitly corrupted once.
///
/// This test utility neither owns nor automatically closes manager TA sessions.
/// The caller must retain session IDs and clean them through a fresh connection
/// if a TLS authentication failure makes the original connection unusable.
pub struct AttackTestCcClient {
    ctx: Context<TamperingStream<VirgeClient>>,
    /// Owned outside the TLS I/O object so the total stays readable after close.
    injections: Arc<AtomicUsize>,
}

impl AttackTestCcClient {
    /// Establishes production TLS with injection disabled.
    pub fn init() -> mbedtls::Result<Self> {
        let (client, config) = connect_and_configure()?;
        let injections = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new(config);
        ctx.establish::<AnyIo>(
            TamperingStream::with_counter(client, Arc::clone(&injections)),
            None,
        )?;
        Ok(Self { ctx, injections })
    }

    /// Arms a one-bit flip in the next application-data record's ciphertext.
    ///
    /// `offset` starts after the TLS 1.2 GCM explicit nonce. The offset must fit
    /// the selected record's ciphertext, excluding its authentication tag. Call
    /// only after the previous response was fully read, before the next request.
    /// Framing/non-application records pass unchanged. An invalid target fails
    /// the read and never counts as an injection.
    pub fn enable_read_tampering_at(&mut self, offset: usize) -> io::Result<()> {
        self.ctx
            .io_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TLS closed"))?
            .arm(offset)
    }

    /// Number of ciphertext bytes actually flipped on this connection.
    ///
    /// The total is owned by the client rather than the TLS I/O object, so it
    /// keeps reporting the real count after [`Self::close`].
    pub fn tampering_count(&self) -> usize {
        self.injections.load(Ordering::Relaxed)
    }

    /// Checks the negotiated production SM4-GCM cipher suite.
    pub fn is_sm4_gcm(&self) -> bool {
        let expected: i32 = CipherSuite::EcdhePskWithSm4128GcmSm3.into();
        self.ctx
            .ciphersuite()
            .is_ok_and(|suite| i32::from(suite) == expected)
    }

    /// Sends the normal production application framing over TLS.
    pub fn send_data_with_header(
        &mut self,
        packet_type: PacketType,
        data: &[u8],
    ) -> io::Result<()> {
        let header = PacketHeader {
            data_type: packet_type.into(),
            data_size: data.len() as u64,
        };
        self.ctx.write_all(header.as_bytes())?;
        self.ctx.write_all(data)
    }

    /// Reads an exact plaintext length, preserving the typed TLS failure.
    pub fn recv_data(&mut self, mut bytes: &mut [u8]) -> mbedtls::Result<()> {
        while !bytes.is_empty() {
            let count = Io::recv(&mut self.ctx, bytes)?;
            if count == 0 {
                return Err(codes::NetRecvFailed.into());
            }
            bytes = &mut bytes[count..];
        }
        Ok(())
    }

    /// Recognizes a TLS record authentication failure, excluding transport errors.
    pub fn is_authentication_failure(error: &mbedtls::Error) -> bool {
        error.high_level() == Some(codes::SslInvalidMac)
    }

    /// Closes the TLS connection; it does not send TA CloseSession requests.
    pub fn close(&mut self) {
        self.ctx.close();
    }
}
