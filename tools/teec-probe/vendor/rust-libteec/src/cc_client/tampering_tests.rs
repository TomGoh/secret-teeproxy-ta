// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd.

use super::*;
use std::io::Cursor;

fn record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, 3, 3];
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[test]
fn tampering_disabled_preserves_all_bytes() {
    let data = record(APPLICATION_DATA, &[0x42; 32]);
    let mut stream = TamperingStream::new(Cursor::new(data.clone()));
    let mut got = Vec::new();
    stream.read_to_end(&mut got).unwrap();
    assert_eq!(got, data);
    assert_eq!(stream.injections(), 0);
}

#[test]
fn tampering_flips_ciphertext_once_across_every_read_fragment_size() {
    let mut data = record(22, &[0x33; 11]);
    data.extend(record(APPLICATION_DATA, &[0x42; 32]));
    data.extend(record(APPLICATION_DATA, &[0x51; 32]));
    let target = 5 + 11 + 5 + EXPLICIT_NONCE_LEN + 2;
    for chunk in 1..=data.len() {
        let mut stream = TamperingStream::new(Cursor::new(data.clone()));
        stream.arm(2).unwrap();
        let mut got = Vec::new();
        loop {
            let mut buf = vec![0; chunk];
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        let mut expected = data.clone();
        expected[target] ^= 1;
        assert_eq!(got, expected, "fragment size {chunk}");
        assert_eq!(stream.injections(), 1);
    }
}

#[test]
fn tampering_invalid_offset_never_changes_nonce_or_tag() {
    let mut stream = TamperingStream::new(Cursor::new(record(APPLICATION_DATA, &[0x42; 32])));
    stream.arm(8).unwrap(); // ciphertext length is eight bytes; offset eight is tag.
    assert_eq!(
        stream.read(&mut [0; 40]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(stream.injections(), 0);
    assert_eq!(
        TamperingStream::new(Cursor::new(Vec::<u8>::new()))
            .arm(MAX_PLAINTEXT_LEN)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn tampering_rejects_rearm_and_partial_record() {
    let mut stream = TamperingStream::new(Cursor::new(record(APPLICATION_DATA, &[0; 32])));
    stream.arm(0).unwrap();
    assert!(stream.arm(0).is_err());
    let mut other = TamperingStream::new(Cursor::new(record(APPLICATION_DATA, &[0; 32])));
    other.read_exact(&mut [0; 2]).unwrap();
    assert!(other.arm(0).is_err());
}

#[test]
fn tampering_empty_reads_and_eof_do_not_count_as_injection() {
    let mut stream = TamperingStream::new(Cursor::new(Vec::<u8>::new()));
    stream.arm(0).unwrap();
    assert_eq!(stream.read(&mut []).unwrap(), 0);
    assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
    assert_eq!(stream.injections(), 0);
}

struct InterruptedOnce {
    data: Cursor<Vec<u8>>,
    interrupted: bool,
}
impl Read for InterruptedOnce {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.data.read(bytes)
    }
}
impl Write for InterruptedOnce {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.data.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.data.flush()
    }
}

#[test]
fn tampering_interrupted_read_preserves_the_pending_target() {
    let data = record(APPLICATION_DATA, &[0x42; 32]);
    let mut stream = TamperingStream::new(InterruptedOnce {
        data: Cursor::new(data.clone()),
        interrupted: false,
    });
    stream.arm(0).unwrap();
    assert_eq!(
        stream.read(&mut [0; 2]).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    let mut got = Vec::new();
    stream.read_to_end(&mut got).unwrap();
    let mut expected = data;
    expected[HEADER_LEN + EXPLICIT_NONCE_LEN] ^= 1;
    assert_eq!(got, expected);
    assert_eq!(stream.injections(), 1);
}

#[test]
fn tampering_does_not_modify_writes() {
    let mut stream = TamperingStream::new(Cursor::new(vec![0; 32]));
    stream.arm(0).unwrap();
    stream.write_all(b"unchanged").unwrap();
    assert_eq!(&stream.inner.into_inner()[..9], b"unchanged");
}

#[test]
fn tampering_only_accepts_tls_mac_errors_as_authentication_failure() {
    use crate::attack_test::AttackTestCcClient;
    assert!(AttackTestCcClient::is_authentication_failure(
        &codes::SslInvalidMac.into()
    ));
    for error in [
        codes::NetRecvFailed.into(),
        codes::SslTimeout.into(),
        codes::SslPeerCloseNotify.into(),
    ] {
        assert!(!AttackTestCcClient::is_authentication_failure(&error));
    }
}

fn tls_config(endpoint: mbedtls::ssl::config::Endpoint) -> std::sync::Arc<mbedtls::ssl::Config> {
    use mbedtls::{
        rng::{CtrDrbg, OsEntropy},
        ssl::{
            CipherSuite::EcdhePskWithSm4128GcmSm3,
            Config, Version,
            config::{Preset, Transport},
        },
    };
    let mut config = Config::new(endpoint, Transport::Stream, Preset::Default);
    config.set_min_version(Version::Tls1_2).unwrap();
    config.set_max_version(Version::Tls1_2).unwrap();
    config.set_ciphersuites(std::sync::Arc::new(vec![
        EcdhePskWithSm4128GcmSm3.into(),
        0,
    ]));
    config.set_rng(std::sync::Arc::new(
        CtrDrbg::new(std::sync::Arc::new(OsEntropy::new()), None).unwrap(),
    ));
    config
        .set_psk(&[0x42; 32], "tls-tampering-unit-test")
        .unwrap();
    std::sync::Arc::new(config)
}

#[test]
fn tampering_real_sm4_gcm_rejects_ciphertext_and_unarmed_connections_succeed() {
    use mbedtls::ssl::{
        Context,
        config::Endpoint,
        io::{AnyIo, Io},
    };
    use std::{
        net::{TcpListener, TcpStream},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };
    for should_corrupt in [false, true] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut ctx = Context::new(tls_config(Endpoint::Server));
            ctx.establish(tcp, None).unwrap();
            for _ in 0..2 {
                let mut request = [0; 1];
                ctx.read_exact(&mut request).unwrap();
                ctx.write_all(b"authenticated response").unwrap();
            }
        });
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new(tls_config(Endpoint::Client));
        ctx.establish::<AnyIo>(
            TamperingStream::with_counter(tcp, Arc::clone(&counter)),
            None,
        )
        .unwrap();
        assert_eq!(ctx.version(), mbedtls::ssl::Version::Tls1_2);
        ctx.write_all(b"1").unwrap();
        let mut baseline = [0; 22];
        ctx.read_exact(&mut baseline).unwrap();
        assert_eq!(&baseline, b"authenticated response");
        if should_corrupt {
            ctx.io_mut().unwrap().arm(0).unwrap();
        }
        ctx.write_all(b"2").unwrap();
        let mut response = [0; 22];
        let result = Io::recv(&mut ctx, &mut response);
        server.join().unwrap();
        if should_corrupt {
            assert!(
                crate::attack_test::AttackTestCcClient::is_authentication_failure(
                    &result.unwrap_err()
                )
            );
            assert_eq!(ctx.io().unwrap().injections(), 1);
            ctx.close();
            assert_eq!(
                counter.load(Ordering::Relaxed),
                1,
                "the injection total must survive closing the TLS connection"
            );
        } else {
            assert_eq!(result.unwrap(), response.len());
            assert_eq!(&response, b"authenticated response");
            assert_eq!(ctx.io().unwrap().injections(), 0);
        }
    }
}
