// SPDX-License-Identifier: Apache-2.0

use std::io::{Error as IoError, ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use xtee_utee::error::Error as TaError;
use xtee_utee::ta_manager::{TAManager, TAManagerConfig, TrustedApplication};
use xtee_utee::tee_api_defines::TEE_SUCCESS;
use xtee_utee::{Parameters, TARequest, TEE_Request, TEE_Response};

static TEST_GUARD: Mutex<()> = Mutex::new(());

fn lock_test_guard() -> std::sync::MutexGuard<'static, ()> {
    TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Clone, Copy)]
struct TestTa;

impl TrustedApplication for TestTa {
    type SessionContext = u32;

    fn create(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn open_session(
        &self,
        _params: &mut Parameters,
    ) -> xtee_utee::error::Result<Self::SessionContext> {
        Ok(1)
    }

    fn close_session(&self, _ctx: &mut Self::SessionContext) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn destroy(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn invoke_command(
        &self,
        cmd_id: u32,
        params: &mut Parameters,
        _ctx: &mut Self::SessionContext,
    ) -> xtee_utee::error::Result<()> {
        params.0.param.values.a = cmd_id;
        params.0.param.values.b = 0xBEEF;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ExclusiveTa;

impl TrustedApplication for ExclusiveTa {
    const IS_SINGLE_INSTANCE: bool = true;
    const IS_MULTI_SESSION: bool = false;
    type SessionContext = u32;

    fn create(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn open_session(
        &self,
        _params: &mut Parameters,
    ) -> xtee_utee::error::Result<Self::SessionContext> {
        Ok(1)
    }

    fn close_session(&self, _ctx: &mut Self::SessionContext) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn destroy(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn invoke_command(
        &self,
        _cmd_id: u32,
        _params: &mut Parameters,
        _ctx: &mut Self::SessionContext,
    ) -> xtee_utee::error::Result<()> {
        Ok(())
    }
}

/// `IS_INSTANCE_KEEP_ALIVE=true`：末会话关闭后监听仍保持（与 `instance_keepalive` 真实 TA 对齐）。
#[derive(Clone, Copy)]
struct KeepAliveTa;

impl TrustedApplication for KeepAliveTa {
    const IS_SINGLE_INSTANCE: bool = true;
    const IS_MULTI_SESSION: bool = true;
    const IS_INSTANCE_KEEP_ALIVE: bool = true;
    type SessionContext = u32;

    fn create(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn open_session(
        &self,
        _params: &mut Parameters,
    ) -> xtee_utee::error::Result<Self::SessionContext> {
        Ok(1)
    }

    fn close_session(&self, _ctx: &mut Self::SessionContext) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn destroy(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn invoke_command(
        &self,
        cmd_id: u32,
        params: &mut Parameters,
        _ctx: &mut Self::SessionContext,
    ) -> xtee_utee::error::Result<()> {
        params.0.param.values.a = cmd_id;
        params.0.param.values.b = 0xBEEF;
        Ok(())
    }
}

/// 与 `multi_session_shutdown` 真实 TA 对齐：`single+multi`，无 keep_alive；进程内单调计数。
static MULTI_SESSION_SHUTDOWN_COUNTER: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
struct MultiSessionShutdownTa;

impl TrustedApplication for MultiSessionShutdownTa {
    const IS_SINGLE_INSTANCE: bool = true;
    const IS_MULTI_SESSION: bool = true;
    type SessionContext = u32;

    fn create(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn open_session(
        &self,
        _params: &mut Parameters,
    ) -> xtee_utee::error::Result<Self::SessionContext> {
        Ok(1)
    }

    fn close_session(&self, _ctx: &mut Self::SessionContext) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn destroy(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn invoke_command(
        &self,
        cmd_id: u32,
        params: &mut Parameters,
        _ctx: &mut Self::SessionContext,
    ) -> xtee_utee::error::Result<()> {
        if cmd_id != 1 {
            return Err(TaError::BadParameters);
        }
        let v = MULTI_SESSION_SHUTDOWN_COUNTER.fetch_add(1, Ordering::Relaxed);
        params.0.param.values.a = v;
        params.0.param.values.b = 0;
        Ok(())
    }
}

/// `single+multi+keep_alive`：与 `multi_session_keepalive` 真实 TA 对齐；计数全关会话后仍延续。
static MULTI_SESSION_KEEPALIVE_COUNTER: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
struct MultiSessionKeepAliveTa;

impl TrustedApplication for MultiSessionKeepAliveTa {
    const IS_SINGLE_INSTANCE: bool = true;
    const IS_MULTI_SESSION: bool = true;
    const IS_INSTANCE_KEEP_ALIVE: bool = true;
    type SessionContext = u32;

    fn create(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn open_session(
        &self,
        _params: &mut Parameters,
    ) -> xtee_utee::error::Result<Self::SessionContext> {
        Ok(1)
    }

    fn close_session(&self, _ctx: &mut Self::SessionContext) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn destroy(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn invoke_command(
        &self,
        cmd_id: u32,
        params: &mut Parameters,
        _ctx: &mut Self::SessionContext,
    ) -> xtee_utee::error::Result<()> {
        if cmd_id != 1 {
            return Err(TaError::BadParameters);
        }
        let v = MULTI_SESSION_KEEPALIVE_COUNTER.fetch_add(1, Ordering::Relaxed);
        params.0.param.values.a = v;
        params.0.param.values.b = 0;
        Ok(())
    }
}

/// `ta_flags` 全默认（single/multi/keep_alive 均为 false）：与 `multi_instance_singleton` 真实 TA 对齐。
static MULTI_INSTANCE_SINGLETON_COUNTER: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
struct MultiInstanceSingletonTa;

impl TrustedApplication for MultiInstanceSingletonTa {
    type SessionContext = u32;

    fn create(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn open_session(
        &self,
        _params: &mut Parameters,
    ) -> xtee_utee::error::Result<Self::SessionContext> {
        Ok(1)
    }

    fn close_session(&self, _ctx: &mut Self::SessionContext) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn destroy(&self) -> xtee_utee::error::Result<()> {
        Ok(())
    }

    fn invoke_command(
        &self,
        cmd_id: u32,
        params: &mut Parameters,
        _ctx: &mut Self::SessionContext,
    ) -> xtee_utee::error::Result<()> {
        if cmd_id != 1 {
            return Err(TaError::BadParameters);
        }
        let v = MULTI_INSTANCE_SINGLETON_COUNTER.fetch_add(1, Ordering::Relaxed);
        params.0.param.values.a = v;
        params.0.param.values.b = 0;
        Ok(())
    }
}

fn unique_test_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "xtee-utee-{}-{}-{}",
        tag,
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("socket not ready: {}", path.display());
}

fn spawn_registry(registry_socket: PathBuf) -> (thread::JoinHandle<()>, mpsc::Receiver<TARequest>) {
    let (tx, rx) = mpsc::channel();
    // Bind on this thread so `TAManager::register_ta` never races a not-yet-listening registry
    // (otherwise `connect` can fail / hang oddly and `register_rx` times out).
    let _ = std::fs::remove_file(&registry_socket);
    let listener = UnixListener::bind(&registry_socket).expect("bind registry socket");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept register stream");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set read timeout");

        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if let Ok(req) = postcard::from_bytes::<TARequest>(&buf) {
                        tx.send(req).expect("send register req");
                        return;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    break;
                }
                Err(e) => panic!("registry read failed: {e}"),
            }
        }
        panic!("registry did not receive valid TARequest::Register");
    });
    (handle, rx)
}

fn send_request(listener_socket: &Path, req: TEE_Request) -> TEE_Response {
    let mut stream = UnixStream::connect(listener_socket).expect("connect ta listener");
    send_request_on_stream(&mut stream, req).expect("send request over stream")
}

fn send_request_try(listener_socket: &Path, req: TEE_Request) -> std::io::Result<TEE_Response> {
    let mut stream = UnixStream::connect(listener_socket)?;
    send_request_on_stream(&mut stream, req)
}

fn send_request_on_stream(
    stream: &mut UnixStream,
    req: TEE_Request,
) -> std::io::Result<TEE_Response> {
    let payload = postcard::to_allocvec(&req).expect("serialize request");
    stream.write_all(&(payload.len() as u32).to_ne_bytes())?;
    stream.write_all(&payload)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_ne_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    postcard::from_bytes::<TEE_Response>(&body)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("deserialize response: {e}")))
}

#[test]
fn smoke_case_open_invoke_close() {
    let _guard = lock_test_guard();
    let uuid = "sanity-smoke-uuid";
    let temp_dir = unique_test_dir("smoke");
    let registry_socket = temp_dir.join("server.sock");
    let listener_socket = temp_dir.join("ta.sock");

    let (registry_handle, register_rx) = spawn_registry(registry_socket.clone());

    let config = TAManagerConfig {
        registry_socket_path: registry_socket,
        listener_socket_path: listener_socket.clone(),
        instance_id: 101,
    };

    let manager_handle = thread::spawn(move || {
        let mut manager = TAManager::new_with_config(TestTa, uuid, config);
        manager.run_ta()
    });

    let register_req = register_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("receive register request");
    match register_req {
        TARequest::Register {
            uuid: got_uuid,
            instance_id,
            socket_path,
            ..
        } => {
            assert_eq!(got_uuid, uuid);
            assert_eq!(instance_id, 101);
            assert_eq!(socket_path, listener_socket.display().to_string());
        }
    }

    wait_for_socket(&listener_socket);

    let open_resp = send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    );
    let sid = match open_resp {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            assert!(session_id > 0);
            session_id
        }
        _ => panic!("unexpected response to open"),
    };

    let invoke_resp = send_request(
        &listener_socket,
        TEE_Request::InvokeCommand {
            session_id: sid,
            cmd_id: 7,
            params: Parameters::default(),
        },
    );
    match invoke_resp {
        TEE_Response::InvokeCommand { params, result } => {
            assert_eq!(result, TEE_SUCCESS);
            assert_eq!(params.0.param.values.a, 7);
            assert_eq!(params.0.param.values.b, 0xBEEF);
        }
        _ => panic!("unexpected response to invoke"),
    }

    let close_resp = send_request(
        &listener_socket,
        TEE_Request::CloseSession { session_id: sid },
    );
    match close_resp {
        TEE_Response::CloseSession { result } => assert_eq!(result, TEE_SUCCESS),
        _ => panic!("unexpected response to close"),
    }

    manager_handle
        .join()
        .expect("join manager thread")
        .expect("manager exits cleanly");
    registry_handle.join().expect("join registry thread");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn bad_uuid_case_rejected() {
    let _guard = lock_test_guard();
    let uuid = "sanity-bad-uuid";
    let temp_dir = unique_test_dir("bad-uuid");
    let registry_socket = temp_dir.join("server.sock");
    let listener_socket = temp_dir.join("ta.sock");

    let (registry_handle, register_rx) = spawn_registry(registry_socket.clone());

    let config = TAManagerConfig {
        registry_socket_path: registry_socket,
        listener_socket_path: listener_socket.clone(),
        instance_id: 202,
    };

    let manager_handle = thread::spawn(move || {
        let mut manager = TAManager::new_with_config(TestTa, uuid, config);
        manager.run_ta()
    });

    let _ = register_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("receive register request");
    wait_for_socket(&listener_socket);

    let open_wrong = send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: "wrong-uuid".to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    );
    match open_wrong {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(session_id, 0);
            assert_eq!(result, Into::<u32>::into(TaError::BadParameters));
        }
        _ => panic!("unexpected response to bad uuid open"),
    }

    // Open a valid session and close it so manager can exit cleanly.
    let sid = match send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    ) {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            session_id
        }
        _ => panic!("unexpected response to valid open"),
    };
    let _ = send_request(
        &listener_socket,
        TEE_Request::CloseSession { session_id: sid },
    );

    manager_handle
        .join()
        .expect("join manager thread")
        .expect("manager exits cleanly");
    registry_handle.join().expect("join registry thread");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn invalid_session_case_rejected() {
    let _guard = lock_test_guard();
    let uuid = "sanity-invalid-session";
    let temp_dir = unique_test_dir("invalid-session");
    let registry_socket = temp_dir.join("server.sock");
    let listener_socket = temp_dir.join("ta.sock");

    let (registry_handle, register_rx) = spawn_registry(registry_socket.clone());

    let config = TAManagerConfig {
        registry_socket_path: registry_socket,
        listener_socket_path: listener_socket.clone(),
        instance_id: 303,
    };

    let manager_handle = thread::spawn(move || {
        let mut manager = TAManager::new_with_config(TestTa, uuid, config);
        manager.run_ta()
    });

    let _ = register_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("receive register request");
    wait_for_socket(&listener_socket);

    let invalid_sid = 9_999;

    let invoke_missing = send_request(
        &listener_socket,
        TEE_Request::InvokeCommand {
            session_id: invalid_sid,
            cmd_id: 123,
            params: Parameters::default(),
        },
    );
    match invoke_missing {
        TEE_Response::InvokeCommand { result, .. } => {
            assert_eq!(result, Into::<u32>::into(TaError::ItemNotFound));
        }
        _ => panic!("unexpected response to invalid invoke"),
    }

    let close_missing = send_request(
        &listener_socket,
        TEE_Request::CloseSession {
            session_id: invalid_sid,
        },
    );
    match close_missing {
        TEE_Response::CloseSession { result } => {
            assert_eq!(result, Into::<u32>::into(TaError::ItemNotFound));
        }
        _ => panic!("unexpected response to invalid close"),
    }

    // Open/close one valid session so manager exits.
    let sid = match send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    ) {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            session_id
        }
        _ => panic!("unexpected response to valid open"),
    };
    let _ = send_request(
        &listener_socket,
        TEE_Request::CloseSession { session_id: sid },
    );

    manager_handle
        .join()
        .expect("join manager thread")
        .expect("manager exits cleanly");
    registry_handle.join().expect("join registry thread");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn session_exclusive_case_busy_on_second_open() {
    let _guard = lock_test_guard();
    let uuid = "sanity-session-exclusive";
    let temp_dir = unique_test_dir("session-exclusive");
    let registry_socket = temp_dir.join("server.sock");
    let listener_socket = temp_dir.join("ta.sock");

    let (registry_handle, register_rx) = spawn_registry(registry_socket.clone());

    let config = TAManagerConfig {
        registry_socket_path: registry_socket,
        listener_socket_path: listener_socket.clone(),
        instance_id: 404,
    };

    let manager_handle = thread::spawn(move || {
        let mut manager = TAManager::new_with_config(ExclusiveTa, uuid, config);
        manager.run_ta()
    });

    let _ = register_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("receive register request");
    wait_for_socket(&listener_socket);

    let sid1 = match send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    ) {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            session_id
        }
        _ => panic!("unexpected response to first open"),
    };

    let second_open = send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    );
    match second_open {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(session_id, 0);
            assert_eq!(result, Into::<u32>::into(TaError::Busy));
        }
        _ => panic!("unexpected response to second open"),
    }

    let _ = send_request(
        &listener_socket,
        TEE_Request::CloseSession { session_id: sid1 },
    );

    manager_handle
        .join()
        .expect("join manager thread")
        .expect("manager exits cleanly");
    registry_handle.join().expect("join registry thread");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn connection_limit_case_excess_connections_rejected() {
    let _guard = lock_test_guard();
    #[derive(Clone, Copy)]
    struct SlowTa;
    impl TrustedApplication for SlowTa {
        type SessionContext = u32;
        fn create(&self) -> xtee_utee::error::Result<()> {
            Ok(())
        }
        fn open_session(
            &self,
            _params: &mut Parameters,
        ) -> xtee_utee::error::Result<Self::SessionContext> {
            // Slow down open path so concurrent connections can hit MAX_CA_CONNECTIONS limit.
            thread::sleep(Duration::from_millis(120));
            Ok(1)
        }
        fn close_session(&self, _ctx: &mut Self::SessionContext) -> xtee_utee::error::Result<()> {
            Ok(())
        }
        fn destroy(&self) -> xtee_utee::error::Result<()> {
            Ok(())
        }
        fn invoke_command(
            &self,
            _cmd_id: u32,
            _params: &mut Parameters,
            _ctx: &mut Self::SessionContext,
        ) -> xtee_utee::error::Result<()> {
            Ok(())
        }
    }

    let uuid = "sanity-connection-limit";
    let temp_dir = unique_test_dir("connection-limit");
    let registry_socket = temp_dir.join("server.sock");
    let listener_socket = temp_dir.join("ta.sock");

    let (registry_handle, register_rx) = spawn_registry(registry_socket.clone());
    let config = TAManagerConfig {
        registry_socket_path: registry_socket,
        listener_socket_path: listener_socket.clone(),
        instance_id: 505,
    };

    let manager_handle = thread::spawn(move || {
        let mut manager = TAManager::new_with_config(SlowTa, uuid, config);
        manager.run_ta()
    });

    let _ = register_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("receive register request");
    wait_for_socket(&listener_socket);

    let mut workers = Vec::new();
    for _ in 0..24 {
        let socket = listener_socket.clone();
        let uuid_str = uuid.to_string();
        workers.push(thread::spawn(move || {
            send_request_try(
                &socket,
                TEE_Request::OpenSession {
                    uuid: uuid_str,
                    connection_method: 0,
                    params: Parameters::default(),
                    ca_auth_info: None,
                },
            )
        }));
    }

    let mut success_session_ids = Vec::new();
    let mut rejected = 0usize;
    for worker in workers {
        match worker.join().expect("join open worker") {
            Ok(TEE_Response::OpenSession { session_id, result }) => {
                if result == TEE_SUCCESS && session_id > 0 {
                    success_session_ids.push(session_id);
                } else {
                    rejected += 1;
                }
            }
            Ok(_) => rejected += 1,
            Err(_) => rejected += 1,
        }
    }

    // Some requests should be rejected/no-response when MAX_CA_CONNECTIONS is hit.
    assert!(
        rejected > 0,
        "expected at least one request rejected when exceeding connection limit"
    );

    for sid in success_session_ids {
        let _ = send_request(
            &listener_socket,
            TEE_Request::CloseSession { session_id: sid },
        );
    }

    manager_handle
        .join()
        .expect("join manager thread")
        .expect("manager exits cleanly");
    registry_handle.join().expect("join registry thread");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn shutdown_keepalive_case_shutdown_on_last_close() {
    let _guard = lock_test_guard();
    let uuid = "sanity-shutdown-keepalive";
    let temp_dir = unique_test_dir("shutdown-keepalive");
    let registry_socket = temp_dir.join("server.sock");
    let listener_socket = temp_dir.join("ta.sock");

    let (registry_handle, register_rx) = spawn_registry(registry_socket.clone());
    let config = TAManagerConfig {
        registry_socket_path: registry_socket,
        listener_socket_path: listener_socket.clone(),
        instance_id: 606,
    };

    let manager_handle = thread::spawn(move || {
        let mut manager = TAManager::new_with_config(TestTa, uuid, config);
        manager.run_ta()
    });

    let _ = register_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("receive register request");
    wait_for_socket(&listener_socket);

    let sid = match send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    ) {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            session_id
        }
        _ => panic!("unexpected response to open"),
    };

    let _ = send_request(
        &listener_socket,
        TEE_Request::CloseSession { session_id: sid },
    );

    manager_handle
        .join()
        .expect("join manager thread")
        .expect("manager exits cleanly");
    registry_handle.join().expect("join registry thread");

    // After shutdown on last close (keep_alive=false), listener should not accept new requests.
    let reconnect = UnixStream::connect(&listener_socket);
    assert!(
        reconnect.is_err(),
        "listener should be closed after last close when keep_alive=false"
    );
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn instance_keepalive_case_listener_accepts_after_last_close() {
    let _guard = lock_test_guard();
    let uuid = "sanity-instance-keepalive";
    let temp_dir = unique_test_dir("instance-keepalive");
    let registry_socket = temp_dir.join("server.sock");
    let listener_socket = temp_dir.join("ta.sock");

    let (registry_handle, register_rx) = spawn_registry(registry_socket.clone());
    let config = TAManagerConfig {
        registry_socket_path: registry_socket,
        listener_socket_path: listener_socket.clone(),
        instance_id: 607,
    };

    let manager_handle = thread::spawn(move || {
        let mut manager = TAManager::new_with_config(KeepAliveTa, uuid, config);
        manager.run_ta()
    });

    let _ = register_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("receive register request");
    wait_for_socket(&listener_socket);

    let sid1 = match send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    ) {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            session_id
        }
        _ => panic!("unexpected response to open"),
    };

    let _ = send_request(
        &listener_socket,
        TEE_Request::CloseSession { session_id: sid1 },
    );

    let sid2 = match send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    ) {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            session_id
        }
        _ => panic!("expected second OpenSession to succeed when keep_alive=true"),
    };

    let _ = send_request(
        &listener_socket,
        TEE_Request::CloseSession { session_id: sid2 },
    );

    // Manager thread keeps serving; joining would hang. Detach for test cleanup.
    std::mem::forget(manager_handle);
    registry_handle.join().expect("join registry thread");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn multi_session_shutdown_case_counter_per_session_and_reset() {
    let _guard = lock_test_guard();
    let uuid = "sanity-multi-session-shutdown";

    fn run_round(
        tag: &str,
        instance_id: u32,
        uuid: &'static str,
    ) -> (
        thread::JoinHandle<anyhow::Result<()>>,
        thread::JoinHandle<()>,
        PathBuf,
    ) {
        MULTI_SESSION_SHUTDOWN_COUNTER.store(0, Ordering::Relaxed);
        let temp_dir = unique_test_dir(tag);
        let registry_socket = temp_dir.join("server.sock");
        let listener_socket = temp_dir.join("ta.sock");

        let (registry_handle, register_rx) = spawn_registry(registry_socket.clone());
        let config = TAManagerConfig {
            registry_socket_path: registry_socket,
            listener_socket_path: listener_socket.clone(),
            instance_id,
        };

        let manager_handle = thread::spawn(move || {
            let mut manager = TAManager::new_with_config(MultiSessionShutdownTa, uuid, config);
            manager.run_ta()
        });

        let _ = register_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("receive register request");
        wait_for_socket(&listener_socket);

        let sid1 = match send_request(
            &listener_socket,
            TEE_Request::OpenSession {
                uuid: uuid.to_string(),
                connection_method: 0,
                params: Parameters::default(),
                ca_auth_info: None,
            },
        ) {
            TEE_Response::OpenSession { session_id, result } => {
                assert_eq!(result, TEE_SUCCESS);
                session_id
            }
            _ => panic!("unexpected response to open (sid1)"),
        };

        let sid2 = match send_request(
            &listener_socket,
            TEE_Request::OpenSession {
                uuid: uuid.to_string(),
                connection_method: 0,
                params: Parameters::default(),
                ca_auth_info: None,
            },
        ) {
            TEE_Response::OpenSession { session_id, result } => {
                assert_eq!(result, TEE_SUCCESS);
                session_id
            }
            _ => panic!("unexpected response to open (sid2)"),
        };

        let inv1 = send_request(
            &listener_socket,
            TEE_Request::InvokeCommand {
                session_id: sid1,
                cmd_id: 1,
                params: Parameters::default(),
            },
        );
        match inv1 {
            TEE_Response::InvokeCommand { params, result } => {
                assert_eq!(result, TEE_SUCCESS);
                assert_eq!(params.0.param.values.a, 0, "{} first invoke", tag);
            }
            _ => panic!("unexpected invoke1"),
        }

        let inv2 = send_request(
            &listener_socket,
            TEE_Request::InvokeCommand {
                session_id: sid2,
                cmd_id: 1,
                params: Parameters::default(),
            },
        );
        match inv2 {
            TEE_Response::InvokeCommand { params, result } => {
                assert_eq!(result, TEE_SUCCESS);
                assert_eq!(params.0.param.values.a, 1, "{} second invoke", tag);
            }
            _ => panic!("unexpected invoke2"),
        }

        let _ = send_request(
            &listener_socket,
            TEE_Request::CloseSession { session_id: sid1 },
        );
        let _ = send_request(
            &listener_socket,
            TEE_Request::CloseSession { session_id: sid2 },
        );

        (manager_handle, registry_handle, temp_dir)
    }

    let (mh1, rh1, dir1) = run_round("msd-1", 610, uuid);
    mh1.join()
        .expect("join manager thread")
        .expect("manager exits cleanly");
    rh1.join().expect("join registry thread");
    let _ = std::fs::remove_dir_all(&dir1);

    let (mh2, rh2, dir2) = run_round("msd-2", 611, uuid);
    mh2.join()
        .expect("join manager thread")
        .expect("manager exits cleanly");
    rh2.join().expect("join registry thread");
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn multi_session_keepalive_case_counter_continues_after_all_sessions_closed() {
    let _guard = lock_test_guard();
    let uuid = "sanity-multi-session-keepalive";
    MULTI_SESSION_KEEPALIVE_COUNTER.store(0, Ordering::Relaxed);

    let temp_dir = unique_test_dir("msk");
    let registry_socket = temp_dir.join("server.sock");
    let listener_socket = temp_dir.join("ta.sock");

    let (registry_handle, register_rx) = spawn_registry(registry_socket.clone());
    let config = TAManagerConfig {
        registry_socket_path: registry_socket,
        listener_socket_path: listener_socket.clone(),
        instance_id: 613,
    };

    let manager_handle = thread::spawn(move || {
        let mut manager = TAManager::new_with_config(MultiSessionKeepAliveTa, uuid, config);
        manager.run_ta()
    });

    let _ = register_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("receive register request");
    wait_for_socket(&listener_socket);

    let sid1 = match send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    ) {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            session_id
        }
        _ => panic!("open sid1"),
    };
    let sid2 = match send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    ) {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            session_id
        }
        _ => panic!("open sid2"),
    };

    for (sid, expected, tag) in [(sid1, 0u32, "r1a"), (sid2, 1u32, "r1b")] {
        let inv = send_request(
            &listener_socket,
            TEE_Request::InvokeCommand {
                session_id: sid,
                cmd_id: 1,
                params: Parameters::default(),
            },
        );
        match inv {
            TEE_Response::InvokeCommand { params, result } => {
                assert_eq!(result, TEE_SUCCESS);
                assert_eq!(params.0.param.values.a, expected, "{tag}");
            }
            _ => panic!("invoke {tag}"),
        }
    }

    let _ = send_request(
        &listener_socket,
        TEE_Request::CloseSession { session_id: sid1 },
    );
    let _ = send_request(
        &listener_socket,
        TEE_Request::CloseSession { session_id: sid2 },
    );

    let sid3 = match send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    ) {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            session_id
        }
        _ => panic!("open sid3"),
    };
    let sid4 = match send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    ) {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            session_id
        }
        _ => panic!("open sid4"),
    };

    for (sid, expected, tag) in [(sid3, 2u32, "r2a"), (sid4, 3u32, "r2b")] {
        let inv = send_request(
            &listener_socket,
            TEE_Request::InvokeCommand {
                session_id: sid,
                cmd_id: 1,
                params: Parameters::default(),
            },
        );
        match inv {
            TEE_Response::InvokeCommand { params, result } => {
                assert_eq!(result, TEE_SUCCESS);
                assert_eq!(params.0.param.values.a, expected, "{tag}");
            }
            _ => panic!("invoke {tag}"),
        }
    }

    let _ = send_request(
        &listener_socket,
        TEE_Request::CloseSession { session_id: sid3 },
    );
    let _ = send_request(
        &listener_socket,
        TEE_Request::CloseSession { session_id: sid4 },
    );

    std::mem::forget(manager_handle);
    registry_handle.join().expect("join registry thread");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// `ta_runtime_sanity` 里每个 `TAManager` 对应 **一个** TA 进程：此处用两段顺序起的 manager 模拟「实例销毁后再起」。
/// 同一 manager 上重叠多 session 会得到 **共享** 静态计数（与真实 x-kernel 多进程多实例不同）；重叠行为以 CA 真机用例为准。
#[test]
fn multi_instance_singleton_case_invoke_sequence() {
    let _guard = lock_test_guard();
    let uuid = "sanity-multi-instance-singleton";
    let temp_dir = unique_test_dir("mis-invoke");

    // Phase 1: one TA instance — invokes 0,1,2; last session close tears down instance (keep_alive=false).
    MULTI_INSTANCE_SINGLETON_COUNTER.store(0, Ordering::Relaxed);
    let registry_socket = temp_dir.join("server.sock");
    let listener_socket = temp_dir.join("ta.sock");

    let (registry_handle, register_rx) = spawn_registry(registry_socket.clone());
    let config = TAManagerConfig {
        registry_socket_path: registry_socket,
        listener_socket_path: listener_socket.clone(),
        instance_id: 614,
    };

    let manager_handle = thread::spawn(move || {
        let mut manager = TAManager::new_with_config(MultiInstanceSingletonTa, uuid, config);
        manager.run_ta()
    });

    let _ = register_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("receive register request");
    wait_for_socket(&listener_socket);

    let sid = match send_request(
        &listener_socket,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    ) {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            session_id
        }
        _ => panic!("open session"),
    };

    for expected in [0u32, 1, 2] {
        let inv = send_request(
            &listener_socket,
            TEE_Request::InvokeCommand {
                session_id: sid,
                cmd_id: 1,
                params: Parameters::default(),
            },
        );
        match inv {
            TEE_Response::InvokeCommand { params, result } => {
                assert_eq!(result, TEE_SUCCESS);
                assert_eq!(params.0.param.values.a, expected);
            }
            _ => panic!("invoke expect {expected}"),
        }
    }

    let _ = send_request(
        &listener_socket,
        TEE_Request::CloseSession { session_id: sid },
    );

    manager_handle
        .join()
        .expect("join manager thread")
        .expect("manager exits cleanly");
    registry_handle.join().expect("join registry thread");

    // Phase 2: new TA instance — static counter as in a fresh process.
    MULTI_INSTANCE_SINGLETON_COUNTER.store(0, Ordering::Relaxed);
    let registry_socket2 = temp_dir.join("server2.sock");
    let listener_socket2 = temp_dir.join("ta2.sock");

    let (registry_handle2, register_rx2) = spawn_registry(registry_socket2.clone());
    let config2 = TAManagerConfig {
        registry_socket_path: registry_socket2,
        listener_socket_path: listener_socket2.clone(),
        instance_id: 615,
    };

    let manager_handle2 = thread::spawn(move || {
        let mut manager = TAManager::new_with_config(MultiInstanceSingletonTa, uuid, config2);
        manager.run_ta()
    });

    let _ = register_rx2
        .recv_timeout(Duration::from_secs(3))
        .expect("receive register request phase2");
    wait_for_socket(&listener_socket2);

    let sid2 = match send_request(
        &listener_socket2,
        TEE_Request::OpenSession {
            uuid: uuid.to_string(),
            connection_method: 0,
            params: Parameters::default(),
            ca_auth_info: None,
        },
    ) {
        TEE_Response::OpenSession { session_id, result } => {
            assert_eq!(result, TEE_SUCCESS);
            session_id
        }
        _ => panic!("open session phase2"),
    };

    for expected in [0u32, 1] {
        let inv = send_request(
            &listener_socket2,
            TEE_Request::InvokeCommand {
                session_id: sid2,
                cmd_id: 1,
                params: Parameters::default(),
            },
        );
        match inv {
            TEE_Response::InvokeCommand { params, result } => {
                assert_eq!(result, TEE_SUCCESS);
                assert_eq!(params.0.param.values.a, expected);
            }
            _ => panic!("invoke phase2 expect {expected}"),
        }
    }

    let _ = send_request(
        &listener_socket2,
        TEE_Request::CloseSession { session_id: sid2 },
    );

    manager_handle2
        .join()
        .expect("join manager thread phase2")
        .expect("manager exits cleanly phase2");
    registry_handle2
        .join()
        .expect("join registry thread phase2");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn create_failure_reports_original_result_before_binding_listener() {
    struct CreateFailTa;
    impl TrustedApplication for CreateFailTa {
        type SessionContext = ();
        fn create(&self) -> xtee_utee::error::Result<()> {
            Err(TaError::Unknown(0xffff1234))
        }
        fn open_session(&self, _: &mut Parameters) -> xtee_utee::error::Result<()> {
            panic!("failed Create must not open a session")
        }
        fn close_session(&self, _: &mut ()) -> xtee_utee::error::Result<()> {
            Ok(())
        }
        fn destroy(&self) -> xtee_utee::error::Result<()> {
            panic!("failed Create must not invoke Destroy")
        }
        fn invoke_command(
            &self,
            _: u32,
            _: &mut Parameters,
            _: &mut (),
        ) -> xtee_utee::error::Result<()> {
            panic!("failed Create must not invoke a command")
        }
    }
    let _guard = lock_test_guard();
    let temp_dir = unique_test_dir("create-failure");
    let registry_socket = temp_dir.join("server.sock");
    let listener_socket = temp_dir.join("ta.sock");
    let listener = UnixListener::bind(&registry_socket).expect("bind registry");
    listener.set_nonblocking(true).unwrap();
    let receiver = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "Create must report failure to manager"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0; 128];
        loop {
            let len = stream.read(&mut chunk).unwrap();
            assert_ne!(len, 0, "complete report required");
            bytes.extend_from_slice(&chunk[..len]);
            if let Ok(report) = postcard::from_bytes::<(u8, String, u32, u32)>(&bytes) {
                stream.write_all(&[1]).unwrap();
                return report;
            }
        }
    });
    let mut manager = TAManager::new_with_config(
        CreateFailTa,
        "create-fail",
        TAManagerConfig {
            registry_socket_path: registry_socket,
            listener_socket_path: listener_socket.clone(),
            instance_id: 37,
        },
    );
    let error = manager.run_ta().expect_err("Create must fail");
    assert_eq!(
        error.downcast_ref::<TaError>(),
        Some(&TaError::Unknown(0xffff1234))
    );
    assert!(
        !listener_socket.exists(),
        "failed Create must not publish a listener"
    );
    let report = receiver.join().unwrap();
    assert_eq!(report, (1, "create-fail".into(), 37, 0xffff1234));
    // Delivery failure must preserve the TA error as well.
    let mut unreachable = TAManager::new_with_config(
        CreateFailTa,
        "create-fail",
        TAManagerConfig {
            registry_socket_path: temp_dir.join("absent.sock"),
            listener_socket_path: listener_socket.clone(),
            instance_id: 38,
        },
    );
    assert_eq!(
        unreachable.run_ta().unwrap_err().downcast_ref::<TaError>(),
        Some(&TaError::Unknown(0xffff1234))
    );
    assert!(!listener_socket.exists());
    std::fs::remove_dir_all(temp_dir).unwrap();
}
