// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crossbeam_channel::{Receiver, Sender, unbounded};
use rust_utee::tee_api_defines::{TEE_ERROR_TARGET_DEAD, TEE_SUCCESS};

use crate::{
    error::{Error, Result},
    panic_notify::{
        clear_invoke_context, install_invoke_context, instance_is_panicked, mark_panic_close_done,
        panic_listener_should_exit,
    },
};
use teec_protocol::{CaAuthInfo, Parameters, TARequest, TEE_Response};

use crate::{
    invoke_cancellation::InvokeScope, invoke_protocol::TaRequest,
    registration_protocol::RegistrationRequest,
};

const DEFAULT_SERVER_SOCKET_PATH: &str = "/tmp/server.sock";
const MAX_CA_CONNECTIONS: usize = 16;

/// Releases an admitted connection even if its handler unwinds.
struct ActiveConnection(Arc<AtomicUsize>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept CA connections. After panic on non-keep-alive instances, poll until Close or grace.
fn accept_ca_connections<'a>(
    listener: &'a UnixListener,
    active_connections: &'a AtomicUsize,
    instance_keep_alive: bool,
) -> impl Iterator<Item = io::Result<UnixStream>> + 'a {
    struct AcceptIter<'a> {
        listener: &'a UnixListener,
        active: &'a AtomicUsize,
        instance_keep_alive: bool,
        finished: bool,
    }

    impl<'a> Iterator for AcceptIter<'a> {
        type Item = io::Result<UnixStream>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.finished {
                return None;
            }
            let active = self.active.load(Ordering::SeqCst);
            if panic_listener_should_exit(active, self.instance_keep_alive) {
                self.finished = true;
                return Some(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "panic listener drain complete",
                )));
            }

            if instance_is_panicked() && !self.instance_keep_alive {
                let _ = self.listener.set_nonblocking(true);
                loop {
                    if panic_listener_should_exit(self.active.load(Ordering::SeqCst), false) {
                        let _ = self.listener.set_nonblocking(false);
                        self.finished = true;
                        return Some(Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "panic listener drain complete",
                        )));
                    }
                    match self.listener.accept() {
                        Ok((stream, _)) => {
                            let _ = self.listener.set_nonblocking(false);
                            return Some(Ok(stream));
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(e) => {
                            let _ = self.listener.set_nonblocking(false);
                            self.finished = true;
                            return Some(Err(e));
                        }
                    }
                }
            }

            let _ = self.listener.set_nonblocking(false);
            match self.listener.accept() {
                Ok((stream, _)) => Some(Ok(stream)),
                Err(e) => {
                    self.finished = true;
                    Some(Err(e))
                }
            }
        }
    }

    AcceptIter {
        listener,
        active: active_connections,
        instance_keep_alive,
        finished: false,
    }
}

/// 会话生命周期深度调试（Close / session 线程与 `sessions` 锁）。在 **TA 进程**环境中设置
/// `XTEE_TA_DEBUG_SESSION_LIFECYCLE=1`，stderr 会输出带时间戳与线程 id 的阶段日志，用于定位
/// `CloseSession` 卡在 `sessions` 互斥锁还是 `resp_rx.recv()` 等。
fn ta_debug_session_lifecycle() -> bool {
    std::env::var_os("XTEE_TA_DEBUG_SESSION_LIFECYCLE").is_some()
}

fn ta_lifecycle_log(msg: &str) {
    if !ta_debug_session_lifecycle() {
        return;
    }
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    eprintln!(
        "[xtee-ta lifecycle {}ms {:?}] {}",
        ms,
        std::thread::current().id(),
        msg
    );
}

fn lock_sessions(
    sessions: &Arc<Mutex<HashMap<u32, Sender<SessionMessage>>>>,
) -> anyhow::Result<std::sync::MutexGuard<'_, HashMap<u32, Sender<SessionMessage>>>> {
    Ok(sessions.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Serialize a response and write it as `[len: u32 NE][payload]` over the stream.
fn write_response(stream: &mut UnixStream, resp: &TEE_Response) -> anyhow::Result<()> {
    let resp_data = postcard::to_allocvec(resp)?;
    let mut message = Vec::with_capacity(4 + resp_data.len());
    message.extend_from_slice(&(resp_data.len() as u32).to_ne_bytes());
    message.extend_from_slice(&resp_data);
    stream.write_all(&message)?;
    Ok(())
}

fn read_framed_tee_request(stream: &mut UnixStream) -> anyhow::Result<TaRequest> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_ne_bytes(len_buf) as usize;
    const MAX_REQ: usize = 16 * 1024 * 1024;
    if len > MAX_REQ {
        anyhow::bail!("TEE_Request frame too large: {len}");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(postcard::from_bytes::<TaRequest>(&buf)?)
}

/// CA 连接数超过上限时仍应先读首帧再写回协议错误；否则客户端可能在 OpenSession 上永久阻塞。
fn reject_excess_ca_connection(mut stream: UnixStream) {
    let req = match read_framed_tee_request(&mut stream) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("reject excess CA connection: read request failed: {e}");
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
    };

    let resp = match req {
        TaRequest::OpenSession { .. } => TEE_Response::OpenSession {
            session_id: 0,
            result: Error::OutOfMemory.into(),
        },
        TaRequest::CloseSession { .. } => TEE_Response::CloseSession {
            result: Error::Communication.into(),
        },
        TaRequest::InvokeCommand { params, .. }
        | TaRequest::InvokeCommandWithTimeout { params, .. } => TEE_Response::InvokeCommand {
            params,
            result: Error::Communication.into(),
        },
        TaRequest::RequestCancellation { session_id: _ } => TEE_Response::RequestCancellation {
            result: Error::NotSupported.into(),
        },
    };

    if let Err(e) = write_response(&mut stream, &resp) {
        eprintln!("reject excess CA connection: write error response failed: {e}");
    }
}

/// Whether the TA's session policy requires exclusive access
/// (SingleInstance + no MultiSession → only one session at a time).
fn is_exclusive_session<T: TrustedApplication>() -> bool {
    T::IS_SINGLE_INSTANCE && !T::IS_MULTI_SESSION
}

/// Trait representing a Trusted Application (TA).
pub trait TrustedApplication: Send + Sync + 'static {
    /// Whether this TA is a single instance.
    ///
    /// Default is `false` to avoid forcing hand-written TAs to set it.
    const IS_SINGLE_INSTANCE: bool = false;
    /// Whether this TA instance can handle multiple concurrent sessions.
    const IS_MULTI_SESSION: bool = false;
    /// Whether the TA instance should be kept alive after all sessions close.
    const IS_INSTANCE_KEEP_ALIVE: bool = false;

    /// User-defined session context type.
    type SessionContext: Send;

    /// Create a new TA instance.
    fn create(&self) -> Result<()>;

    /// ACL check using CA authentication info from `OpenSession`.
    fn acl_check(&self, _ca_auth_info: Option<&CaAuthInfo>) -> Result<()> {
        Ok(())
    }

    /// Open a session with the TA.
    fn open_session(&self, params: &mut Parameters) -> Result<Self::SessionContext>;

    /// Close the session with the TA.
    fn close_session(&self, ctx: &mut Self::SessionContext) -> Result<()>;

    /// Destroy the TA instance.
    fn destroy(&self) -> Result<()>;

    /// Invoke a command on the TA.
    fn invoke_command(
        &self,
        cmd_id: u32,
        params: &mut Parameters,
        ctx: &mut Self::SessionContext,
    ) -> Result<()>;
}

/// Shared state passed to each CA connection handler thread.
/// A failed Open response removes its map entry and asks the owning session
/// worker to close the TA context, including for exclusive-session instances.
struct ConnectionContext<T: TrustedApplication> {
    ta: Arc<T>,
    sessions: Arc<Mutex<HashMap<u32, Sender<SessionMessage>>>>,
    session_id: Arc<AtomicU32>,
    uuid: String,
    listener_socket_path: PathBuf,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
pub struct TAManagerConfig {
    pub registry_socket_path: PathBuf,
    pub listener_socket_path: PathBuf,
    pub instance_id: u32,
}

impl TAManagerConfig {
    pub fn from_uuid(uuid: &str) -> Self {
        let instance_id = std::env::var("XTEE_TA_INSTANCE_ID")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|id| *id != 0)
            .unwrap_or(1);

        let listener_socket_path = std::env::var("XTEE_TA_LISTENER_SOCKET_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_listener_socket_path(uuid, instance_id));

        let registry_socket_path = std::env::var("XTEE_TA_REGISTRY_SOCKET_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_SERVER_SOCKET_PATH));

        Self {
            registry_socket_path,
            listener_socket_path,
            instance_id,
        }
    }
}

fn default_listener_socket_path(uuid: &str, instance_id: u32) -> PathBuf {
    PathBuf::from(format!("/tmp/{}.{}.sock", uuid, instance_id))
}

/// Manager for a Trusted Application (TA).
pub struct TAManager<T: TrustedApplication> {
    ta: Arc<T>,
    uuid: String,
    instance_id: u32,
    registry_socket_path: PathBuf,
    listener_socket_path: PathBuf,
    sessions: Arc<Mutex<HashMap<u32, Sender<SessionMessage>>>>,
    session_id: Arc<AtomicU32>,
    shutdown: Arc<AtomicBool>,
}

impl<T: TrustedApplication> TAManager<T> {
    pub fn new(ta: T, uuid: &str) -> Self {
        let config = TAManagerConfig::from_uuid(uuid);
        Self::new_with_config(ta, uuid, config)
    }

    pub fn new_with_config(ta: T, uuid: &str, config: TAManagerConfig) -> Self {
        Self {
            ta: Arc::new(ta),
            uuid: uuid.to_string(),
            instance_id: config.instance_id,
            registry_socket_path: config.registry_socket_path,
            listener_socket_path: config.listener_socket_path,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_id: Arc::new(AtomicU32::new(1)),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Run Create before publishing a listener. A Create error is reported to
    /// the manager and returned unchanged even when reporting fails.
    pub fn run_ta(&mut self) -> anyhow::Result<()> {
        if let Err(error) = self.ta.create() {
            let result: u32 = error.into();
            if let Err(report_error) = self.report_create_failure(result) {
                log::warn!("TA Create failure report failed: {report_error:#}");
            }
            return Err(Error::from(result).into());
        }
        let listener = self.bind_listener()?;
        let _stream = self.register_ta()?;
        self.handle_ca_request(self.ta.clone(), listener)?;
        if !instance_is_panicked() {
            let _ = self.ta.destroy();
        }
        // Remove the socket file so the inode (and its BindEntry) is
        // released promptly instead of lingering until the next instance
        // starts or the system cleans up.
        let _ = std::fs::remove_file(&self.listener_socket_path);
        Ok(())
    }

    fn report_create_failure(&self, result: u32) -> anyhow::Result<()> {
        let mut stream = UnixStream::connect(&self.registry_socket_path)?;
        let timeout = Some(Duration::from_secs(5));
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        let request = RegistrationRequest::CreateFailed {
            uuid: self.uuid.clone(),
            instance_id: self.instance_id,
            result,
        };
        stream.write_all(&postcard::to_allocvec(&request)?)?;
        let mut accepted = [0];
        stream.read_exact(&mut accepted)?;
        anyhow::ensure!(accepted == [1], "manager rejected TA Create failure");
        Ok(())
    }

    fn register_ta(&self) -> anyhow::Result<UnixStream> {
        let mut stream = UnixStream::connect(&self.registry_socket_path)?;

        let socket_path = self.listener_socket_path.display().to_string();
        let req = TARequest::Register {
            uuid: self.uuid.clone(),
            instance_id: self.instance_id,
            socket_path,
            is_single_instance: T::IS_SINGLE_INSTANCE,
            is_multi_session: T::IS_MULTI_SESSION,
            is_instance_keep_alive: T::IS_INSTANCE_KEEP_ALIVE,
        };
        let data = postcard::to_allocvec(&req)?;
        stream.write_all(&data)?;
        println!(
            "TA registered with UUID: {}, instance_id: {}",
            self.uuid, self.instance_id
        );

        Ok(stream)
    }

    fn bind_listener(&self) -> anyhow::Result<UnixListener> {
        let path = self.listener_socket_path.clone();
        let _ = std::fs::remove_file(path.clone());

        let listener = UnixListener::bind(path.clone())?;
        println!("TA listening on socket: {:?}", path);
        Ok(listener)
    }

    fn handle_ca_request(&mut self, ta: Arc<T>, listener: UnixListener) -> anyhow::Result<()> {
        let active_connections = Arc::new(AtomicUsize::new(0));
        let mut handlers: Vec<JoinHandle<()>> = Vec::new();

        let instance_keep_alive = T::IS_INSTANCE_KEEP_ALIVE;

        for stream in accept_ca_connections(&listener, &active_connections, instance_keep_alive) {
            if instance_is_panicked() {
                self.shutdown.store(true, Ordering::SeqCst);
            } else if self.shutdown.load(Ordering::SeqCst) {
                break;
            }

            if panic_listener_should_exit(
                active_connections.load(Ordering::SeqCst),
                instance_keep_alive,
            ) {
                break;
            }

            let stream = match stream {
                Ok(s) => s,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => break,
                Err(e) => return Err(e.into()),
            };

            if active_connections.fetch_add(1, Ordering::SeqCst) >= MAX_CA_CONNECTIONS {
                active_connections.fetch_sub(1, Ordering::SeqCst);
                eprintln!(
                    "Connection rejected: max concurrent connections ({}) reached",
                    MAX_CA_CONNECTIONS
                );
                reject_excess_ca_connection(stream);
                continue;
            }

            let ctx = ConnectionContext {
                ta: ta.clone(),
                sessions: self.sessions.clone(),
                session_id: self.session_id.clone(),
                uuid: self.uuid.clone(),
                listener_socket_path: self.listener_socket_path.clone(),
                shutdown: self.shutdown.clone(),
            };
            let conn_active = active_connections.clone();

            let handle = thread::spawn(move || {
                let _connection = ActiveConnection(conn_active);
                if let Err(e) = handle_ca_connection::<T>(stream, ctx) {
                    eprintln!("Failed to handle CA connection: {:?}", e);
                }
            });
            handlers.push(handle);
        }

        for handle in handlers {
            let _ = handle.join();
        }

        if instance_is_panicked() && !T::IS_INSTANCE_KEEP_ALIVE {
            self.shutdown.store(true, Ordering::SeqCst);
            let _ = self.ta.destroy();
        }

        Ok(())
    }
}

enum SessionMessage {
    Invoke {
        deadline_ns: Option<u64>,
        cmd_id: u32,
        params: Parameters,
        resp_tx: Sender<TEE_Response>,
    },
    Close {
        resp_tx: Sender<TEE_Response>,
    },
}

fn session_thread<T: TrustedApplication>(
    ta: Arc<T>,
    mut ctx: T::SessionContext,
    rx: Receiver<SessionMessage>,
) {
    for msg in rx.iter() {
        match msg {
            SessionMessage::Invoke {
                deadline_ns,
                cmd_id,
                mut params,
                resp_tx,
            } => {
                if let Ok(bytes) = postcard::to_allocvec(&params)
                    && let Ok(params_snapshot) = postcard::from_bytes::<Parameters>(&bytes)
                {
                    install_invoke_context(resp_tx.clone(), params_snapshot);
                }
                let scope = InvokeScope::enter(deadline_ns);
                let result = match scope {
                    Ok(_scope) => ta.invoke_command(cmd_id, &mut params, &mut ctx),
                    Err(error) => Err(error),
                };
                let resp = match result {
                    Ok(_) => TEE_Response::InvokeCommand {
                        params,
                        result: TEE_SUCCESS,
                    },
                    Err(e) => TEE_Response::InvokeCommand {
                        params,
                        result: e.into(),
                    },
                };
                clear_invoke_context();
                if !instance_is_panicked() {
                    let _ = resp_tx.send(resp);
                }
            }
            SessionMessage::Close { resp_tx } => {
                ta_lifecycle_log(
                    "session_thread: Close message received, calling ta.close_session…",
                );
                let resp = match ta.close_session(&mut ctx) {
                    Ok(_) => TEE_Response::CloseSession {
                        result: TEE_SUCCESS,
                    },
                    Err(e) => TEE_Response::CloseSession { result: e.into() },
                };
                ta_lifecycle_log(
                    "session_thread: ta.close_session returned, sending Close resp to CA handler…",
                );
                let _ = resp_tx.send(resp);
                ta_lifecycle_log(
                    "session_thread: Close resp send done, exiting session_thread loop",
                );
                break;
            }
        }
    }
}

fn handle_ca_connection<T: TrustedApplication>(
    mut stream: UnixStream,
    ctx: ConnectionContext<T>,
) -> anyhow::Result<()> {
    let req = read_framed_tee_request(&mut stream)?;

    match req {
        TaRequest::OpenSession {
            uuid: req_uuid,
            connection_method: _,
            params,
            ca_auth_info,
        } => handle_open_session(&mut stream, &ctx, req_uuid, params, ca_auth_info),
        TaRequest::CloseSession { session_id } => {
            handle_close_session(&mut stream, &ctx, session_id)?;
            Ok(())
        }
        TaRequest::InvokeCommand {
            session_id,
            cmd_id,
            params,
        } => handle_invoke_command(&mut stream, &ctx.sessions, session_id, cmd_id, params, None),
        TaRequest::InvokeCommandWithTimeout {
            session_id,
            cmd_id,
            params,
            deadline_ns,
        } => handle_invoke_command(
            &mut stream,
            &ctx.sessions,
            session_id,
            cmd_id,
            params,
            Some(deadline_ns),
        ),
        TaRequest::RequestCancellation { session_id: _ } => {
            write_response(
                &mut stream,
                &TEE_Response::RequestCancellation {
                    result: Error::NotSupported.into(),
                },
            )?;
            Ok(())
        }
    }
}

fn handle_open_session<T: TrustedApplication>(
    stream: &mut UnixStream,
    ctx: &ConnectionContext<T>,
    req_uuid: String,
    mut params: Parameters,
    ca_auth_info: Option<CaAuthInfo>,
) -> anyhow::Result<()> {
    if instance_is_panicked() {
        write_response(
            stream,
            &TEE_Response::OpenSession {
                session_id: 0,
                result: TEE_ERROR_TARGET_DEAD,
            },
        )?;
        return Ok(());
    }

    if ctx.uuid != req_uuid {
        write_response(
            stream,
            &TEE_Response::OpenSession {
                session_id: 0,
                result: Error::BadParameters.into(),
            },
        )?;
        return Ok(());
    }

    if let Err(e) = ctx.ta.acl_check(ca_auth_info.as_ref()) {
        println!("ACL check failed: {:?}", e);
        write_response(
            stream,
            &TEE_Response::OpenSession {
                session_id: 0,
                result: e.into(),
            },
        )?;
        return Ok(());
    }

    let exclusive = is_exclusive_session::<T>();

    // 独占会话：在持有 `sessions` 锁期间完成 open + insert，避免两个 CA 连接并发时
    // 都通过「map 为空」检查（session_exclusive / 双 Context 场景）。
    let (session_ctx, sid, rx) = if exclusive {
        let mut guard = lock_sessions(&ctx.sessions)?;
        if !guard.is_empty() {
            write_response(
                stream,
                &TEE_Response::OpenSession {
                    session_id: 0,
                    result: Error::Busy.into(),
                },
            )?;
            return Ok(());
        }
        let mut session_ctx = match ctx.ta.open_session(&mut params) {
            Ok(c) => c,
            Err(e) => {
                println!("Failed to open session: {:?}", e);
                write_response(
                    stream,
                    &TEE_Response::OpenSession {
                        session_id: 0,
                        result: e.into(),
                    },
                )?;
                return Ok(());
            }
        };
        if !guard.is_empty() {
            drop(guard);
            let _ = ctx.ta.close_session(&mut session_ctx);
            write_response(
                stream,
                &TEE_Response::OpenSession {
                    session_id: 0,
                    result: Error::Busy.into(),
                },
            )?;
            return Ok(());
        }
        let sid = ctx.session_id.fetch_add(1, Ordering::SeqCst);
        println!("Opening session with ID: {}", sid);
        let (tx, rx) = unbounded();
        guard.insert(sid, tx);
        drop(guard);
        (session_ctx, sid, rx)
    } else {
        let session_ctx = match ctx.ta.open_session(&mut params) {
            Ok(c) => c,
            Err(e) => {
                println!("Failed to open session: {:?}", e);
                write_response(
                    stream,
                    &TEE_Response::OpenSession {
                        session_id: 0,
                        result: e.into(),
                    },
                )?;
                return Ok(());
            }
        };
        let (tx, rx) = unbounded();
        let mut guard = lock_sessions(&ctx.sessions)?;
        let sid = ctx.session_id.fetch_add(1, Ordering::SeqCst);
        println!("Opening session with ID: {}", sid);
        guard.insert(sid, tx);
        drop(guard);
        (session_ctx, sid, rx)
    };

    let ta = ctx.ta.clone();
    let _shutdown = ctx.shutdown.clone();
    thread::spawn(move || {
        session_thread(ta, session_ctx, rx);
    });

    let response = write_response(
        stream,
        &TEE_Response::OpenSession {
            session_id: sid,
            result: TEE_SUCCESS,
        },
    );
    if response.is_err() {
        // The peer never learned this local ID. Removing it also releases an
        // exclusive-session slot; the worker owns the TA context and closes it.
        if let Some(tx) = lock_sessions(&ctx.sessions)?.remove(&sid) {
            let (resp_tx, _resp_rx) = unbounded();
            let _ = tx.send(SessionMessage::Close { resp_tx });
        }
    }
    response
}

fn handle_close_session<T: TrustedApplication>(
    stream: &mut UnixStream,
    ctx: &ConnectionContext<T>,
    session_id: u32,
) -> anyhow::Result<bool> {
    println!("Closing session with ID: {}", session_id);
    ta_lifecycle_log(&format!(
        "handle_close_session: BEGIN local_session_id={session_id} uuid={}",
        ctx.uuid
    ));

    // session_thread 在 TEE_Panic 后卡在 _utee_panic 循环里，不能再等 Close ack
    if instance_is_panicked() {
        ta_lifecycle_log(&format!(
            "handle_close_session: instance panicked, fast Close (session_id={session_id})"
        ));
        let _ = lock_sessions(&ctx.sessions)?.remove(&session_id);
        write_response(
            stream,
            &TEE_Response::CloseSession {
                result: TEE_ERROR_TARGET_DEAD,
            },
        )?;
        mark_panic_close_done();
        return Ok(false);
    }

    let (resp, should_exit) = {
        ta_lifecycle_log(&format!(
            "handle_close_session: waiting for sessions mutex (local_session_id={session_id})…"
        ));
        let lock_wait = Instant::now();
        let mut guard = lock_sessions(&ctx.sessions)?;
        ta_lifecycle_log(&format!(
            "handle_close_session: sessions mutex acquired after {:?} (local_session_id={session_id})",
            lock_wait.elapsed()
        ));
        match guard.remove(&session_id) {
            Some(tx) => {
                ta_lifecycle_log(&format!(
                    "handle_close_session: removed session {session_id} from map, posting Close to session_thread…"
                ));
                let (resp_tx, resp_rx) = unbounded();
                tx.send(SessionMessage::Close { resp_tx })?;
                drop(guard);
                ta_lifecycle_log(&format!(
                    "handle_close_session: blocking on resp_rx.recv() for Close ack (local_session_id={session_id})…"
                ));
                let recv_wait = Instant::now();
                let resp = resp_rx.recv()?;
                ta_lifecycle_log(&format!(
                    "handle_close_session: resp_rx.recv() done after {:?} (local_session_id={session_id})",
                    recv_wait.elapsed()
                ));
                let empty = lock_sessions(&ctx.sessions)?.is_empty();
                (resp, empty && !T::IS_INSTANCE_KEEP_ALIVE)
            }
            None => {
                println!("Session {} not found", session_id);
                ta_lifecycle_log(&format!(
                    "handle_close_session: session {session_id} not in map (ItemNotFound)"
                ));
                (
                    TEE_Response::CloseSession {
                        result: Error::ItemNotFound.into(),
                    },
                    false,
                )
            }
        }
    };

    ta_lifecycle_log(&format!(
        "handle_close_session: writing Close response to CA unix stream (local_session_id={session_id})…"
    ));
    write_response(stream, &resp)?;
    ta_lifecycle_log(&format!(
        "handle_close_session: END ok (local_session_id={session_id})"
    ));

    if should_exit {
        ta_lifecycle_log(&format!(
            "handle_close_session: should_exit=true, destroying TA uuid={}",
            ctx.uuid
        ));
        println!(
            "All sessions closed for TA {}. Shutting down (instanceKeepAlive=false).",
            ctx.uuid
        );
        let _ = ctx.ta.destroy();
        ctx.shutdown.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(Path::new(&ctx.listener_socket_path));
    }

    Ok(should_exit)
}

fn handle_invoke_command(
    stream: &mut UnixStream,
    sessions: &Arc<Mutex<HashMap<u32, Sender<SessionMessage>>>>,
    session_id: u32,
    cmd_id: u32,
    params: Parameters,
    deadline_ns: Option<u64>,
) -> anyhow::Result<()> {
    if instance_is_panicked() {
        return write_response(
            stream,
            &TEE_Response::InvokeCommand {
                params,
                result: TEE_ERROR_TARGET_DEAD,
            },
        );
    }

    let params_for_dead = postcard::to_allocvec(&params)
        .ok()
        .and_then(|b| postcard::from_bytes(&b).ok());

    let tx = lock_sessions(sessions)?.get(&session_id).cloned();
    match tx {
        Some(tx) => {
            let (resp_tx, resp_rx) = unbounded();
            tx.send(SessionMessage::Invoke {
                deadline_ns,
                cmd_id,
                params,
                resp_tx,
            })?;
            let resp = match resp_rx.recv() {
                Ok(r) => r,
                Err(_) => TEE_Response::InvokeCommand {
                    params: params_for_dead.unwrap_or_default(),
                    result: TEE_ERROR_TARGET_DEAD,
                },
            };
            write_response(stream, &resp)
        }
        None => write_response(
            stream,
            &TEE_Response::InvokeCommand {
                params: Parameters::default(),
                result: Error::ItemNotFound.into(),
            },
        ),
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;
    struct Probe;
    impl TrustedApplication for Probe {
        type SessionContext = u32;
        fn create(&self) -> Result<()> {
            Ok(())
        }
        fn destroy(&self) -> Result<()> {
            Ok(())
        }
        fn open_session(&self, _: &mut Parameters) -> Result<u32> {
            Ok(0)
        }
        fn close_session(&self, _: &mut u32) -> Result<()> {
            Ok(())
        }
        fn invoke_command(&self, cmd: u32, _: &mut Parameters, count: &mut u32) -> Result<()> {
            assert_eq!(
                crate::invoke_cancellation::installed_deadline(),
                if cmd == 1 { Some(123) } else { None }
            );
            *count += 1;
            if cmd == 1 { Err(Error::Cancel) } else { Ok(()) }
        }
    }
    #[test]
    fn worker_scopes_cancel_to_one_invoke_and_reuses_session() {
        let (tx, rx) = unbounded();
        let worker = thread::spawn(move || session_thread(Arc::new(Probe), 0, rx));
        for cmd in [1, 2] {
            let (resp_tx, resp_rx) = unbounded();
            tx.send(SessionMessage::Invoke {
                deadline_ns: if cmd == 1 { Some(123) } else { None },
                cmd_id: cmd,
                params: Parameters::default(),
                resp_tx,
            })
            .unwrap();
            let response = resp_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            assert!(
                matches!(response, TEE_Response::InvokeCommand { result, .. } if result == if cmd == 1 { u32::from(Error::Cancel) } else { TEE_SUCCESS })
            );
        }
        let (resp_tx, resp_rx) = unbounded();
        tx.send(SessionMessage::Close { resp_tx }).unwrap();
        assert!(matches!(
            resp_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            TEE_Response::CloseSession {
                result: TEE_SUCCESS
            }
        ));
        worker.join().unwrap();
    }
}

#[cfg(test)]
mod connection_cleanup_tests {
    use super::*;

    struct CloseProbe(Sender<()>);
    impl TrustedApplication for CloseProbe {
        type SessionContext = ();
        const IS_SINGLE_INSTANCE: bool = true;
        fn create(&self) -> Result<()> {
            Ok(())
        }
        fn destroy(&self) -> Result<()> {
            Ok(())
        }
        fn open_session(&self, _: &mut Parameters) -> Result<()> {
            Ok(())
        }
        fn close_session(&self, _: &mut ()) -> Result<()> {
            self.0.send(()).unwrap();
            Ok(())
        }
        fn invoke_command(&self, _: u32, _: &mut Parameters, _: &mut ()) -> Result<()> {
            Ok(())
        }
    }

    fn context(closed: Sender<()>) -> ConnectionContext<CloseProbe> {
        ConnectionContext {
            ta: Arc::new(CloseProbe(closed)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_id: Arc::new(AtomicU32::new(1)),
            uuid: "test-ta".into(),
            listener_socket_path: PathBuf::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn failed_open_response_closes_context_and_releases_exclusive_slot() {
        let (closed_tx, closed_rx) = unbounded();
        let ctx = context(closed_tx);
        let (peer, mut server) = UnixStream::pair().unwrap();
        drop(peer);
        assert!(
            handle_open_session(
                &mut server,
                &ctx,
                ctx.uuid.clone(),
                Parameters::default(),
                None
            )
            .is_err()
        );
        closed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(ctx.sessions.lock().unwrap().is_empty());
        // A later Open must still be admitted by the exclusive-session check.
        let (peer, mut server) = UnixStream::pair().unwrap();
        handle_open_session(
            &mut server,
            &ctx,
            ctx.uuid.clone(),
            Parameters::default(),
            None,
        )
        .unwrap();
        drop(peer);
        let sid = *ctx.sessions.lock().unwrap().keys().next().unwrap();
        let tx = ctx.sessions.lock().unwrap().remove(&sid).unwrap();
        let (resp_tx, _) = unbounded();
        tx.send(SessionMessage::Close { resp_tx }).unwrap();
        closed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(closed_rx.try_recv().is_err());
    }

    #[test]
    fn unsupported_cancellation_returns_response_without_panicking() {
        let (closed_tx, _) = unbounded();
        let (mut peer, server) = UnixStream::pair().unwrap();
        let request =
            postcard::to_allocvec(&TaRequest::RequestCancellation { session_id: 7 }).unwrap();
        peer.write_all(&(request.len() as u32).to_ne_bytes())
            .unwrap();
        peer.write_all(&request).unwrap();
        handle_ca_connection(server, context(closed_tx)).unwrap();
        let mut header = [0; 4];
        peer.read_exact(&mut header).unwrap();
        let mut payload = vec![0; u32::from_ne_bytes(header) as usize];
        peer.read_exact(&mut payload).unwrap();
        assert!(
            matches!(postcard::from_bytes::<TEE_Response>(&payload).unwrap(),
            TEE_Response::RequestCancellation { result } if result == u32::from(Error::NotSupported))
        );
    }

    #[test]
    fn connection_admission_is_released_during_unwind() {
        let active = Arc::new(AtomicUsize::new(1));
        let count = active.clone();
        assert!(
            std::panic::catch_unwind(move || {
                let _connection = ActiveConnection(count);
                panic!("handler failure");
            })
            .is_err()
        );
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
