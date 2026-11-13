/*
 * LSP CA process-local C ABI v1 -- DESIGN DECLARATIONS ONLY.
 * No implementation is supplied by this header.
 *
 * Production implementation is a Rust native library in the MagicSmooth
 * APK/:runtime process. No daemon, helper process or remote listener.
 * Load once from the main App ClassLoader; no hot unload/reload in v1.
 * Product and mock builds reuse the SAME SOURCE CORE AND ABI. Additional
 * loaded-module identity is deferred unless real SDK admission requires it.
 * Preserve existing SDK verification and report its actual result; runtime
 * config MUST NOT inject verified=true or override identity UUIDs. A later
 * identity-enabled build may use separately signed product/mock descriptors.
 *
 * ABI scalars/structs are native C ABI on the selected Android target, NOT
 * LSP/1 wire serialization. Rust implementations use repr(C), fixed-width
 * fields and no unwinding across these functions. No Rust/C++ exception may
 * cross this boundary. Catchable panics become local errors; abort/OOM/UB
 * are not claimed recoverable.
 *
 * See docs/design/ca-jni-lifecycle-v0.1.md.
 */
#ifndef LSP_CA_FFI_V1_DRAFT_H
#define LSP_CA_FFI_V1_DRAFT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LSP_CA_ABI_V1 UINT32_C(1)

/* Process-local ABI statuses only; never use these as GP/LSP wire statuses. */
typedef int32_t lsp_ca_status_t;
enum {
    LSP_CA_OK = 0,
    LSP_CA_WAIT_TIMEOUT = 1,      /* Poll/join wait only; operation not cancelled. */
    LSP_CA_BUFFER_TOO_SMALL = 2,  /* Required lengths set; no lease/no dequeue. */
    LSP_CA_EVENT_PENDING = 3,     /* A delivery ticket is already outstanding. */
    LSP_CA_CLOSED = 4,            /* Consumer side closed or terminal ACKed. */
    LSP_CA_ALREADY = 5,           /* Idempotent control already accepted. */
    LSP_CA_TICKET_REVOKED = 6,    /* Close/lease deadline retired ticket; cancel retains it. */
    LSP_CA_E_INVALID_ARGUMENT = -1,
    LSP_CA_E_ABI_MISMATCH = -2,
    LSP_CA_E_INVALID_RUNTIME = -3,
    LSP_CA_E_INVALID_OPERATION = -4,
    LSP_CA_E_OWNER_MISMATCH = -5,
    LSP_CA_E_BUSY = -6,
    LSP_CA_E_RESOURCE_LIMIT = -7,
    LSP_CA_E_STALE_TICKET = -8,
    LSP_CA_E_OUT_OF_MEMORY = -9,
    LSP_CA_E_UNSUPPORTED = -10,
    LSP_CA_E_INTERNAL = -11,
    LSP_CA_E_PANIC = -12
};

/*
 * Opaque values. Never dereference/cast to pointers or serialize to disk.
 * process_epoch is generated once for this loaded library/process instance;
 * runtime_generation never reuses/wraps in that instance.
 */
typedef struct {
    uint64_t process_epoch_hi;
    uint64_t process_epoch_lo;
    uint64_t runtime_generation;
} lsp_ca_runtime_handle;

/*
 * Bound to the runtime supplied with EVERY call. Slot generation increments
 * on reuse; exhaustion retires the slot. A stale generation cannot access a
 * new operation. A handle is not authorization against hostile same-process
 * native code.
 */
typedef struct {
    lsp_ca_runtime_handle owner;
    uint64_t slot;
    uint64_t generation;
} lsp_ca_operation_handle;

/* Borrowed for the duration of a call only. NULL data iff len/capacity is 0. */
typedef struct {
    const uint8_t *data;
    uint32_t len;
    uint32_t reserved; /* 0 */
} lsp_ca_bytes;

typedef struct {
    uint8_t *data;
    uint32_t capacity;
    uint32_t reserved; /* 0 */
} lsp_ca_buffer;

enum {
    LSP_CA_RUNTIME_READY = 1, /* Local admission ready, not proof TA is reachable. */
    LSP_CA_RUNTIME_CLOSING = 2,
    LSP_CA_RUNTIME_STALLED = 3,
    LSP_CA_RUNTIME_QUIESCENT = 4,
    LSP_CA_RUNTIME_FAILED = 5
};

enum {
    LSP_CA_OP_QUEUED = 1,
    LSP_CA_OP_SETUP = 2,
    LSP_CA_OP_UPLOADING = 3,
    LSP_CA_OP_ACTIVE = 4,
    LSP_CA_OP_FINALIZING = 5,
    LSP_CA_OP_TERMINAL = 6
};

enum {
    LSP_CA_DELIVERY_OPEN = 1,
    LSP_CA_DELIVERY_LEASED = 2,
    LSP_CA_DELIVERY_DRAINING = 3,
    LSP_CA_DELIVERY_TERMINAL_AVAILABLE = 4,
    LSP_CA_DELIVERY_DONE = 5,
    LSP_CA_DELIVERY_DETACHED = 6
};

enum {
    LSP_CA_CLEANUP_LIVE = 1,
    LSP_CA_CLEANUP_REQUESTED = 2,
    LSP_CA_CLEANUP_SDK_CLOSING = 3,
    LSP_CA_CLEANUP_LOCAL_RELEASED = 4,
    LSP_CA_CLEANUP_STALLED = 5
};

enum {
    LSP_CA_OUTCOME_UNDECIDED = 0,
    LSP_CA_OUTCOME_COMPLETED = 1,
    LSP_CA_OUTCOME_INCOMPLETE = 2,
    LSP_CA_OUTCOME_PROVIDER_ERROR = 3,
    LSP_CA_OUTCOME_TRANSPORT_ERROR = 4,
    LSP_CA_OUTCOME_CANCELLED = 5,
    LSP_CA_OUTCOME_TIMEOUT = 6,
    LSP_CA_OUTCOME_PROTOCOL_ERROR = 7
};

/* model_outcome uses a strict subset; UNDECIDED maps to JSON null. */
enum {
    LSP_CA_MODEL_UNDECIDED = LSP_CA_OUTCOME_UNDECIDED,
    LSP_CA_MODEL_COMPLETED = LSP_CA_OUTCOME_COMPLETED,
    LSP_CA_MODEL_INCOMPLETE = LSP_CA_OUTCOME_INCOMPLETE,
    LSP_CA_MODEL_PROVIDER_ERROR = LSP_CA_OUTCOME_PROVIDER_ERROR,
    LSP_CA_MODEL_PROTOCOL_ERROR = LSP_CA_OUTCOME_PROTOCOL_ERROR
};

enum {
    LSP_CA_EVENT_RESPONSE_HEAD = 1,
    LSP_CA_EVENT_BODY = 2,
    LSP_CA_EVENT_MANAGEMENT_RESULT = 3,
    LSP_CA_EVENT_TERMINAL = 4
};

enum {
    LSP_CA_MANAGEMENT_PUT = 1,
    LSP_CA_MANAGEMENT_QUERY = 2,
    LSP_CA_MANAGEMENT_DELETE = 3,
    LSP_CA_MANAGEMENT_PROBE = 4 /* Native composite operation; LSP HELLO only. */
};

enum {
    LSP_CA_COMMIT_NOT_APPLICABLE = 0, /* Request, QUERY or PROBE. */
    LSP_CA_COMMIT_NOT_SENT = 1,
    LSP_CA_COMMIT_UNKNOWN = 2,
    LSP_CA_COMMIT_COMMITTED = 3,
    LSP_CA_COMMIT_NOT_COMMITTED_CONFIRMED = 4
};
/*
 * operation_get_info exposes this as a u32. TERMINAL metadata must expose
 * the same fact at event creation as one of these exact strings:
 * not_applicable / not_sent / unknown / committed / not_committed_confirmed.
 * It is distinct from cancellation and local/remote cleanup. A later QUERY
 * reconciliation is a new operation, not a rewrite of an emitted Terminal.
 */

enum {
    LSP_CA_CANCEL_USER = 1,
    LSP_CA_CANCEL_CALLER_GONE = 2,
    LSP_CA_CANCEL_TIMEOUT = 3,
    LSP_CA_CANCEL_SHUTDOWN = 4
};

enum {
    LSP_CA_ACK_DELIVERED = 1, /* BODY: delivered_bytes == data_len, others: 0. */
    LSP_CA_ACK_DROPPED = 2    /* Valid ticket + cancel_pending; known prefix. */
};

#define LSP_CA_EVENT_HAS_STREAM_OFFSET UINT32_C(1)
#define LSP_CA_INFO_DELIVERY_UNCERTAIN UINT32_C(1)
#define LSP_CA_INFO_REMOTE_CLEANUP_UNKNOWN UINT32_C(2)

/*
 * Caller sets struct_size=sizeof(struct), abi_version=LSP_CA_ABI_V1 before
 * passing any output structure. v1 requires exact values. No hidden output
 * allocation or cross-runtime allocator/free API is exposed.
 */
typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t state;
    uint32_t accepting; /* 0 or 1 */
    uint32_t operation_records;
    uint32_t active_workers;
    uint32_t pending_sdk_calls;
    uint32_t outstanding_event_leases;
    uint32_t max_event_metadata_bytes;
    uint32_t max_event_body_bytes;
    uint32_t max_read_wait_ms;
    uint32_t remote_cleanup_unknown_operations;
    uint64_t queued_body_bytes;
    uint64_t retained_secret_bytes;
} lsp_ca_runtime_info;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t phase;
    uint32_t delivery_state;
    uint32_t cleanup_state;
    uint32_t outcome;
    uint32_t model_outcome; /* LSP_CA_MODEL_* subset: 0,1,2,3,7 only. */
    uint32_t consumer_closed; /* 0 or 1 */
    uint32_t flags;           /* LSP_CA_INFO_* */
    uint32_t lease_remaining_ms;
    uint32_t management_commit_state; /* LSP_CA_COMMIT_*, distinct from cleanup. */
    uint32_t reserved;        /* 0 */
    uint64_t delivered_body_bytes_confirmed;
    uint64_t queued_body_bytes;
    uint64_t outstanding_ticket; /* 0 when none */
} lsp_ca_operation_info;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t kind;
    uint32_t flags;         /* LSP_CA_EVENT_HAS_STREAM_OFFSET only in v1 */
    uint64_t event_sequence;/* Process-local delivery sequence, not LSP event_seq */
    uint64_t ticket;        /* Lease attempt ID, changes after a NACK/re-read. */
    uint64_t stream_offset;
    uint32_t metadata_len;  /* Actual on OK; required on BUFFER_TOO_SMALL. */
    uint32_t body_len;      /* Actual on OK; required on BUFFER_TOO_SMALL. */
} lsp_ca_event;

/*
 * create: local config validation/admission setup only. Copies all config
 * bytes before returning. No SDK/network call on the calling JNI thread.
 * sdk_profile selects a build-supported transport/deployment combination;
 * it is not a claim that loaded-module identity has been implemented.
 * Config cannot override identity UUIDs or accept caller "verified=true".
 * One live runtime per process v1.
 */
lsp_ca_status_t lsp_ca_runtime_create(
    lsp_ca_bytes config_utf8_json, lsp_ca_runtime_handle *out_runtime);

lsp_ca_status_t lsp_ca_runtime_get_info(
    lsp_ca_runtime_handle runtime, lsp_ca_runtime_info *out_info);

/*
 * submit: short local call. OK means local queue admission plus valid handle,
 * NOT TA persistence, TLS, HTTP or provider success. Copies input before
 * return; no borrowed pointer survives. On failure no operation is admitted
 * and out_operation is zeroed. Real remote results arrive as events.
 */
lsp_ca_status_t lsp_ca_submit_request(
    lsp_ca_runtime_handle runtime, lsp_ca_bytes request_utf8_json,
    lsp_ca_bytes body, lsp_ca_operation_handle *out_operation);

lsp_ca_status_t lsp_ca_submit_management(
    lsp_ca_runtime_handle runtime, uint32_t management_kind,
    lsp_ca_bytes request_utf8_json, lsp_ca_bytes secret_utf8,
    lsp_ca_operation_handle *out_operation);

/*
 * One active reader and at most one outstanding ticket PER operation.
 * timeout_ms=0 polls; finite waits only, capped by runtime.max_read_wait_ms.
 * Waiting releases request/runtime locks; cancel/close/shutdown wake it.
 *
 * BUFFER_TOO_SMALL writes required lengths only: buffers unchanged, ticket=0,
 * event_sequence=0, no lease and no queue mutation. A retry may observe a
 * different head if cancellation wins; no implicit reservation is promised.
 *
 * OK copies a complete event to caller-owned buffers and creates a local
 * delivery lease. Event remains logically retained until ACK/NACK/revocation.
 * No partially copied event is exposed as OK. Metadata/body are length-
 * delimited, no trailing NUL guarantee. Success does not ACK the event.
 */
lsp_ca_status_t lsp_ca_read_event(
    lsp_ca_runtime_handle runtime, lsp_ca_operation_handle operation,
    uint32_t timeout_ms, lsp_ca_buffer metadata_out, lsp_ca_buffer body_out,
    lsp_ca_event *out_event);

/*
 * Local consumption ACK only; NOT LSP DATA_ACK and NOT a TA command.
 * DELIVERED means the serial Java adapter successfully handed the body to
 * the agreed consumer, not JNI copying or arbitrary Handler queue admission.
 * Calls are short and never invoke SDK. A matching settled last ticket may
 * return ALREADY; different disposition/byte count is rejected. Older ticket
 * is stale. ACK updates delivery accounting, not TLS input/output ownership.
 * DROPPED is valid only while cancel_pending with a live ticket; BODY permits
 * a known consumed prefix 0..body_len, control requires zero. Close/lease
 * revocation returns TICKET_REVOKED even for DROPPED; counts remain a lower
 * bound if a consumer callback may have acted before revocation.
 */
lsp_ca_status_t lsp_ca_ack_event(
    lsp_ca_runtime_handle runtime, lsp_ca_operation_handle operation,
    uint64_t ticket, uint32_t disposition, uint32_t delivered_bytes);

/*
 * NACK only before publishing the C event into Java/caller-visible state,
 * e.g. JNI allocation failed. Event stays at head; the next read gets a NEW
 * ticket but SAME event_sequence. No remote command is replayed.
 * If cancel_pending and ticket is valid, settle as dropped with zero bytes,
 * no requeue. Close/lease expiry revocation returns TICKET_REVOKED.
 */
lsp_ca_status_t lsp_ca_nack_event(
    lsp_ca_runtime_handle runtime, lsp_ca_operation_handle operation,
    uint64_t ticket);

/*
 * Independent short control path. Never waits for SDK Invoke/consumer/reader.
 * Request operations may schedule LSP CANCEL. Management sessions MUST NOT
 * receive that request-role opcode. A queued management write can be removed
 * before dispatch; an in-flight PUT/DELETE may already have committed.
 * SDK abort/cancel is not rollback: retain non-secret operation/ref/version
 * reconciliation data, mark commit UNKNOWN if necessary, QUERY later. Never
 * retain a Key merely to retry an uncertain write in the background.
 * The admin WORKER is shared/single-flight. Each management operation owns
 * a fresh context/session (Open/HELLO, one operation, Close/Finalize); PROBE
 * performs HELLO only. No idle session is reused across human interaction.
 * After an uncertain write, first issue read-only QUERY on a fresh context.
 * E_BUSY fences undispatched writes; their original deadline/budget remains.
 * Never replay the uncertain write or retain its Key for background retry.
 * Cancel retains an outstanding ticket until ACK/NACK or its original lease
 * expiry. No normal outcome can win after cancel; close revokes the ticket.
 */
lsp_ca_status_t lsp_ca_cancel(
    lsp_ca_runtime_handle runtime, lsp_ca_operation_handle operation,
    uint32_t reason);

lsp_ca_status_t lsp_ca_operation_get_info(
    lsp_ca_runtime_handle runtime, lsp_ca_operation_handle operation,
    lsp_ca_operation_info *out_info);

/*
 * close detaches consumer and schedules cancellation/cleanup if needed.
 * It revokes outstanding local tickets; already copied Java byte[] remains
 * Java-owned and valid. Late ACK is rejected safely and cannot update a
 * finalized outcome. Unconfirmed delivery is flagged as uncertain.
 * It is idempotent, non-joining, and does NOT free worker/context resources.
 * No later read starts a new delivery; an earlier committed read may finish
 * returning to Java and must be discarded by the closed Java facade.
 */
lsp_ca_status_t lsp_ca_operation_close(
    lsp_ca_runtime_handle runtime, lsp_ca_operation_handle operation);

/*
 * release retires the handle only after local SDK worker/context/buffers and
 * active ABI uses are quiescent, including this management operation's own
 * context/session references (the shared admin worker itself remains alive).
 * E_BUSY means not yet safe. Remote cleanup
 * may still be unknown and is not reclassified by freeing local resources.
 */
lsp_ca_status_t lsp_ca_operation_release(
    lsp_ca_runtime_handle runtime, lsp_ca_operation_handle operation);

/*
 * Process RuntimeHolder owns this runtime; Service recreation only reattaches.
 * Service.onDestroy MUST NOT call this function. CLOSING/STALLED must not be
 * bypassed by creating another runtime. Explicit disable/process-exit only.
 * Phase 1: reject new work, detach consumers, request all local cancellations,
 * wake readers and initiate per-context abort/close. No joins.
 */
lsp_ca_status_t lsp_ca_runtime_begin_shutdown(lsp_ca_runtime_handle runtime);

/*
 * Phase 2 wait: background thread only. Does not force-free anything.
 * WAIT_TIMEOUT leaves runtime alive in CLOSING/STALLED. Requires implemented
 * SDK abort/owner cleanup for bounded remote recovery; current 5s read timeout
 * is NOT evidence of that guarantee.
 */
lsp_ca_status_t lsp_ca_runtime_await_shutdown(
    lsp_ca_runtime_handle runtime, uint32_t timeout_ms,
    lsp_ca_runtime_info *out_info);

/*
 * Final free: allowed only once QUIESCENT, all operation handles released and
 * no other ABI calls in flight. E_BUSY never frees partially. No dlclose or
 * killing the app to cancel a single operation.
 */
lsp_ca_status_t lsp_ca_runtime_destroy(lsp_ca_runtime_handle runtime);

#ifdef __cplusplus
} /* extern "C" */
static_assert(sizeof(lsp_ca_runtime_handle) == 24, "runtime handle ABI");
static_assert(sizeof(lsp_ca_operation_handle) == 40, "operation handle ABI");
static_assert(sizeof(lsp_ca_event) == 48, "event ABI");
static_assert(sizeof(lsp_ca_runtime_info) == 64, "runtime info ABI");
static_assert(sizeof(lsp_ca_operation_info) == 72, "operation info ABI");
static_assert(offsetof(lsp_ca_operation_info, management_commit_state) == 40,
              "management commit state offset");
static_assert(offsetof(lsp_ca_operation_info, reserved) == 44,
              "operation info reserved offset");
static_assert(offsetof(lsp_ca_operation_info, delivered_body_bytes_confirmed) == 48,
              "operation delivered bytes offset");
static_assert(offsetof(lsp_ca_operation_info, outstanding_ticket) == 64,
              "operation outstanding ticket offset");
#else
_Static_assert(sizeof(lsp_ca_runtime_handle) == 24, "runtime handle ABI");
_Static_assert(sizeof(lsp_ca_operation_handle) == 40, "operation handle ABI");
_Static_assert(sizeof(lsp_ca_event) == 48, "event ABI");
_Static_assert(sizeof(lsp_ca_runtime_info) == 64, "runtime info ABI");
_Static_assert(sizeof(lsp_ca_operation_info) == 72, "operation info ABI");
_Static_assert(offsetof(lsp_ca_operation_info, management_commit_state) == 40,
               "management commit state offset");
_Static_assert(offsetof(lsp_ca_operation_info, reserved) == 44,
               "operation info reserved offset");
_Static_assert(offsetof(lsp_ca_operation_info, delivered_body_bytes_confirmed) == 48,
               "operation delivered bytes offset");
_Static_assert(offsetof(lsp_ca_operation_info, outstanding_ticket) == 64,
               "operation outstanding ticket offset");
#endif

#endif /* LSP_CA_FFI_V1_DRAFT_H */
