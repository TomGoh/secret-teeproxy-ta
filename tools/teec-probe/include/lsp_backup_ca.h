#ifndef LSP_BACKUP_CA_H
#define LSP_BACKUP_CA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Current APK library ABI. Native scalars use the target C ABI.
 * Input/output memory belongs to the caller and remains valid for the call.
 * Use a fresh opaque handle for each raw/stream request. */

/* Returns a nonzero handle, or zero on failure. Endpoint is process-immutable. */
uint64_t lsp_native_open(uint32_t cid, uint32_t port);

/* Runs one credential-free health probe synchronously on a dedicated worker.
 * Output capacity is at least 2048. Returns UTF-8 JSON bytes or -1 on invalid
 * output/encoding. Normal availability failures are represented inside JSON.
 * The calling thread retains SDK ownership until Close/Finalize returns.
 * No native handle remains after return. An observer timeout leaves the
 * calling thread responsible for this call through actual return. */
int64_t lsp_native_probe_health(uint32_t cid, uint32_t port,
    uint8_t *output, size_t output_capacity);

/* Output capacity must be at least 32776 bytes. capacity is GP p1 capacity.
 * Returns output bytes, or -1. Envelope is LE status u32 + LE length u32
 * followed by the LSP frame. Peer input limits come from HELLO. */
int64_t lsp_native_exchange(uint64_t handle, const uint8_t *input,
    size_t length, size_t capacity, uint8_t *output, size_t output_capacity);

/* Configuration is UTF-8 JSON, at most 4096 bytes. Returns required aggregate
 * output capacity, or -1. The caller allocates this full capacity for raw_call. */
int64_t lsp_native_raw_capacity(const uint8_t *config, size_t config_length);

/* Returns encoded bytes, or -1. Output is LE metadata length u32, metadata
 * JSON and original body bytes. Body input is at most 33554432 bytes.
 * Pass a valid non-NULL body pointer also for a zero-length MODELS body. */
int64_t lsp_native_raw_call(uint64_t handle, const uint8_t *config,
    size_t config_length, const uint8_t *body, size_t body_length,
    uint8_t *output, size_t output_capacity);

/* kind 1 is HTTP_HEAD JSON. kind 2 is original HTTP body bytes.
 * The slice is borrowed until callback return. Return zero to accept.
 * Callback and user_data stay valid until stream_call returns. */
typedef int32_t (*lsp_stream_callback)(void *user_data, uint32_t kind,
    const uint8_t *bytes, size_t length);

/* Synchronous on the calling thread, with bounded one-event ACK delivery.
 * Output capacity is at least 8192. Successful output contains LE metadata
 * length + metadata JSON, with zero aggregate body bytes. Returns bytes or -1. */
int64_t lsp_native_stream_call(uint64_t handle, const uint8_t *config,
    size_t config_length, const uint8_t *body, size_t body_length,
    lsp_stream_callback callback, void *user_data,
    uint8_t *output, size_t output_capacity);

/* Returns 0 when the cancellation request is accepted, or -1 on error. */
int32_t lsp_native_cancel(uint64_t handle);

/* Returns 0 while SDK cleanup is pending, 1 after SDK cleanup and handle
 * retirement, or -1 on error. A retired handle is stale. The stream callback
 * may still be returning, so its memory lifetime also follows stream_call. */
int32_t lsp_native_close(uint64_t handle);

/* Returns 0/1 for SDK cleanup state of a live handle, or -1 on error. */
int32_t lsp_native_released(uint64_t handle);

/* Borrowed thread-local UTF-8 error. Copy before another failing native call
 * on the same thread. The caller leaves ownership with this library. */
const char *lsp_native_last_error(void);

#ifdef __cplusplus
}
#endif
#endif
