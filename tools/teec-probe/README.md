# In-process backup CA and interoperability driver

The Rust library `lsp_backup_ca` contains GP/LSP framing, the request/session codec, the full bounded TLS/TCP pump, and a dedicated SDK owner for each opaque native handle. The `lsp-teec-probe` executable uses this library for device interoperability tests. Android calls the library from the runtime APK through `BackupTeeClient`.

## Android integration

The Java entry class is `com.kylinos.systemai.tee.BackupTeeClient`. Package the Java class and the two ARM64 libraries `liblsp_backup_ca.so` and `liblsp_backup_jni.so` in the APK. The class loads the core library followed by the JNI adapter. Preserve this class and its native method names during shrinking.

The current native C declarations are in `include/lsp_backup_ca.h`, matching `src/native.rs` and the declarations used by `src/jni_adapter.c`. The current Java API and this header describe the delivered APK module. The workspace's `lsp-ca-ffi-v1-draft.h` retains the fuller runtime-handle design for a subsequent interface revision.

The release couples the core, JNI adapter and Java JAR through a hash manifest. Its current input ceiling is 61440 bytes after HELLO advertises `bulk_input_frames`. Initial HELLO and featureless peers use 16384 bytes. The request pump selects 57280-byte or 15000-byte upload chunks from the peer's capability. GP replies remain bounded to 32768 bytes. The SDK checks readable/writable coverage across continuous adjacent VMAs while preserving the caller's original tagged addresses for memory access.

```proguard
-keep class com.kylinos.systemai.tee.BackupTeeClient { *; }
-keep class com.kylinos.systemai.tee.BackupTeeClient$** { *; }
```

`BackupTeeClient.open(cid, 10099)` returns a future. The endpoint is explicit and immutable in the task-owned SDK copy. Repeating an identical endpoint succeeds. A different endpoint within the same process is rejected. Configuration uses a OnceLock and is safe with existing Java threads.

Each handle owns one SDK thread, a boxed stable TEEC_Context and its TEEC_Session. `exchange(frame, outputCapacity)` submits one complete LSP request on that owner. The returned bytes contain a little-endian status u32, a little-endian frame length u32, followed by the LSP reply. E_OUTPUT_CAPACITY contains status 0x1001, required capacity 32768 and an empty reply. Callers may retry that capacity rejection with the same sequence. Other failed or uncertain invokes close the owner and require reconciliation or a new request according to the LSP contract.

`rawCall(configBytes, bodyBytes)` runs HELLO, OPEN, bounded upload, COMMIT, upstream TLS/TCP pumping, HTTP delivery, FINISH and SDK close. It requires a fresh handle. It returns a little-endian JSON metadata length u32, metadata JSON and the original HTTP body. Metadata includes `status`, `content_type`, `transport` and `body_length`. Request bodies support up to 33554432 bytes. Aggregate response capacity is configured through max_response_bytes, up to 67108864 bytes. JNI obtains the configured output capacity before allocating its aggregate output buffer. JSON and SSE response bytes are preserved.

A raw configuration object contains the following fields.

```json
{
  "namespace": "demo",
  "profile_id": "deepseek-prod-v1",
  "credential_ref": "00112233445566778899aabbccddeeff",
  "expected_version": 1,
  "operation": "CHAT",
  "response_mode": "sse",
  "overall_timeout_ms": 60000,
  "max_response_bytes": 1048576,
  "network_chunk_size": 8192,
  "upstream_ip": null,
  "headers": []
}
```

The raw configuration's expected_version is a JSON integer. The library encodes the LSP field as its required decimal string. Request body bytes contain the caller's original provider JSON or other supported payload. MODELS requires an empty body. Supported operations are CHAT, RESPONSES, MESSAGES, GENERATE, OLLAMA_CHAT and MODELS, subject to the credential's provider profile. Response modes are json, sse and ndjson. profile_id defaults to deepseek-prod-v1. The custom-provider-v1 profile uses the provider_config bound to its credential during provisioning. Gemini GENERATE also supplies model_id. The CA takes host, port and SNI from the TA's validated connect_target and checks canonical host syntax, matching SNI and HTTP/1.1 ALPN. An optional upstream_ip selects the TCP address, while TLS identity verification remains in the TA. network_chunk_size defaults to 8192 and bounds each TCP receive to 1–16384 bytes for fragmentation testing.

The Java class uses a dedicated request executor and futures, plus a shared cleanup reaper. A synchronized lifecycle gate selects one terminal winner for Raw completion, cancellation and close. One call may be pending per client. Public cancellation and close are idempotent. `cancel()` atomically signals the SDK owner independently of an occupied Invoke. The raw pump observes the flag at bounded network/relay points and sends business CANCEL when possible. An occupied SDK Invoke retains all memory until it returns. `closeAsync()` also signals that flag and its future completes after the SDK owner has returned from CloseSession and FinalizeContext. `isReleased()` reports this local cleanup fact. The TA's manager_cleanup value remains not_asserted.

## Incremental Android response delivery

`streamCall(configBytes, bodyBytes, listener)` uses the same request pump. `StreamListener.onHead(byte[])` receives the original HTTP_HEAD JSON with status and response headers. `onBody(byte[])` receives original body bytes in order, before the HTTP response completes. Chunk boundaries may split UTF-8 characters, JSON tokens, SSE lines and provider events. Incremental parsers retain the required small parsing state across callbacks.

Callbacks run synchronously on that client's request executor. The Rust SDK owner sends one bounded event and waits for its acknowledgement before another TA STEP or TCP read. The JNI adapter releases each chunk's local reference immediately. The listener may retain its own received arrays. Configured total response capacity remains bounded at 64 MiB. The native streaming pump retains each current frame and chunk through acknowledgement.

The future returns the same LE metadata-length plus metadata JSON envelope, with the complete body_length and zero aggregate body bytes. Successful completion follows HTTP_END, FINISH and SDK CloseSession/FinalizeContext. HTTP status remains available in the metadata. The caller applies its provider's application-level terminal rules.

A listener exception aborts delivery, requests business cancellation and completes the future exceptionally with the original Java Throwable. `client.cancel()`, `closeAsync()` and future cancellation signal the owner independently of a blocked listener. Cancellation rejects later callback admissions. A callback admitted before the terminal decision can return afterward. `cleanup()` reports SDK cleanup, and the listener's execution is independently owned by the request executor. Each client owns its own Java executor, SDK owner, context, TLS state and callback flow.

The request budget begins before REQUEST_OPEN. Upload, each connect attempt, TCP read, STEP and completion use the same absolute deadline. Each connect timeout is at most the remaining budget and five seconds. DNS and an occupied SDK invoke retain their owner and memory until they return. A late DNS return cannot admit another connection or successful completion.

Response metadata includes a separate ca_metrics object. SDK metrics contain OpenSession duration, Invoke count, Invoke total time and maximum Invoke latency. Request metrics contain time from request-pump entry to HTTP head, first body delivery and FINISH, together with TLS input/output and HTTP body byte counts. Durations use microseconds. request_total_us ends after FINISH and excludes subsequent SDK close/finalize. transport remains the TA terminal snapshot.

The low-level exchange method supports explicit management provisioning in APK memory. The caller owns and erases its original Key input array. The adapter erases its owned Java/C/Rust transport copies when their calls finish.

## Static interoperability CLI

All modes require the observed VM CID.

```sh
lsp-teec-probe --cid CID --port 10099 --probe
lsp-teec-probe --cid CID --port 10099 --test-suite
lsp-teec-probe --cid CID --port 10099 --parallel-suite
lsp-teec-probe --cid CID --port 10099 --fault-suite
lsp-teec-probe --cid CID --port 10099 --models
```

The probe checks OpenSession, output-capacity rejection, a same-sequence HELLO retry, p1/p2/LSP associations, and Close/Finalize return. The suite uses a fixed intentionally invalid test credential to check CRUD, CAS, receipt replay, adaptive admission, offsets, FINISH rejection, cancellation and terminal idempotence. The parallel suite starts one OS thread and SDK context for each advertised generation slot, races REQUEST_OPEN through a barrier and requires an additional OPEN to return BUSY. It checks update snapshot continuity, cancellation isolation, slot reuse, DELETE revocation of every old and updated snapshot and rejection of future opens. The fault suite checks session close during upload, incomplete FINISH, a synthetic network failure after the first TLS flight and fresh-context recovery. MODELS provisions a temporary fake credential, runs real upstream TLS, requires HTTP 401, FINISHes and deletes the fake credential.

Explicit credential import reads stdin. Only a terminal LF or CRLF is removed. The remaining 1–4096 UTF-8 bytes are preserved. Key bytes are excluded from argv, environment variables, diagnostics and output.

```sh
lsp-teec-probe --cid CID --provision-stdin --namespace demo \
  --credential-ref FRESH_REF --operation-id FRESH_OPERATION
```

`--profile-id custom-provider-v1 --provider-type TYPE --base-url HTTPS_BASE` provisions a custom provider configuration with the stdin credential. The TA normalizes and binds this configuration to the credential receipt. Reference-only requests pass the same --profile-id. Builtin calls default to deepseek-prod-v1.

```sh
lsp-teec-probe --cid CID --provision-stdin --namespace demo \
  --credential-ref FRESH_REF --operation-id FRESH_OPERATION \
  --profile-id custom-provider-v1 --provider-type openai_responses \
  --base-url https://api.deepseek.com/
lsp-teec-probe --cid CID --chat-stream --operation RESPONSES \
  --namespace demo --credential-ref REF --expected-version 1 \
  --profile-id custom-provider-v1 --model deepseek-flash
```

The import result contains only namespace, reference, version and receipt. PUT failure or uncertain transport is reported once. QUERY is the reconciliation path.

Normal tests use an existing reference and version.

```sh
lsp-teec-probe --cid CID --real-models --namespace demo \
  --credential-ref REF --expected-version 1
lsp-teec-probe --cid CID --chat --namespace demo \
  --credential-ref REF --expected-version 1 --model deepseek-flash
lsp-teec-probe --cid CID --chat-stream --namespace demo \
  --credential-ref REF --expected-version 1 --model deepseek-flash
```

`--parallel-chat --chat-stream` starts four reference-only requests, each with its own SDK context and synthetic marker. A barrier after successful REQUEST_OPEN keeps every request admitted before any body upload or COMMIT. The result records opened_before_first_commit. `--operation CHAT|RESPONSES|MESSAGES` selects the official DeepSeek request and completion format. CHAT requires stop and a complete DONE event. RESPONSES requires response.completed with completed status. MESSAGES requires end_turn and message_stop. JSON responses use the corresponding terminal fields. Reports contain hashes, counts, requested model and a bounded observed model identifier.

```sh
lsp-teec-probe --cid CID --parallel-chat --chat-stream --operation RESPONSES \
  --namespace demo --credential-ref REF --expected-version 1 --model deepseek-flash
lsp-teec-probe --cid CID --chat-stream --operation MESSAGES \
  --namespace demo --credential-ref REF --expected-version 1 --network-chunk-size 7
```

`--hold-upload` and `--hold-tls` create a temporary fake credential, emit hold_ready after reaching the chosen phase and hold the SDK session for 60 seconds. A device harness can terminate that test process to check manager-side disconnect cleanup. Normal return cancels the request and deletes the fake credential. The fake credential expires after its configured TTL when the process is terminated.

The chat probes encode a synthetic LSP_OK_ marker with eight random hex characters and a 512-token budget. They require HTTP 200, observed nonce content and finish_reason stop. Streaming additionally requires a complete SSE DONE event. Diagnostics contain status, lengths, hashes, token counts and completion booleans. Optional `--upstream-ip IP` supports Android static-musl environments whose libc resolver lacks the platform DNS configuration.

## Build

Static ARM64 driver builds use `CARGO_BUILD_JOBS=2`, the aarch64-unknown-linux-musl target, musl-gcc linker and musl-gcc CC. The task-owned build script is retained in `artifacts/ta-implementation-20261113/teec-probe/build.sh`.

For the Android core, source `artifacts/ta-implementation-20261113/android-toolchain/env.sh` and run the following command from this tools directory.

```sh
cargo build --lib --no-default-features --target aarch64-linux-android --offline
```

Compile `src/jni_adapter.c` with the Android toolchain wrapper as a shared PIC library, linking against the resulting `liblsp_backup_ca.so`. The Android toolchain lane retains the native build logs and final libraries in `artifacts/ta-implementation-20261113/android-backup-ca/`.

The copied SDK originates from the pinned rust-libteec 1a6c7619 source. The local patch adds explicit immutable endpoint configuration and Android/AArch64 tagged-heap VMA address normalization. The VMA check retains permission and extent validation, and memory access/deallocation retain their original pointer tags. ca-sign-verify remains enabled, and its actual identity/verification result continues through OpenSession. The local Cargo dependency enables rsa pkcs1v15 to compile tee_crypto 0.1.5 with rsa 0.10 final. Shared SDK sources and existing workspace lock files retain their prior contents.

## Provider extension artifacts

The extension's new build scripts and outputs are retained under `artifacts/provider-expansion-20261113/ca/`. build-static.sh builds the ARM64 static driver into bin/lsp-teec-probe. build-android.sh uses the existing task-owned Android toolchain and writes the core, JNI adapter and Java JAR to android/. Source snapshots and SHA256 values are saved before editing under before/.

The initial extension host gate passed 30 Rust/SDK tests, including incremental byte preservation, bounded acknowledgement, listener failure, cancellation isolation, aggregate compatibility, immutable deadline and protocol terminal truncation. The workspace harness at `artifacts/provider-expansion-20261113/ca/java-tests/` passes 103 cases using the production Java and JNI adapter with a test-only C ABI fixture. The 64 MiB streaming fixture runs with a 24 MiB Java heap. The Rust and Java copied-source mutation gates catch eight and six regressions respectively. GP/TLS/device acceptance is recorded by the root device lane.

## Current source-frozen release

The final bulk-input Android core is `7c98fd1e875ba1d6dd0ca739e7c0a7a2b34d94953462593460a1b8181185ef32`, paired with JNI `cdf92cd0e348643aa3ad793eff7ea138315e6eecfacc9e384fbc16a140ad761c` and Java JAR `d7c6cfca92e7e7f05e730ad7a6419166f008ff1ef1046ccd87529097e83f0b0a`. The release preserves the 23 core export names and seven JNI entry points. Its actual process-local C API consists of the nine `lsp_native_*` functions in `include/lsp_backup_ca.h`.

The final CA host suite passes 40 cases. The retained SDK VMA adaptation passes 145 SDK cases with its associated negative controls. The final TA host gates pass 63 library cases and five GP-entry cases. Bulk transport has seven caught regression mutations. Source and exact build identities are under the workspace artifact `perf-optimization/bulk-input/`.

The ordinary-UID final-peer APK on `.18` passes all eight device cases on the final TA/manager combination. Its HELLO and same-context QUERY validate frame bounds, epoch, nonce and public receipt. Cases cover streaming, a slow listener, callback exception propagation, cancellation, close, future cancellation and fresh MODELS recovery.

The earlier new-CA/old-TA compatibility cohort retains two strict-content failures. The first fixture omitted the detailed completion flags. A later failure had HTTP 200, matching body lengths, stop/DONE and complete SSE framing, with the generated marker absent. Five subsequent diagnostic slow-listener cases passed unchanged strict checks. The original records and the final-peer cohort are separately indexed in `apk-stream-final/` and `apk-stream-final-peer/`.

## Earlier verified delivery checkpoint

The root device lane verified the backup APK in an ordinary Android UID on the protected-VM endpoint. Its final lifecycle candidate passed six device cases, including MODELS HTTP 200, real Chat SSE, cancellation followed by a fresh MODELS request, and close followed by a fresh MODELS request. The tested Bionic core SHA256 is `3ec120d06263f23595642096e6fc114216de5fbfeb3d1ae29954fbbee948ca3a`. The tested lifecycle Java JAR is `artifacts/ta-implementation-20261113/android-backup-ca/lsp-backup-ca-java-lifecycle.jar`, SHA256 `220aa9874207791809f6db4af40fc7c52d2ccc0118d976165c3f15d9dca411cd`. The delivery lane also places this Java implementation at the primary `lsp-backup-ca-java.jar` filename.

The final short-marker CLI completed ten consecutive real SSE requests on the 19 device. The 18 device completed ten consecutive requests with the earlier long marker and another short-marker SSE request after VM restart. Earlier failed synthetic runs are retained in the acceptance artifacts.

Host validation includes 17 Rust/SDK tests and 80 Java lifecycle cases using an explicitly test-only JNI stub. Forty of the Java cases race cancellation with completion. Device results remain recorded separately from these host gates.

The SDK endpoint is fixed for the lifetime of the Android runtime process. After a VM restart yields a new CID, persist the validated nonsecret endpoint configuration and recreate the Android runtime process before opening the new SDK context. Preserve the project's TA persistent data across ordinary VM restarts. The existing key reference and version are then used for normal requests.

Cancellation and close select a single Java terminal winner against Raw completion. Cleanup polling uses a separate shared reaper and releases each handle once. The public cancel/close calls remain idempotent after normal completion, cancellation and cleanup.

The delivery lane's final source-frozen Android core rebuild has SHA256 `280af05efc6e1c4d2ad1c855471546aef759f0e81b5ebe184459cec14f5be7c8`. Its binary/source manifests are retained beside the libraries. The tested `3ec120d...` checkpoint is archived separately, preserving its runtime evidence. The primary and lifecycle Java JAR filenames both contain the same `220aa987...` lifecycle implementation.
