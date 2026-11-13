# TA Create failure reporting

`TAManager::run_ta` invokes Create before binding the TA listener or registering
Ready. If Create returns an error, its original 32-bit TEE result is reported to
the manager. Destroy and OpenSession are not called. Failure to deliver the
report is logged and does not replace the original Create error returned by the
SDK. Cancellation of nested TA calls is a separate feature.

## Registration wire compatibility

The existing `/tmp/server.sock` registration endpoint accepts a postcard enum.
Variant 0 has exactly the published `teec-protocol 0.2.0 TARequest::Register`
layout: UUID String, instance_id u32, socket_path String, single-instance bool,
multi-session bool, keep-alive bool. Existing TA binaries continue to register.

Variant 1 is `CreateFailed { uuid: String, instance_id: u32, result: u32 }`.
The result must be nonzero. The manager replies with a single byte: 1 if the
report was accepted, otherwise 0. The SDK keeps this connection open and waits
for acknowledgment, with 5-second socket read/write timeouts. This keeps the TA
alive while the manager authenticates and publishes the error; an exited child
must not be reaped before its error report is processed. Delivery is best effort:
an older manager rejects the new variant, and unavailable/mismatched binaries
can still produce a registration timeout. The manager and affected TA runtime
must both be rebuilt to enable error propagation.

The private definition is mirrored in `registration_protocol.rs` in xtee-utee
and vsock-manager. Fixed wire fixtures and legacy-registration tests pin both
copies. The published teec-protocol package is not modified or vendored. This
extension changes neither CA/VSOCK frames nor the plan-004 inter-TA control
protocol.

## Identity, concurrency, and cleanup

Reports are accepted only for an existing Starting instance with a matching
UUID, instance id, and verified SO_PEERCRED pid. A bounded condvar wait handles
pid publication after spawn; it releases the registry lock. Missing/mismatched
credentials, Ready/dead instances, duplicate reports, and success results are
rejected. Guest uid is currently 0 for TA processes, so pid matching remains
the identity boundary; the registration socket retains its restrictive mode.

Each Open attached to the same startup holds a shared one-shot error result.
The manager publishes the result under the registry lock before removing the
failed instance and waking waiters. This survives removal, prevents automatic
respawn within those failed Open calls, and avoids retaining failed instances.
New Open calls can start again. The original spawn caller checks that same
result and attempt identity when attaching its Child handle, including the
window between pid publication and child attachment. Timeout cleanup checks
the retained result under the lock before touching a possibly reused instance.

The manager acknowledges outside the registry lock, then kills/reaps the owned
child outside the lock using its existing bounded cleanup. If Child attachment
has not completed, the spawn caller performs that cleanup instead. Create
failure owns no listener node, so this cleanup never unlinks a path that a new
attempt could already be using.

The original error is returned by OpenSession with session id 0 and no session
binding. Inter-TA control responses use TRUSTED_APP origin for this TA error;
VSOCK retains its existing result-only response layout. Real RegisterTimeout
and SpawnQueueTimeout remain BUSY; spawn/internal failures remain GENERIC.

If the report is unavailable or rejected, existing registration-timeout cleanup
remains the fallback. This does not promise detection of arbitrary process
crashes or preservation of errors that cannot reach the registration service.
