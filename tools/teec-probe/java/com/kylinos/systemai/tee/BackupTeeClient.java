package com.kylinos.systemai.tee;

import java.util.Arrays;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/** In-process GP bridge for the runtime APK. Each instance owns one SDK context. */
public final class BackupTeeClient implements AutoCloseable {
    static {
        System.loadLibrary("lsp_backup_ca");
        System.loadLibrary("lsp_backup_jni");
    }

    private static final ScheduledExecutorService REAPER =
        Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "lsp-apk-cleanup");
            thread.setDaemon(true);
            return thread;
        });
    private enum Terminal { ACTIVE, COMPLETED, FAILED, CANCELLED, CLOSED }
    private final Object lifecycle = new Object();
    private final ExecutorService executor =
        Executors.newSingleThreadExecutor(r -> new Thread(r, "lsp-apk-owner"));
    private final CompletableFuture<Void> cleanup = new CompletableFuture<>();
    private Terminal terminal = Terminal.ACTIVE;
    private CompletableFuture<byte[]> pending;
    private boolean exchangeUsed;
    private boolean rawStarted;
    private boolean cleanupStarted;
    private boolean handleRemoved;
    private long handle;

    private BackupTeeClient() {}

    /** Runs one credential-free manager/TA probe synchronously on its caller.
     * Invoke on a dedicated background worker. The UTF-8 JSON result follows
     * SDK CloseSession/FinalizeContext return, with no retained native handle.
     * An observer timeout keeps this call and its worker owned until return.
     */
    public static byte[] probeHealthBlocking(int cid, int port) {
        return nativeProbeHealth(cid, port);
    }

    /** Receives HTTP head metadata and original body chunks synchronously on this
     * client's request executor. Returning from a callback allows the native pump
     * to proceed. A listener may retain its byte array. Callback exceptions fail
     * the request, and cleanup remains observable through cleanup().
     */
    public interface StreamListener {
        void onHead(byte[] metadata);
        void onBody(byte[] bytes);
    }

    public static CompletableFuture<BackupTeeClient> open(int cid, int port) {
        BackupTeeClient client = new BackupTeeClient();
        CompletableFuture<BackupTeeClient> result = new CompletableFuture<>();
        client.executor.execute(() -> {
            try {
                client.handle = nativeOpen(cid, port);
                if (!result.complete(client)) client.closeAsync();
            } catch (Throwable failure) {
                client.executor.shutdown();
                result.completeExceptionally(failure);
            }
        });
        return result;
    }

    /** Returns LE status u32 + frame-length/required-capacity u32 + LSP reply.
     * OUTPUT_CAPACITY returns required-capacity 32768 and an empty reply.
     * The caller owns and erases its original input array.
     */
    public CompletableFuture<byte[]> exchange(byte[] frame, int outputCapacity) {
        java.util.Objects.requireNonNull(frame,"frame");
        CompletableFuture<byte[]> result = reserve(false);
        if (result.isDone()) return result;
        byte[] copied = null;
        try {
            copied = frame.clone();
            final byte[] owned = copied;
            submit(() -> {
                try {
                    if (isPending(result))
                        publish(result, nativeExchange(handle, owned, outputCapacity), null, false);
                } catch (Throwable failure) {
                    publish(result, null, failure, false);
                } finally {
                    Arrays.fill(owned, (byte)0);
                }
            }, result, owned);
        } catch (Throwable failure) {
            if (copied != null) Arrays.fill(copied, (byte)0);
            publish(result, null, failure, false);
        }
        return result;
    }

    /** Runs the shared complete LSP/TLS/TCP pump on a fresh handle.
     * Returns LE metadata-length u32, status/content_type/transport/body_length
     * JSON, then original HTTP body bytes. Configured body capacity is at most
     * 64 MiB. Request bodies are bounded at 32 MiB.
     * SDK close/finalize return before nativeRawCall returns its complete body.
     */
    public CompletableFuture<byte[]> rawCall(byte[] config, byte[] body) {
        return httpCall(config, body, null);
    }

    /** Delivers the HTTP body incrementally with bounded native backpressure.
     * The future returns LE metadata-length u32 followed by completion metadata
     * JSON, including total body_length. It carries no aggregate body bytes.
     * Successful completion follows HTTP_END, FINISH and SDK close/finalize.
     * Cancellation prevents further callback admissions. A callback admitted
     * before cancellation may return afterward, so listeners must avoid waiting
     * for cleanup() on their callback thread.
     */
    public CompletableFuture<byte[]> streamCall(byte[] config, byte[] body,
            StreamListener listener) {
        java.util.Objects.requireNonNull(listener, "listener");
        return httpCall(config, body, listener);
    }

    private CompletableFuture<byte[]> httpCall(byte[] config, byte[] body,
            StreamListener listener) {
        java.util.Objects.requireNonNull(config,"config");
        java.util.Objects.requireNonNull(body,"body");
        CompletableFuture<byte[]> result = reserve(true);
        if (result.isDone()) return result;
        if (config.length > 4096 || body.length > 32 * 1024 * 1024) {
            publish(result, null, new IllegalArgumentException("HTTP input bounds"), true);
            return result;
        }
        byte[] copiedConfig = null;
        byte[] copiedBody = null;
        try {
            copiedConfig = config.clone();
            copiedBody = body.clone();
            final byte[] ownedConfig = copiedConfig;
            final byte[] ownedBody = copiedBody;
            submit(() -> {
                try {
                    if (isPending(result)) {
                        byte[] response = listener == null
                            ? nativeRawCall(handle, ownedConfig, ownedBody)
                            : nativeStreamCall(handle, ownedConfig, ownedBody,
                                new StreamListener() {
                                    @Override public void onHead(byte[] metadata) {
                                        admitCallback(result);
                                        listener.onHead(metadata);
                                    }
                                    @Override public void onBody(byte[] bytes) {
                                        admitCallback(result);
                                        listener.onBody(bytes);
                                    }
                                });
                        publish(result, response, null, true);
                    }
                } catch (Throwable failure) {
                    publish(result, null, failure, true);
                } finally {
                    Arrays.fill(ownedConfig, (byte)0);
                    Arrays.fill(ownedBody, (byte)0);
                    beginCleanup();
                }
            }, result, ownedConfig, ownedBody);
        } catch (Throwable failure) {
            if (copiedConfig != null) Arrays.fill(copiedConfig, (byte)0);
            if (copiedBody != null) Arrays.fill(copiedBody, (byte)0);
            publish(result, null, failure, true);
        }
        return result;
    }

    private void admitCallback(CompletableFuture<byte[]> result) {
        synchronized (lifecycle) {
            if (pending != result || terminal != Terminal.ACTIVE)
                throw new CancellationException("TEE stream cancelled or closed");
        }
    }

    private CompletableFuture<byte[]> reserve(boolean raw) {
        CompletableFuture<byte[]> result = new CompletableFuture<>();
        synchronized (lifecycle) {
            if (terminal != Terminal.ACTIVE || pending != null || rawStarted
                    || raw && exchangeUsed) {
                result.completeExceptionally(new IllegalStateException("TEE handle busy or ended"));
                return result;
            }
            pending = result;
            if (raw) rawStarted = true;
            else exchangeUsed = true;
        }
        result.whenComplete((response, failure) -> {
            if (result.isCancelled()) stop(Terminal.CANCELLED);
        });
        return result;
    }

    private boolean isPending(CompletableFuture<byte[]> result) {
        synchronized (lifecycle) { return pending == result && terminal == Terminal.ACTIVE; }
    }

    private void publish(CompletableFuture<byte[]> result, byte[] response,
            Throwable failure, boolean raw) {
        synchronized (lifecycle) {
            if (pending != result || terminal != Terminal.ACTIVE) return;
            pending = null;
            if (failure != null) terminal = Terminal.FAILED;
            else if (raw) terminal = Terminal.COMPLETED;
        }
        // The terminal decision is immutable before callbacks are invoked.
        if (raw || failure != null) beginCleanup();
        if (failure == null) result.complete(response);
        else result.completeExceptionally(failure);
    }

    /** Records cancellation immediately. cleanup() independently tracks the SDK
     * owner's actual CloseSession/FinalizeContext return.
     */
    public void cancel() { stop(Terminal.CANCELLED); }

    public CompletableFuture<Void> closeAsync() {
        stop(Terminal.CLOSED);
        return cleanup;
    }

    private void stop(Terminal reason) {
        CompletableFuture<byte[]> rejected = null;
        synchronized (lifecycle) {
            if (terminal == Terminal.ACTIVE) {
                terminal = reason;
                rejected = pending;
                pending = null;
            }
        }
        beginCleanup();
        if (rejected != null)
            rejected.completeExceptionally(new CancellationException("TEE request cancelled or closed"));
    }

    public CompletableFuture<Void> cleanup() { return cleanup; }

    public boolean isReleased() {
        synchronized (lifecycle) { return handleRemoved || nativeReleased(handle); }
    }

    private void submit(Runnable action, CompletableFuture<byte[]> result, byte[]... owned) {
        try {
            executor.execute(action);
        } catch (Throwable failure) {
            for (byte[] buffer : owned) Arrays.fill(buffer, (byte)0);
            publish(result, null, failure, rawStarted);
        }
    }

    private void beginCleanup() {
        synchronized (lifecycle) {
            if (cleanupStarted) return;
            cleanupStarted = true;
        }
        pollCleanup();
    }

    private void pollCleanup() {
        try {
            boolean done;
            synchronized (lifecycle) {
                done = handleRemoved || nativeClose(handle);
                if (done) handleRemoved = true;
            }
            if (done) {
                executor.shutdown();
                cleanup.complete(null);
            } else REAPER.schedule(this::pollCleanup, 50, TimeUnit.MILLISECONDS);
        } catch (Throwable failure) {
            executor.shutdown();
            cleanup.completeExceptionally(failure);
        }
    }

    @Override public void close() { closeAsync(); }

    private static native byte[] nativeProbeHealth(int cid, int port);
    private static native long nativeOpen(int cid, int port);
    private static native byte[] nativeExchange(long handle, byte[] frame, int capacity);
    private static native byte[] nativeRawCall(long handle, byte[] config, byte[] body);
    private static native byte[] nativeStreamCall(long handle, byte[] config, byte[] body,
            StreamListener listener);
    private static native boolean nativeClose(long handle);
    private static native boolean nativeReleased(long handle);
}
