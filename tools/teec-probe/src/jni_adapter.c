/* APK in-process JNI adapter. Link against liblsp_backup_ca.so. */
#include <jni.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern uint64_t lsp_native_open(uint32_t cid, uint32_t port);
extern int64_t lsp_native_exchange(uint64_t handle, const uint8_t *input,
    size_t length, size_t capacity, uint8_t *output, size_t output_capacity);
extern int32_t lsp_native_cancel(uint64_t handle);
extern int32_t lsp_native_close(uint64_t handle);
extern int32_t lsp_native_released(uint64_t handle);
extern const char *lsp_native_last_error(void);
typedef int32_t (*lsp_stream_callback)(void *user_data, uint32_t kind,
    const uint8_t *bytes, size_t length);
extern int64_t lsp_native_raw_call(uint64_t handle, const uint8_t *config,
    size_t config_length, const uint8_t *body, size_t body_length,
    uint8_t *output, size_t output_capacity);
extern int64_t lsp_native_raw_capacity(const uint8_t *config, size_t config_length);
extern int64_t lsp_native_stream_call(uint64_t handle, const uint8_t *config,
    size_t config_length, const uint8_t *body, size_t body_length,
    lsp_stream_callback callback, void *user_data,
    uint8_t *output, size_t output_capacity);

static void throw_error(JNIEnv *env, const char *message) {
    jclass error = (*env)->FindClass(env, "java/lang/IllegalStateException");
    if (error != NULL) (*env)->ThrowNew(env, error, message);
}

JNIEXPORT jlong JNICALL
Java_com_kylinos_systemai_tee_BackupTeeClient_nativeOpen(
    JNIEnv *env, jclass clazz, jint cid, jint port) {
    (void)clazz;
    if (cid <= 2 || port <= 0) {
        throw_error(env, "Invalid explicit VSOCK endpoint");
        return 0;
    }
    uint64_t handle = lsp_native_open((uint32_t)cid, (uint32_t)port);
    if (handle == 0) throw_error(env, lsp_native_last_error());
    return (jlong)handle;
}

JNIEXPORT jbyteArray JNICALL
Java_com_kylinos_systemai_tee_BackupTeeClient_nativeExchange(
    JNIEnv *env, jclass clazz, jlong handle, jbyteArray input, jint capacity) {
    (void)clazz;
    if (input == NULL || capacity < 0 || capacity > 32768) {
        throw_error(env, "Invalid LSP frame or output capacity");
        return NULL;
    }
    jsize length = (*env)->GetArrayLength(env, input);
    if (length < 64 || length > 61440) {
        throw_error(env, "LSP input frame length exceeds bounds");
        return NULL;
    }
    uint8_t *bytes = malloc((size_t)length);
    uint8_t *output = malloc(32776);
    if (bytes == NULL || output == NULL) {
        free(bytes); free(output);
        throw_error(env, "JNI frame allocation failed");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, input, 0, length, (jbyte *)bytes);
    int64_t count = -1;
    if (!(*env)->ExceptionCheck(env)) {
        count = lsp_native_exchange((uint64_t)handle, bytes, (size_t)length,
            (size_t)capacity, output, 32776);
    }
    volatile uint8_t *wipe = bytes;
    for (jsize i = 0; i < length; ++i) wipe[i] = 0;
    free(bytes);
    jbyteArray result = NULL;
    if (!(*env)->ExceptionCheck(env)) {
        if (count < 0) throw_error(env, lsp_native_last_error());
        else if (count > 32776) throw_error(env, "JNI exchange output exceeds capacity");
        else {
            result = (*env)->NewByteArray(env, (jsize)count);
            if (result != NULL)
                (*env)->SetByteArrayRegion(env, result, 0, (jsize)count, (jbyte *)output);
        }
    }
    free(output);
    return result;
}

JNIEXPORT void JNICALL
Java_com_kylinos_systemai_tee_BackupTeeClient_nativeCancel(
    JNIEnv *env, jclass clazz, jlong handle) {
    (void)clazz;
    if (lsp_native_cancel((uint64_t)handle) < 0)
        throw_error(env, lsp_native_last_error());
}

JNIEXPORT jboolean JNICALL
Java_com_kylinos_systemai_tee_BackupTeeClient_nativeClose(
    JNIEnv *env, jclass clazz, jlong handle) {
    (void)clazz;
    int32_t result = lsp_native_close((uint64_t)handle);
    if (result < 0) throw_error(env, lsp_native_last_error());
    return result > 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_kylinos_systemai_tee_BackupTeeClient_nativeReleased(
    JNIEnv *env, jclass clazz, jlong handle) {
    (void)clazz;
    int32_t result = lsp_native_released((uint64_t)handle);
    if (result < 0) throw_error(env, lsp_native_last_error());
    return result > 0 ? JNI_TRUE : JNI_FALSE;
}

struct stream_bridge {
    JNIEnv *env;
    jobject listener;
    jmethodID on_head;
    jmethodID on_body;
};

/* Rust dispatches this synchronously on the JNI caller thread. Local references
 * are released per event, bounding retained JNI memory for long streams. */
static int32_t deliver_stream(void *user_data, uint32_t kind,
    const uint8_t *bytes, size_t length) {
    struct stream_bridge *bridge = user_data;
    JNIEnv *env = bridge->env;
    if ((*env)->ExceptionCheck(env)) return -1;
    if ((kind != 1 && kind != 2) || length > 32768 ||
        (length > 0 && bytes == NULL)) {
        throw_error(env, "Invalid native stream event");
        return -1;
    }
    jbyteArray chunk = (*env)->NewByteArray(env, (jsize)length);
    if (chunk == NULL) return -1;
    (*env)->SetByteArrayRegion(env, chunk, 0, (jsize)length, (const jbyte *)bytes);
    if (!(*env)->ExceptionCheck(env))
        (*env)->CallVoidMethod(env, bridge->listener,
            kind == 1 ? bridge->on_head : bridge->on_body, chunk);
    (*env)->DeleteLocalRef(env, chunk);
    return (*env)->ExceptionCheck(env) ? -1 : 0;
}

static void wipe_free(uint8_t *bytes, size_t length) {
    if (bytes != NULL) {
        volatile uint8_t *wipe = bytes;
        for (size_t i = 0; i < length; ++i) wipe[i] = 0;
        free(bytes);
    }
}

static jbyteArray http_call(JNIEnv *env, jlong handle, jbyteArray config,
    jbyteArray body, struct stream_bridge *bridge) {
    if (config == NULL || body == NULL) {
        throw_error(env, "rawCall configuration and body required"); return NULL;
    }
    jsize config_length = (*env)->GetArrayLength(env, config);
    jsize body_length = (*env)->GetArrayLength(env, body);
    if (config_length > 4096 || body_length > 32 * 1024 * 1024) {
        throw_error(env, "rawCall input bounds"); return NULL;
    }
    uint8_t *config_bytes = malloc((size_t)config_length + 1);
    if (config_bytes == NULL) {
        throw_error(env, "rawCall configuration allocation failed"); return NULL;
    }
    (*env)->GetByteArrayRegion(env, config, 0, config_length, (jbyte *)config_bytes);
    if ((*env)->ExceptionCheck(env)) {
        wipe_free(config_bytes, (size_t)config_length);
        return NULL;
    }
    int64_t configured_capacity = bridge == NULL
        ? lsp_native_raw_capacity(config_bytes, (size_t)config_length) : 8192;
    if (configured_capacity < 8192 || configured_capacity > 64 * 1024 * 1024 + 8192) {
        wipe_free(config_bytes, (size_t)config_length);
        throw_error(env, lsp_native_last_error());
        return NULL;
    }
    size_t capacity = (size_t)configured_capacity;
    uint8_t *body_bytes = malloc((size_t)body_length + 1);
    uint8_t *output = malloc(capacity);
    if (body_bytes == NULL || output == NULL) {
        wipe_free(config_bytes, (size_t)config_length); free(body_bytes); free(output);
        throw_error(env, "rawCall allocation failed"); return NULL;
    }
    (*env)->GetByteArrayRegion(env, body, 0, body_length, (jbyte *)body_bytes);
    int64_t count = -1;
    if (!(*env)->ExceptionCheck(env)) {
        if (bridge == NULL)
            count = lsp_native_raw_call((uint64_t)handle, config_bytes,
                (size_t)config_length, body_bytes, (size_t)body_length, output, capacity);
        else
            count = lsp_native_stream_call((uint64_t)handle, config_bytes,
                (size_t)config_length, body_bytes, (size_t)body_length,
                deliver_stream, bridge, output, capacity);
    }
    wipe_free(config_bytes, (size_t)config_length);
    wipe_free(body_bytes, (size_t)body_length);
    jbyteArray result = NULL;
    if (!(*env)->ExceptionCheck(env)) {
        if (count < 0) throw_error(env, lsp_native_last_error());
        else if ((uint64_t)count > capacity)
            throw_error(env, "JNI HTTP output exceeds capacity");
        else {
            result = (*env)->NewByteArray(env, (jsize)count);
            if (result != NULL)
                (*env)->SetByteArrayRegion(env, result, 0, (jsize)count, (jbyte *)output);
        }
    }
    wipe_free(output, capacity);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_kylinos_systemai_tee_BackupTeeClient_nativeRawCall(
    JNIEnv *env, jclass clazz, jlong handle, jbyteArray config, jbyteArray body) {
    (void)clazz;
    return http_call(env, handle, config, body, NULL);
}

JNIEXPORT jbyteArray JNICALL
Java_com_kylinos_systemai_tee_BackupTeeClient_nativeStreamCall(
    JNIEnv *env, jclass clazz, jlong handle, jbyteArray config, jbyteArray body,
    jobject listener) {
    (void)clazz;
    if (listener == NULL) {
        throw_error(env, "Stream listener required");
        return NULL;
    }
    jclass listener_class = (*env)->GetObjectClass(env, listener);
    if (listener_class == NULL) return NULL;
    struct stream_bridge bridge = { env, listener,
        (*env)->GetMethodID(env, listener_class, "onHead", "([B)V"), NULL };
    if (bridge.on_head != NULL)
        bridge.on_body = (*env)->GetMethodID(env, listener_class, "onBody", "([B)V");
    (*env)->DeleteLocalRef(env, listener_class);
    if (bridge.on_head == NULL || bridge.on_body == NULL) return NULL;
    return http_call(env, handle, config, body, &bridge);
}
