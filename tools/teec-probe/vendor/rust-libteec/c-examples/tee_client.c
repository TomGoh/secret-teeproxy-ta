// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/queue.h>
#include <errno.h>
#include <error.h>

#include "tee_client_api.h"
#include "teec_trace.h"

/**
 * 格式化 UUID 为字符串
 */
static void format_uuid_string(TEEC_UUID *uuid, char *buf, size_t buf_size)
{
    if (!uuid || !buf)
        return;

    snprintf(buf, buf_size,
             "UUID: { 0x%.8x 0x%.4x 0x%.4x { 0x%.2x 0x%.2x 0x%.2x 0x%.2x "
             "0x%.2x 0x%.2x 0x%.2x 0x%.2x }}",
             uuid->timeLow, uuid->timeMid, uuid->timeHiAndVersion,
             uuid->clockSeqAndNode[0], uuid->clockSeqAndNode[1],
            uuid->clockSeqAndNode[2], uuid->clockSeqAndNode[3],
            uuid->clockSeqAndNode[4], uuid->clockSeqAndNode[5],
            uuid->clockSeqAndNode[6], uuid->clockSeqAndNode[7]);
}

/**
 * @brief 初始化TEE上下文
 *
 * @return TEEC_Result 操作结果
 */
TEEC_Result init_tee_context(TEEC_Context *ctx)
{
    TEEC_Result res = TEEC_InitializeContext(NULL, ctx);
    if (res != TEEC_SUCCESS) {
        EMSG("TEEC_InitializeContext failed with code 0x%x", res);
    }
    return res;
}

/**
 * @brief 打开TEE会话
 *
 * @param session 会话指针
 * @param ret_orig 错误来源指针
 * @return TEEC_Result 操作结果
 */
TEEC_Result open_tee_session(TEEC_Context *ctx,
                             TEEC_Session *session,
                             TEEC_UUID *uuid,
                             uint32_t *ret_orig)
{
    TEEC_Result res = TEEC_OpenSession(ctx, session, uuid,
                                       TEEC_LOGIN_PUBLIC,
                                       NULL, NULL, ret_orig);

    if (res != TEEC_SUCCESS) {
        char buf[128] = {0};
        format_uuid_string(uuid, buf, sizeof(buf));
        /* ret_orig 可为 NULL（与底层 TEEC_OpenSession 兼容），解引用前判空 */
        EMSG("%s TEEC_Opensession failed with code 0x%x origin 0x%x",
             buf, res, ret_orig ? *ret_orig : 0);
    }
    return res;
}

/**
 * 初始化 TEE 上下文并打开会话
 *
 * @param ctx      TEE 上下文指针
 * @param session  TEE 会话指针
 * @param uuid     TA 的 UUID
 * @return         TEEC_SUCCESS 表示成功，其他为错误码
 */
TEEC_Result init_tee_session(TEEC_Context *ctx,
                             TEEC_Session *session,
                             TEEC_UUID *uuid)
{
    if (!ctx || !session || !uuid) {
        EMSG("Invalid parameters for session initialization");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    TEEC_Result res;
    uint32_t origin;
    char uuid_str[128] = {0};

    res = TEEC_InitializeContext(NULL, ctx);
    if (res != TEEC_SUCCESS) {
        EMSG("TEEC_InitializeContext failed: 0x%x", res);
        return res;
    }

    res = TEEC_OpenSession(ctx, session, uuid, TEEC_LOGIN_PUBLIC,
                           NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        format_uuid_string(uuid, uuid_str, sizeof(uuid_str));
        EMSG("%s TEEC_OpenSession failed: 0x%x (origin: 0x%x)",
             uuid_str, res, origin);
        TEEC_FinalizeContext(ctx);
        return res;
    }

    return TEEC_SUCCESS;
}

/**
 * 终止 TEE 会话并清理上下文
 */
void terminate_tee_session(TEEC_Context *ctx, TEEC_Session *session)
{
    if (!ctx || !session)
        return;

    TEEC_CloseSession(session);
    TEEC_FinalizeContext(ctx);
}

/**
 * 调用已初始化的 TA 命令
 *
 * @param session   已建立的 TEE 会话
 * @param cmd_id    命令 ID
 * @param operation 操作参数
 * @return          TEEC_SUCCESS 表示成功，其他为错误码
 */
TEEC_Result invoke_inited_tee_command(TEEC_Session *session,
                                      uint32_t cmd_id,
                                      TEEC_Operation *operation)
{
    if (!session) {
        EMSG("Session is NULL");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    uint32_t origin;
    TEEC_Result res = TEEC_InvokeCommand(session, cmd_id, operation, &origin);

    if (res != TEEC_SUCCESS) {
        EMSG("TEEC_InvokeCommand [0x%x] failed: 0x%x (origin: %u)",
             cmd_id, res, origin);
    }

    return res;
}

/**
 * 单次 TA 命令调用（自动创建/销毁会话）
 *
 * @param uuid      TA 的 UUID
 * @param cmd_id    命令 ID
 * @param operation 操作参数
 * @return          TEEC_SUCCESS 表示成功，其他为错误码
 */
TEEC_Result invoke_tee_command(TEEC_UUID *uuid,
                               uint32_t cmd_id,
                               TEEC_Operation *operation)
{
    if (!uuid || !operation) {
        EMSG("Invalid parameters for command invocation");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    TEEC_Context ctx = {0};
    TEEC_Session session = {0};
    TEEC_Result res;
    char uuid_str[128] = {0};

    res = init_tee_session(&ctx, &session, uuid);
    if (res != TEEC_SUCCESS) {
        return res;
    }

    res = invoke_inited_tee_command(&session, cmd_id, operation);
    if (res != TEEC_SUCCESS) {
        format_uuid_string(uuid, uuid_str, sizeof(uuid_str));
        EMSG("%s Command 0x%x failed", uuid_str, cmd_id);
    }

    terminate_tee_session(&ctx, &session);
    return res;
}
