// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "tee_client_api.h"
#include "teec_trace.h"

/* TA UUID */
#define TA_UUID \
    { 0x9b28392f, 0x39d2, 0x497d, \
        { 0x91, 0xaf, 0xb6, 0x60, 0x0e, 0x3d, 0x6a, 0x3e } }

/* 命令定义 */
typedef enum {
    CMD_VALUE_INPUT_OUTPUT = 0,   /* VALUE_INPUT + VALUE_OUTPUT */
    CMD_VALUE_INOUT = 1,          /* VALUE_INOUT */

    CMD_MEMREF_TEMP_INPUT_OUTPUT = 10,  /* TEMP_INPUT + TEMP_OUTPUT */
    CMD_MEMREF_TEMP_INOUT = 11,        /* TEMP_INOUT */

    CMD_MEMREF_WHOLE_INPUT_OUTPUT = 20,  /* WHOLE_INPUT + WHOLE_OUTPUT */
    CMD_MEMREF_WHOLE_INOUT = 21,        /* WHOLE_INOUT */

    CMD_MEMREF_PARTIAL_INPUT_OUTPUT = 30,  /* PARTIAL_INPUT + PARTIAL_OUTPUT */
    CMD_MEMREF_PARTIAL_INOUT = 31,        /* PARTIAL_INOUT */

    CMD_MIXED_PARAMS = 100,
} Command;

extern TEEC_Result init_tee_context(TEEC_Context *ctx);
extern TEEC_Result open_tee_session(TEEC_Context *ctx,
                                    TEEC_Session *session,
                                    TEEC_UUID *uuid,
                                    uint32_t *ret_orig);

static TEEC_UUID uuid = TA_UUID;
static TEEC_Context ctx = { };

/**
 * @brief 打印字节数组
 */
static void print_hex_array(const uint8_t *data, size_t len)
{
    printf("[");
    for (size_t i = 0; i < len; i++) {
        if (i > 0) printf(", ");
        printf("0x%02X", data[i]);
    }
    printf("]");
}

/* VALUE 参数演示 */
static void value_params(TEEC_Session *session)
{
    TEEC_Operation op = { };
    uint32_t ret_orig;
    TEEC_Result res;

    printf("\nVALUE 参数类型\n");

    /* VALUE_INPUT + VALUE_OUTPUT: 计算两数之和 */
    {
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(
                    TEEC_VALUE_INPUT,
                    TEEC_VALUE_OUTPUT,
                    TEEC_NONE,
                    TEEC_NONE
                    );
        op.params[0].value.a = 100;
        op.params[0].value.b = 200;

        res = TEEC_InvokeCommand(session, CMD_VALUE_INPUT_OUTPUT, &op, &ret_orig);
        if (res == TEEC_SUCCESS) {
            uint32_t result = op.params[1].value.a;
            printf("  VALUE_INPUT+OUTPUT: %u + %u = %u\n", 100, 200, result);
        } else {
            printf("  VALUE_INPUT+OUTPUT 失败: 0x%x\n", res);
        }
    }

    /* VALUE_INOUT: 数值翻倍 */
    {
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(
                    TEEC_VALUE_INOUT,
                    TEEC_NONE,
                    TEEC_NONE,
                    TEEC_NONE
                    );
        op.params[0].value.a = 42;
        op.params[0].value.b = 99;

        res = TEEC_InvokeCommand(session, CMD_VALUE_INOUT, &op, &ret_orig);
        if (res == TEEC_SUCCESS) {
            printf("  VALUE_INOUT: (%u, %u) → (%u, %u)\n",
                   42, 99, op.params[0].value.a, op.params[0].value.b);
        } else {
            printf("  VALUE_INOUT 失败: 0x%x\n", res);
        }
    }
}

/* MEMREF TEMP 参数演示 */
static void memref_temp_params(TEEC_Session *session)
{
    TEEC_Operation op = { };
    uint32_t ret_orig;
    TEEC_Result res;

    printf("\nMEMREF TEMP 参数类型\n");

    /* TEMP_INPUT + TEMP_OUTPUT */
    {
        uint8_t input_data[] = {1, 2, 3, 4, 5};
        uint8_t output_data[16] = {0};

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_NONE,
                                         TEEC_NONE);
        op.params[0].tmpref.buffer = input_data;
        op.params[0].tmpref.size = sizeof(input_data);
        op.params[1].tmpref.buffer = output_data;
        op.params[1].tmpref.size = sizeof(output_data);

        res = TEEC_InvokeCommand(session, CMD_MEMREF_TEMP_INPUT_OUTPUT, &op, &ret_orig);
        if (res == TEEC_SUCCESS) {
            printf("  TEMP_INPUT+OUTPUT: ");
            print_hex_array(input_data, sizeof(input_data));
            printf(" → ");
            print_hex_array(output_data, 8);
            printf("\n");
        } else {
            printf("  TEMP_INPUT+OUTPUT 失败: 0x%x\n", res);
        }
    }

    /* TEMP_INOUT: 按位取反 */
    {
        uint8_t inout_data[] = {0xAA, 0xBB, 0xCC, 0xDD};

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
                                         TEEC_NONE,
                                         TEEC_NONE,
                                         TEEC_NONE);
        op.params[0].tmpref.buffer = inout_data;
        op.params[0].tmpref.size = sizeof(inout_data);

        res = TEEC_InvokeCommand(session, CMD_MEMREF_TEMP_INOUT, &op, &ret_orig);
        if (res == TEEC_SUCCESS) {
            printf("  TEMP_INOUT: ");
            print_hex_array((uint8_t[]){0xAA, 0xBB, 0xCC, 0xDD}, 4);
            printf(" → ");
            print_hex_array(inout_data, sizeof(inout_data));
            printf("\n");
        } else {
            printf("  TEMP_INOUT 失败: 0x%x\n", res);
        }
    }
}

/* MEMREF WHOLE 参数演示 */
static void memref_whole_params(TEEC_Session *session)
{
    TEEC_Operation op = { };
    uint32_t ret_orig;
    TEEC_Result res;

    printf("\nMEMREF WHOLE 参数类型\n");

    /* WHOLE_INPUT + WHOLE_OUTPUT */
    {
        uint8_t input_data[] = {1, 2, 3, 4, 5, 6, 7, 8};
        uint8_t output_data[8] = {0};
        TEEC_SharedMemory input_shm = { };
        TEEC_SharedMemory output_shm = { };

        /* 分配输入共享内存 */
        input_shm.size = sizeof(input_data);
        input_shm.flags = TEEC_MEM_INPUT;
        res = TEEC_AllocateSharedMemory(&ctx, &input_shm);
        if (res != TEEC_SUCCESS) {
            printf("  分配输入共享内存失败: 0x%x\n", res);
            return;
        }
        memcpy(input_shm.buffer, input_data, sizeof(input_data));

        /* 分配输出共享内存 */
        output_shm.size = sizeof(output_data);
        output_shm.flags = TEEC_MEM_OUTPUT;
        res = TEEC_AllocateSharedMemory(&ctx, &output_shm);
        if (res != TEEC_SUCCESS) {
            printf("  分配输出共享内存失败: 0x%x\n", res);
            TEEC_ReleaseSharedMemory(&input_shm);
            return;
        }

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
                                         TEEC_MEMREF_WHOLE,
                                         TEEC_NONE,
                                         TEEC_NONE);
        op.params[0].memref.parent = &input_shm;
        op.params[0].memref.size = sizeof(input_data);
        op.params[1].memref.parent = &output_shm;
        op.params[1].memref.size = sizeof(output_data);

        res = TEEC_InvokeCommand(session, CMD_MEMREF_WHOLE_INPUT_OUTPUT, &op, &ret_orig);
        if (res == TEEC_SUCCESS) {
            memcpy(output_data, output_shm.buffer, sizeof(output_data));
            printf("  WHOLE_INPUT+OUTPUT: ");
            print_hex_array(input_data, sizeof(input_data));
            printf(" → ");
            print_hex_array(output_data, sizeof(output_data));
            printf("\n");
        } else {
            printf("  WHOLE_INPUT+OUTPUT 失败: 0x%x\n", res);
        }

        TEEC_ReleaseSharedMemory(&input_shm);
        TEEC_ReleaseSharedMemory(&output_shm);
    }

    /* WHOLE_INOUT (Allocate) */
    {
        uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8};
        uint8_t original[] = {1, 2, 3, 4, 5, 6, 7, 8};
        TEEC_SharedMemory shm = { };

        shm.size = sizeof(data);
        shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
        res = TEEC_AllocateSharedMemory(&ctx, &shm);
        if (res != TEEC_SUCCESS) {
            printf("  分配共享内存失败: 0x%x\n", res);
            return;
        }
        memcpy(shm.buffer, data, sizeof(data));

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
                                         TEEC_NONE,
                                         TEEC_NONE,
                                         TEEC_NONE);
        op.params[0].memref.parent = &shm;
        op.params[0].memref.size = sizeof(data);

        res = TEEC_InvokeCommand(session, CMD_MEMREF_WHOLE_INOUT, &op, &ret_orig);
        if (res == TEEC_SUCCESS) {
            memcpy(data, shm.buffer, sizeof(data));
            printf("  WHOLE_INOUT (Alloc): ");
            print_hex_array(original, sizeof(original));
            printf(" → ");
            print_hex_array(data, sizeof(data));
            printf("\n");
        } else {
            printf("  WHOLE_INOUT (Alloc) 失败: 0x%x\n", res);
        }

        TEEC_ReleaseSharedMemory(&shm);
    }

    /* WHOLE_INOUT (Register) */
    {
        uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8};
        uint8_t original[] = {1, 2, 3, 4, 5, 6, 7, 8};
        TEEC_SharedMemory shm = { };

        shm.buffer = data;
        shm.size = sizeof(data);
        shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
        res = TEEC_RegisterSharedMemory(&ctx, &shm);
        if (res != TEEC_SUCCESS) {
            printf("  注册共享内存失败: 0x%x\n", res);
            return;
        }

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
                                         TEEC_NONE,
                                         TEEC_NONE,
                                         TEEC_NONE);
        op.params[0].memref.parent = &shm;
        op.params[0].memref.size = sizeof(data);

        res = TEEC_InvokeCommand(session, CMD_MEMREF_WHOLE_INOUT, &op, &ret_orig);
        if (res == TEEC_SUCCESS) {
            printf("  WHOLE_INOUT (Register): ");
            print_hex_array(original, sizeof(original));
            printf(" → ");
            print_hex_array(data, sizeof(data));
            printf("\n");
        } else {
            printf("  WHOLE_INOUT (Register) 失败: 0x%x\n", res);
        }

        TEEC_ReleaseSharedMemory(&shm);
    }
}

/* MEMREF PARTIAL 参数演示 */
static void memref_partial_params(TEEC_Session *session)
{
    TEEC_Operation op = { };
    uint32_t ret_orig;
    TEEC_Result res;
    const size_t page_size = 4096;

    printf("\nMEMREF PARTIAL 参数类型\n");

    /* 分配共享内存（需要足够大以支持多个 PARTIAL 引用） */
    TEEC_SharedMemory shm = { };
    shm.size = 8 * page_size;
    shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    res = TEEC_AllocateSharedMemory(&ctx, &shm);
    if (res != TEEC_SUCCESS) {
        printf("  分配共享内存失败: 0x%x\n", res);
        return;
    }

    /* PARTIAL_INPUT + PARTIAL_OUTPUT */
    {
        uint8_t input_data[] = {0x10, 0x20, 0x30, 0x40};
        size_t input_offset = 0;
        size_t output_offset = page_size;
        size_t output_size = 8;

        /* 边界检查：确保偏移量 + 大小不超出共享内存范围 */
        if (input_offset + sizeof(input_data) > shm.size ||
            output_offset + output_size > shm.size) {
            printf("  PARTIAL 参数越界\n");
            TEEC_ReleaseSharedMemory(&shm);
            return;
        }

        /* 将输入数据复制到共享内存的指定偏移位置 */
        memcpy((uint8_t *)shm.buffer + input_offset, input_data, sizeof(input_data));

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
                                         TEEC_MEMREF_PARTIAL_OUTPUT,
                                         TEEC_NONE,
                                         TEEC_NONE);
        /* 参数 0: PARTIAL INPUT */
        op.params[0].memref.parent = &shm;
        op.params[0].memref.offset = input_offset;
        op.params[0].memref.size = sizeof(input_data);
        /* 参数 1: PARTIAL OUTPUT */
        op.params[1].memref.parent = &shm;
        op.params[1].memref.offset = output_offset;
        op.params[1].memref.size = output_size;

        res = TEEC_InvokeCommand(session, CMD_MEMREF_PARTIAL_INPUT_OUTPUT, &op, &ret_orig);
        if (res == TEEC_SUCCESS) {
            uint8_t output_data[8];
            /* 边界检查已在前面完成 */
            memcpy(output_data, (uint8_t *)shm.buffer + output_offset, output_size);
            printf("  PARTIAL_INPUT+OUTPUT: offset[%zu]=", input_offset);
            print_hex_array(input_data, sizeof(input_data));
            printf(" → offset[%zu]=", output_offset);
            print_hex_array(output_data, output_size);
            printf("\n");
        } else {
            printf("  PARTIAL_INPUT+OUTPUT 失败: 0x%x\n", res);
        }
    }

    /* PARTIAL_INOUT: XOR 加密 */
    {
        uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
        uint8_t key = 0x55;
        uint8_t original[] = {0x01, 0x02, 0x03, 0x04};
        size_t offset = 2 * page_size;

        /* 边界检查：确保偏移量 + 大小不超出共享内存范围 */
        if (offset + sizeof(data) > shm.size) {
            printf("  PARTIAL INOUT 参数越界\n");
            TEEC_ReleaseSharedMemory(&shm);
            return;
        }

        /* 将数据复制到共享内存的指定偏移位置 */
        memcpy((uint8_t *)shm.buffer + offset, data, sizeof(data));

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                         TEEC_MEMREF_PARTIAL_INOUT,
                                         TEEC_NONE,
                                         TEEC_NONE);
        op.params[0].value.a = key;
        op.params[1].memref.parent = &shm;
        op.params[1].memref.offset = offset;
        op.params[1].memref.size = sizeof(data);

        res = TEEC_InvokeCommand(session, CMD_MEMREF_PARTIAL_INOUT, &op, &ret_orig);
        if (res == TEEC_SUCCESS) {
            uint8_t result[4];
            memcpy(result, (uint8_t *)shm.buffer + offset, sizeof(data));
            printf("  PARTIAL_INOUT: offset[%zu]=", offset);
            print_hex_array(original, sizeof(original));
            printf(" ^ 0x%02X → ", key);
            print_hex_array(result, sizeof(result));
            printf("\n");
        } else {
            printf("  PARTIAL_INOUT 失败: 0x%x\n", res);
        }
    }

    TEEC_ReleaseSharedMemory(&shm);
}

/* 混合参数演示 */
static void mixed_params(TEEC_Session *session)
{
    TEEC_Operation op = { };
    uint32_t ret_orig;
    TEEC_Result res;

    printf("\n混合参数演示\n");

    {
        uint8_t input_data[] = {10, 20, 30, 40, 50};
        uint8_t output_hash[4] = {0};

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,
                                         TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_VALUE_OUTPUT);
        op.params[0].value.a = 7;  /* counter */
        op.params[1].tmpref.buffer = input_data;
        op.params[1].tmpref.size = sizeof(input_data);
        op.params[2].tmpref.buffer = output_hash;
        op.params[2].tmpref.size = sizeof(output_hash);

        res = TEEC_InvokeCommand(session, CMD_MIXED_PARAMS, &op, &ret_orig);
        if (res == TEEC_SUCCESS) {
            uint32_t counter = op.params[0].value.a;
            uint32_t status = op.params[3].value.a;
            uint32_t processed = op.params[3].value.b;
            
            printf("  输入: counter=7, data=");
            print_hex_array(input_data, sizeof(input_data));
            printf("\n");
            printf("  输出: counter=%u, hash=0x%02X%02X%02X%02X, status=0x%08X, bytes=%u\n",
                   counter, output_hash[3], output_hash[2], output_hash[1], output_hash[0],
                    status, processed);
        } else {
            printf("  混合参数演示失败: 0x%x\n", res);
        }
    }
}

int main(void)
{
    TEEC_Session session = { };
    uint32_t ret_orig;
    TEEC_Result res;

    /* 初始化 TEE Context */
    res = init_tee_context(&ctx);
    if (res != TEEC_SUCCESS) {
        EMSG("init_tee_context failed with code 0x%x", res);
        return -1;
    }

    /* 打开 Session */
    res = open_tee_session(&ctx, &session, &uuid, &ret_orig);
    if (res != TEEC_SUCCESS) {
        EMSG("open_tee_session failed with code 0x%x origin 0x%x", res, ret_orig);
        TEEC_FinalizeContext(&ctx);
        return -1;
    }

    /* 执行各项演示 */
    value_params(&session);
    memref_temp_params(&session);
    memref_whole_params(&session);
    memref_partial_params(&session);
    mixed_params(&session);

    /* 清理资源 */
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&ctx);

    return 0;
}
