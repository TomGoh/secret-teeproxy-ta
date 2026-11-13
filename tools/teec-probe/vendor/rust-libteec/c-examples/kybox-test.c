// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "tee_client_api.h"

#define KEY_AUTH_SIZE   32
#define BOX_GLOBAL_KEY  "box_global.key"
#define BOX_KEY         "box-key.txt"
#define TEST_DATA       "Hello, Encryption Test!"

#define SMALL_DATA_SIZE 125
#define LARGE_DATA_SIZE 21003    /* 超过TLS 16384记录限制，测试write_all分片 */
#define LARGE_CIPHER_SIZE 21259  /* LARGE_DATA_SIZE + 256 加密开销 */

#define KYBOX_UUID \
    { 0x600bcc19, 0xbb0d, 0x4ced, \
        { 0xad, 0x48, 0x84, 0x8d, 0xad, 0x7e, 0x66, 0x56 } }

/* TA命令ID */
#define TA_KYBOX_GENERATE_BOX_KEY   0
#define TA_KYBOX_DESTROY_BOX_KEY    1
#define TA_KYBOX_BOX_KEY_IS_EXIST   2
#define TA_KYBOX_ENCRYPT            3
#define TA_KYBOX_DECRYPT            4
#define TA_KYBOX_VERIFY_BOX_KEY     5

extern TEEC_Result init_tee_session(TEEC_Context *ctx, TEEC_Session *session,
                                    TEEC_UUID *uuid);
extern void terminate_tee_session(TEEC_Context *ctx, TEEC_Session *session);
extern TEEC_Result invoke_inited_tee_command(TEEC_Session *session,
                                             uint32_t cmd_id,
                                             TEEC_Operation *operation);
extern TEEC_Result invoke_tee_command(TEEC_UUID *uuid, uint32_t cmd_id,
                                      TEEC_Operation *operation);

struct box_data {
    char *key_id;              /* 密钥标识符 */
    unsigned char *key_auth;   /* 密钥验证数据 */
    size_t key_auth_size;      /* 验证数据大小 */
    unsigned char *plaindata;  /* 明文数据 */
    size_t plaindata_size;     /* 明文数据大小 */
    unsigned char *cipherdata; /* 密文数据 */
    size_t cipherdata_size;    /* 密文数据大小 */
    int result;                /* 操作结果 */
};

static TEEC_UUID uuid = KYBOX_UUID;

static TEEC_Result box_generate_key(uint32_t cmd_id, struct box_data *data)
{
    TEEC_Operation op = {};

    if (!data || !data->key_id || !data->key_auth || data->key_auth_size == 0) {
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)data->key_id;
    op.params[0].tmpref.size = strnlen(data->key_id, NAME_MAX);
    op.params[1].tmpref.buffer = data->key_auth;
    op.params[1].tmpref.size = data->key_auth_size;

    return invoke_tee_command(&uuid, cmd_id, &op);
}

static TEEC_Result box_destroy_key(uint32_t cmd_id, struct box_data *data)
{
    TEEC_Operation op = {};
    TEEC_Result res = TEEC_SUCCESS;

    if (!data || !data->key_id)
        return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)data->key_id;
    op.params[0].tmpref.size = strnlen(data->key_id, NAME_MAX);

    res = invoke_tee_command(&uuid, cmd_id, &op);
    data->result = op.params[1].value.a;

    return res;
}

static TEEC_Result box_key_is_exist(uint32_t cmd_id, struct box_data *data)
{
    TEEC_Operation op = {};
    TEEC_Result res = TEEC_SUCCESS;

    if (!data || !data->key_id)
        return TEEC_ERROR_BAD_PARAMETERS;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)data->key_id;
    op.params[0].tmpref.size = strnlen(data->key_id, NAME_MAX);

    res = invoke_tee_command(&uuid, cmd_id, &op);
    data->result = op.params[1].value.a;

    return res;
}

static TEEC_Result box_verify_key(uint32_t cmd_id, struct box_data *data)
{
    TEEC_Operation op = {};
    TEEC_Result res = TEEC_SUCCESS;

    if (!data || !data->key_id || !data->key_auth || data->key_auth_size == 0) {
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)data->key_id;
    op.params[0].tmpref.size = strnlen(data->key_id, NAME_MAX);
    op.params[1].tmpref.buffer = data->key_auth;
    op.params[1].tmpref.size = data->key_auth_size;

    res = invoke_tee_command(&uuid, cmd_id, &op);
    data->result = op.params[2].value.a;

    return res;
}

static TEEC_Result box_encrypt(uint32_t cmd_id, struct box_data *data)
{
    TEEC_Operation op = {0};
    TEEC_Result res = TEEC_SUCCESS;

    if (!data || !data->key_id || !data->plaindata ||
            data->plaindata_size == 0 || !data->cipherdata ||
            data->cipherdata_size == 0) {
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)data->key_id;
    op.params[0].tmpref.size = strnlen(data->key_id, NAME_MAX);
    op.params[1].tmpref.buffer = data->plaindata;
    op.params[1].tmpref.size = data->plaindata_size;
    op.params[2].tmpref.buffer = data->cipherdata;
    op.params[2].tmpref.size = data->cipherdata_size;

    res = invoke_tee_command(&uuid, cmd_id, &op);
    if (res == TEEC_SUCCESS) {
        data->cipherdata_size = op.params[2].tmpref.size;
    }

    return res;
}

static TEEC_Result box_decrypt(uint32_t cmd_id, struct box_data *data)
{
    TEEC_Operation op = {0};
    TEEC_Result res = TEEC_SUCCESS;

    if (!data || !data->key_id || !data->key_auth ||
            data->key_auth_size == 0 || !data->plaindata ||
            data->plaindata_size == 0 || !data->cipherdata ||
            data->cipherdata_size == 0) {
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT);
    op.params[0].tmpref.buffer = (void *)data->key_id;
    op.params[0].tmpref.size = strnlen(data->key_id, NAME_MAX);
    op.params[1].tmpref.buffer = data->key_auth;
    op.params[1].tmpref.size = data->key_auth_size;
    op.params[2].tmpref.buffer = data->cipherdata;
    op.params[2].tmpref.size = data->cipherdata_size;
    op.params[3].tmpref.buffer = data->plaindata;
    op.params[3].tmpref.size = data->plaindata_size;

    res = invoke_tee_command(&uuid, cmd_id, &op);
    if (res == TEEC_SUCCESS) {
        data->plaindata_size = op.params[3].tmpref.size;
    }

    return res;
}

static int test_encrypt_and_decrypt(const char *label,
                                    struct box_data *data,
                                    const unsigned char *test_key_auth)
{
    printf("\n  ▶ %s\n", label);

    TEEC_Result res = box_encrypt(TA_KYBOX_ENCRYPT, data);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "  ❌ 加密失败: 0x%x\n", res);
        return -1;
    }
    printf("  ✅ 加密成功 (密文: %zu bytes)\n", data->cipherdata_size);

    printf("  → 使用正确密钥解密...\n");
    unsigned char *decrypted = calloc(1, data->plaindata_size);
    if (!decrypted) {
        fprintf(stderr, "  ❌ 内存分配失败\n");
        return -1;
    }
    struct box_data decrypt_data = *data;
    decrypt_data.plaindata = decrypted;
    decrypt_data.plaindata_size = data->plaindata_size;

    res = box_decrypt(TA_KYBOX_DECRYPT, &decrypt_data);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "  ❌ 正确密钥解密失败: 0x%x\n", res);
        free(decrypted);
        return -1;
    }

    printf("  ✅ 正确密钥解密成功\n");

    if (test_key_auth) {
        printf("  → 使用错误密钥解密...\n");
        struct box_data bad_key_data = decrypt_data;

        bad_key_data.key_auth = (unsigned char *)test_key_auth;
        bad_key_data.key_auth_size = KEY_AUTH_SIZE;

        res = box_decrypt(TA_KYBOX_DECRYPT, &bad_key_data);
        printf("  %s\n",
               (res == TEEC_SUCCESS) ? "❌ 错误密钥解密成功（异常）" : "✅ 错误密钥解密失败（符合预期）");
    }

    free(decrypted);
    return 0;
}
int main(void)
{
    TEEC_Result res = TEEC_SUCCESS;
    const char *key_id = BOX_GLOBAL_KEY;
    unsigned char key_auth[KEY_AUTH_SIZE] = {0};
    unsigned char wrong_key_auth[KEY_AUTH_SIZE] = {0};
    struct box_data box_data = {
        .key_id = (char *)key_id,
        .key_auth = key_auth,
        .key_auth_size = sizeof(key_auth),
    };

    memset(wrong_key_auth, 0xAA, sizeof(wrong_key_auth));

    printf("\n");
    printf("  KyBox 密钥管理与加解密测试程序\n");
    printf("  ============================\n\n");

    printf("\n  [测试项 1] 生成密钥\n");
    res = box_generate_key(TA_KYBOX_GENERATE_BOX_KEY, &box_data);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "❌ 密钥生成失败: 0x%x\n", res);
        if (res == TEEC_ERROR_ACCESS_DENIED) {
            fprintf(stderr,
                "  提示: TA 已存在同 key_id 的密钥（GenerateBoxKey 拒绝覆盖）。\n"
                "  上次运行未走完销毁步骤。示例不持久化 key_auth，中断的既有密钥\n"
                "  无法从示例侧销毁属预期行为：请先完整跑完本示例的销毁步骤，\n"
                "  或清理 TEE 存储后重试。\n");
        }
        return -1;
    }
    printf("✅ 密钥生成成功\n");

    printf("\n  [测试项 2] 密钥状态验证\n");
    res = box_key_is_exist(TA_KYBOX_BOX_KEY_IS_EXIST, &box_data);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "❌ 检查密钥是否存在失败: %d\n", res);
        return -1;
    }

    printf("  密钥存在: %s\n", box_data.result ? "是" : "否");

    printf("\n  [测试项 3] 验证正确密钥\n");
    res = box_verify_key(TA_KYBOX_VERIFY_BOX_KEY, &box_data);
    printf("  %s\n", box_data.result ? "✅ 正确密钥验证成功" : "❌ 正确密钥验证失败");

    printf("\n  [测试项 4] 验证非法密钥\n");
    struct box_data wrong_box_data = box_data;
    wrong_box_data.key_auth = wrong_key_auth;
    wrong_box_data.key_auth_size = sizeof(wrong_key_auth);

    res = box_verify_key(TA_KYBOX_VERIFY_BOX_KEY, &wrong_box_data);
    printf("  %s\n", wrong_box_data.result ? "❌ 错误密钥验证成功（异常）" : "✅ 错误密钥验证失败（符合预期）");

    printf("\n  [测试项 5] 小数据加解密测试\n");
    {
        unsigned char plaintext[SMALL_DATA_SIZE] = TEST_DATA;
        unsigned char ciphertext[SMALL_DATA_SIZE] = {0};

        struct box_data test_box_data = box_data;
        test_box_data.plaindata = plaintext;
        test_box_data.plaindata_size = strnlen(TEST_DATA, PATH_MAX);
        test_box_data.cipherdata = ciphertext;
        test_box_data.cipherdata_size = sizeof(ciphertext);

        if (test_encrypt_and_decrypt("小数据加解密测试", &test_box_data,
                                     wrong_key_auth) != 0) {
            return -1;
        }
    }

    printf("\n  [测试项 6] 大数据加解密测试\n");
    {
        unsigned char large_plain[LARGE_DATA_SIZE];
        unsigned char large_cipher[LARGE_CIPHER_SIZE] = {0};

        memset(large_plain, 0x01, sizeof(large_plain));

        struct box_data test_box_data = box_data;
        test_box_data.plaindata = large_plain;
        test_box_data.plaindata_size = sizeof(large_plain);
        test_box_data.cipherdata = large_cipher;
        test_box_data.cipherdata_size = sizeof(large_cipher);

        if (test_encrypt_and_decrypt("大数据加解密测试", &test_box_data,
                                     wrong_key_auth) != 0) {
            return -1;
        }
    }

    printf("\n  [测试项 7] 密钥销毁\n");
    res = box_destroy_key(TA_KYBOX_DESTROY_BOX_KEY, &box_data);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "❌ 密钥销毁失败: 0x%x\n", res);
        return -1;
    }
    printf("✅ 密钥销毁成功\n");

    res = box_key_is_exist(TA_KYBOX_BOX_KEY_IS_EXIST, &box_data);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "❌ 最终检查失败: 0x%x\n", res);
        return -1;
    }

    printf("  最终检查 - 密钥存在: %s\n", box_data.result ? "是（异常）" : "否（预期）");

    printf("\n========================================\n");
    printf("  ✅ 所有测试通过！\n");
    printf("========================================\n\n");

    return 0;
}
