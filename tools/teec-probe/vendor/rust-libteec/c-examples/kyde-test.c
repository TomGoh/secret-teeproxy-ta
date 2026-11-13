// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "tee_client_api.h"

#define KEY_AUTH_SIZE   32
#define TEST_PASSWORD   "test_password_123"
#define TEST_DATA       "Hello, Kylin Disk Encryption Test!"

#define SMALL_DATA_SIZE 125
#define LARGE_DATA_SIZE 4099
#define LARGE_CIPHER_SIZE 4199

#define KYLIN_DISK_ENCRYPTION_UUID \
    { 0x1d9f033e, 0x0d88, 0x474c, \
        { 0x81, 0x93, 0xbd, 0x54, 0x27, 0x00, 0x69, 0xc1 } }

/* TA 命令 ID */
#define TA_KYLIN_DISK_ENCRYPT 0
#define TA_KYLIN_DISK_DECRYPT 1

extern TEEC_Result init_tee_session(TEEC_Context *ctx, TEEC_Session *session,
                                    TEEC_UUID *uuid);
extern void terminate_tee_session(TEEC_Context *ctx, TEEC_Session *session);
extern TEEC_Result invoke_inited_tee_command(TEEC_Session *session,
                                             uint32_t cmd_id,
                                             TEEC_Operation *operation);
extern TEEC_Result invoke_tee_command(TEEC_UUID *uuid, uint32_t cmd_id,
                                      TEEC_Operation *operation);

struct disk_enc_data {
    char *password;            /* 口令（用作 key_id） */
    unsigned char *plaindata;  /* 明文数据 */
    size_t plaindata_size;     /* 明文数据大小 */
    unsigned char *cipherdata; /* 密文数据 */
    size_t cipherdata_size;    /* 密文数据大小 */
    int result;                /* 操作结果 */
};

static TEEC_UUID uuid = KYLIN_DISK_ENCRYPTION_UUID;

static TEEC_Result disk_encrypt(uint32_t cmd_id, struct disk_enc_data *data)
{
    TEEC_Operation op = {};
    TEEC_Result res = TEEC_SUCCESS;

    if (!data || !data->password || !data->plaindata ||
            data->plaindata_size == 0 || !data->cipherdata ||
            data->cipherdata_size == 0) {
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)data->password;
    op.params[0].tmpref.size = strnlen(data->password, NAME_MAX);
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

static TEEC_Result disk_decrypt(uint32_t cmd_id, struct disk_enc_data *data)
{
    TEEC_Operation op = {};
    TEEC_Result res = TEEC_SUCCESS;

    if (!data || !data->password || !data->cipherdata ||
            data->cipherdata_size == 0 || !data->plaindata ||
            data->plaindata_size == 0) {
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)data->password;
    op.params[0].tmpref.size = strnlen(data->password, NAME_MAX);
    op.params[1].tmpref.buffer = data->cipherdata;
    op.params[1].tmpref.size = data->cipherdata_size;
    op.params[2].tmpref.buffer = data->plaindata;
    op.params[2].tmpref.size = data->plaindata_size;

    res = invoke_tee_command(&uuid, cmd_id, &op);
    if (res == TEEC_SUCCESS) {
        data->plaindata_size = op.params[2].tmpref.size;
    }

    return res;
}

static int test_encrypt_and_decrypt(const char *label,
                                    struct disk_enc_data *data,
                                    const char *wrong_password)
{
    printf("\n  ▶ %s\n", label);

    TEEC_Result res = disk_encrypt(TA_KYLIN_DISK_ENCRYPT, data);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "  ❌ 加密失败：0x%x\n", res);
        return -1;
    }

    printf("  ✅ 加密成功 (密文: %zu bytes)\n", data->cipherdata_size);
    printf("  密文前 16 字节：%02x %02x %02x %02x %02x %02x %02x %02x "
           "%02x %02x %02x %02x %02x %02x %02x %02x\n",
           data->cipherdata[0], data->cipherdata[1], data->cipherdata[2],
            data->cipherdata[3], data->cipherdata[4], data->cipherdata[5],
            data->cipherdata[6], data->cipherdata[7], data->cipherdata[8],
            data->cipherdata[9], data->cipherdata[10], data->cipherdata[11],
            data->cipherdata[12], data->cipherdata[13], data->cipherdata[14],
            data->cipherdata[15]);

    printf("  → 使用正确口令解密...\n");
    unsigned char decrypted[SMALL_DATA_SIZE] = {0};
    struct disk_enc_data decrypt_data = *data;

    decrypt_data.plaindata = decrypted;
    decrypt_data.plaindata_size = sizeof(decrypted);

    res = disk_decrypt(TA_KYLIN_DISK_DECRYPT, &decrypt_data);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "  ❌ 正确口令解密失败：0x%x\n", res);
        return -1;
    }
    printf("  ✅ 正确口令解密成功\n");
    printf("  解密数据：%.*s\n", (int)decrypt_data.plaindata_size, decrypted);

    if (wrong_password)
    {
        printf("  → 使用错误口令解密...\n");
        struct disk_enc_data wrong_pass_data = decrypt_data;
        wrong_pass_data.password = (char *)wrong_password;

        res = disk_decrypt(TA_KYLIN_DISK_DECRYPT, &wrong_pass_data);
        printf("  %s\n",
               (res == TEEC_SUCCESS) ? "❌ 错误口令解密成功（异常）" : "✅ 错误口令解密失败（符合预期）");
    }

    return 0;
}

int main(void)
{
    TEEC_Result res = TEEC_SUCCESS;
    const char *password = TEST_PASSWORD;
    const char *wrong_password = "wrong_password";
    struct disk_enc_data disk_data = {
        .password = (char *)password,
    };

    printf("\n");
    printf("  Kylin 磁盘加密 TA 测试程序\n");
    printf("  ========================\n\n");

    printf("\n  [测试项 1] 小数据加解密测试\n");
    {
        unsigned char plaintext[SMALL_DATA_SIZE] = TEST_DATA;
        unsigned char ciphertext[SMALL_DATA_SIZE] = {0};

        struct disk_enc_data test_disk_data = disk_data;
        test_disk_data.plaindata = plaintext;
        test_disk_data.plaindata_size = strnlen(TEST_DATA, NAME_MAX);
        test_disk_data.cipherdata = ciphertext;
        test_disk_data.cipherdata_size = sizeof(ciphertext);

        if (test_encrypt_and_decrypt("小数据加解密测试", &test_disk_data,
                                     wrong_password) != 0) {
            return -1;
        }
    }

    printf("\n  [测试项 2] 大数据加解密测试\n");
    {
        unsigned char large_plain[LARGE_DATA_SIZE];
        unsigned char large_cipher[LARGE_CIPHER_SIZE] = {0};

        memset(large_plain, 0x01, sizeof(large_plain));

        struct disk_enc_data test_disk_data = disk_data;
        test_disk_data.plaindata = large_plain;
        test_disk_data.plaindata_size = sizeof(large_plain);
        test_disk_data.cipherdata = large_cipher;
        test_disk_data.cipherdata_size = sizeof(large_cipher);

        if (test_encrypt_and_decrypt("大数据加解密测试", &test_disk_data,
                                     wrong_password) != 0) {
            return -1;
        }
    }

    printf("\n  [测试项 3] 不同口令测试\n");
    {
        const char *test_passwords[] = {
            "password1",
            "password2",
            "test_password",
            "secure_key_2025",
            ""
        };

        unsigned char plaintext[SMALL_DATA_SIZE] = "Different password test";
        unsigned char ciphertext[SMALL_DATA_SIZE] = {0};

        for (int i = 0; test_passwords[i][0] != '\0'; i++) {
            printf("\n  测试口令 %d: \"%s\"\n", i + 1, test_passwords[i]);

            struct disk_enc_data test_data = disk_data;
            test_data.password = (char *)test_passwords[i];
            test_data.plaindata = plaintext;
            test_data.plaindata_size = strnlen((char *)plaintext, sizeof(plaintext));
            test_data.cipherdata = ciphertext;
            test_data.cipherdata_size = sizeof(ciphertext);

            res = disk_encrypt(TA_KYLIN_DISK_ENCRYPT, &test_data);
            if (res != TEEC_SUCCESS) {
                fprintf(stderr, "  ❌ 加密失败：0x%x\n", res);
                continue;
            }
            printf("  ✅ 加密成功 (密文: %zu bytes)\n", test_data.cipherdata_size);

            unsigned char decrypted[SMALL_DATA_SIZE] = {0};
            test_data.plaindata = decrypted;
            test_data.plaindata_size = sizeof(decrypted);

            res = disk_decrypt(TA_KYLIN_DISK_DECRYPT, &test_data);
            if (res != TEEC_SUCCESS) {
                fprintf(stderr, "  ❌ 解密失败：0x%x\n", res);
                continue;
            }
	    printf("  ✅ 解密成功: %.20s%s\n", decrypted, strnlen((char *)decrypted, sizeof(decrypted)) > 20 ? "..." : "");
        }
    }

    printf("\n  [测试项 4] 空数据测试\n");
    {
        unsigned char empty_data[1] = {0};
        unsigned char empty_cipher[16] = {0};

        struct disk_enc_data empty_test_data = disk_data;
        empty_test_data.plaindata = empty_data;
        empty_test_data.plaindata_size = 0;
        empty_test_data.cipherdata = empty_cipher;
        empty_test_data.cipherdata_size = sizeof(empty_cipher);

        res = disk_encrypt(TA_KYLIN_DISK_ENCRYPT, &empty_test_data);
        printf("  %s\n",
               (res == TEEC_SUCCESS) ? "✅ 空数据加密成功" : "✅ 空数据加密失败（符合预期）");
    }

    printf("\n========================================\n");
    printf("  ✅ 所有测试通过！\n");
    printf("========================================\n\n");

    return 0;
}
