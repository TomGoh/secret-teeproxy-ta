use rust_utee::{
    api::{
        tee_api_objects::{
            TEE_AllocateTransientObject, TEE_CopyObjectAttributes1, TEE_FreeTransientObject,
            TEE_GenerateKey, TEE_GetObjectBufferAttribute, TEE_GetObjectBufferAttribute1,
            TEE_InitRefAttribute, TEE_InitValueAttribute, TEE_PopulateTransientObject,
        },
        tee_api_operations::{
            TEE_AEDecryptFinal, TEE_AEEncryptFinal, TEE_AEInit, TEE_AEUpdate, TEE_AEUpdateAAD,
            TEE_AllocateOperation, TEE_AsymmetricDecrypt, TEE_AsymmetricEncrypt,
            TEE_AsymmetricSignDigest, TEE_AsymmetricVerifyDigest, TEE_CipherDoFinal,
            TEE_CipherInit, TEE_CipherUpdate, TEE_CopyOperation, TEE_DeriveKey, TEE_DigestDoFinal,
            TEE_DigestUpdate, TEE_FreeOperation, TEE_GenerateRandom, TEE_MACComputeFinal,
            TEE_MACInit, TEE_MACUpdate, TEE_SetOperationKey, TEE_SetOperationKey2,
            sm2_compute_sign_digest,
        },
    },
    tee_api_defines::{
        TEE_ALG_AES_CCM, TEE_ALG_AES_CMAC, TEE_ALG_ED25519, TEE_ALG_HKDF_SHA256_DERIVE_KEY,
        TEE_ALG_HMAC_SM3, TEE_ALG_MD5, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256,
        TEE_ALG_RSAES_PKCS1_V1_5, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256, TEE_ALG_SM2_DSA_SM3,
        TEE_ALG_SM2_KEP, TEE_ALG_SM2_PKE, TEE_ALG_SM3, TEE_ALG_SM4_CBC_NOPAD, TEE_ALG_SM4_CTR,
        TEE_ALG_SM4_ECB_NOPAD, TEE_ALG_SM4_GCM, TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_X,
        TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_Y, TEE_ATTR_ECC_PRIVATE_VALUE,
        TEE_ATTR_ECC_PUBLIC_VALUE_X, TEE_ATTR_ECC_PUBLIC_VALUE_Y, TEE_ATTR_ED25519_PUBLIC_VALUE,
        TEE_ATTR_HKDF_IKM, TEE_ATTR_HKDF_INFO, TEE_ATTR_HKDF_OKM_LENGTH, TEE_ATTR_HKDF_SALT,
        TEE_ATTR_RSA_OAEP_LABEL, TEE_ATTR_SECRET_VALUE, TEE_ATTR_SM2_ID_INITIATOR,
        TEE_ATTR_SM2_ID_RESPONDER, TEE_ATTR_SM2_KEP_CONFIRMATION_IN,
        TEE_ATTR_SM2_KEP_CONFIRMATION_OUT, TEE_ATTR_SM2_KEP_USER, TEE_ERROR_BAD_PARAMETERS,
        TEE_ERROR_SIGNATURE_INVALID, TEE_MODE_DECRYPT, TEE_MODE_DERIVE, TEE_MODE_DIGEST,
        TEE_MODE_ENCRYPT, TEE_MODE_MAC, TEE_MODE_SIGN, TEE_MODE_VERIFY, TEE_SUCCESS, TEE_TYPE_AES,
        TEE_TYPE_ED25519_PUBLIC_KEY, TEE_TYPE_GENERIC_SECRET, TEE_TYPE_HKDF_IKM, TEE_TYPE_HMAC_SM3,
        TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY, TEE_TYPE_SM2_DSA_KEYPAIR,
        TEE_TYPE_SM2_DSA_PUBLIC_KEY, TEE_TYPE_SM2_KEP_KEYPAIR, TEE_TYPE_SM2_PKE_KEYPAIR,
        TEE_TYPE_SM2_PKE_PUBLIC_KEY, TEE_TYPE_SM4,
    },
    tee_api_types::{TEE_Attribute, TEE_ObjectHandle, TEE_OperationHandle, TEE_Result},
};

// #[unsafe(no_mangle)]
fn main() {
    let test_func = [
        cryp_hash_sm3_test,
        copy_operation_sm3_digest_test,
        cryp_hash_md5_test,
        cryp_hmac_sm3_test,
        copy_operation_hmac_sm3_test,
        cryp_aes_cmac_test,
        cryp_aes_ccm_test,
        cryp_sm4_ecb_test,
        cryp_sm4_cbc_test,
        copy_operation_sm4_cbc_encrypt_test,
        cryp_sm4_gcm_test,
        cryp_sm2_enc_dec_test,
        cryp_sm2_pke_decrypt_vector_test,
        cryp_sm2_sign_verify_test,
        cryp_sm2_verify_with_fixed_pubkey_test,
        cryp_ed25519_verify_sig_structure_vector_test,
        cryp_rsa_pkcs1_v15_encrypt_decrypt_test,
        cryp_rsa_oaep_sha256_encrypt_decrypt_with_label_test,
        cryp_rsa_pss_sha256_sign_verify_test,
        cryp_generate_random_number,
        cryp_derive_key_hkdf_sha256_test,
        cryp_derive_key_sm2_kep_test,
        cryp_derive_key_sm2_kep_with_confirmation_test,
        cryp_key_free_test,
    ];

    for func in &test_func {
        let res = func();
        if res == TEE_SUCCESS {
            println!("<<< test success");
        } else {
            eprintln!("<<< test failed");
        }
    }

    let plain_data: [u8; 48] = [
        0xce, 0x3b, 0x91, 0x3b, 0x42, 0xf3, 0x9d, 0x3d, 0x61, 0xfb, 0x75, 0x2f, 0xff, 0x81, 0x51,
        0xc6, 0x13, 0xf1, 0x0a, 0x8b, 0xb9, 0x5c, 0x8e, 0xe1, 0x59, 0x56, 0x6c, 0xc9, 0xcb, 0x91,
        0x57, 0xf8, 0xf3, 0x4f, 0xa5, 0xa9, 0x0c, 0x02, 0x39, 0xcc, 0x76, 0x1b, 0x4f, 0xe2, 0xb1,
        0xbc, 0xd1, 0x96,
    ];

    let res = encrypt_box_data(b"abcdefghabcdefgh", b"1234qwerasdfzxcv", &plain_data);

    if res == TEE_SUCCESS {
        println!("<<< test success");
    } else {
        eprintln!("<<< test failed");
    }
}

fn cryp_hash_sm3_test() -> TEE_Result {
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_SM3, TEE_MODE_DIGEST, 0);
    assert_eq!(res, 0);

    let data = b"abc";

    TEE_DigestUpdate(operation_ptr, data.as_ptr() as _, data.len());

    let hash: [u8; 32] = [0; 32];
    let mut hash_len = hash.len();
    let res = TEE_DigestDoFinal(
        operation_ptr,
        core::ptr::null(),
        0,
        hash.as_ptr() as _,
        &mut hash_len,
    );
    assert_eq!(res, 0);

    assert_eq!(hash_len, 32);
    assert_eq!(
        hash,
        [
            0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10,
            0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b,
            0x8f, 0x4b, 0xa8, 0xe0
        ]
    );

    TEE_FreeOperation(operation_ptr);

    TEE_SUCCESS
}

fn copy_operation_sm3_digest_test() -> TEE_Result {
    let mut src_op: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut src_op, TEE_ALG_SM3, TEE_MODE_DIGEST, 0);
    assert_eq!(res, 0);

    let mut dst_op: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut dst_op, TEE_ALG_SM3, TEE_MODE_DIGEST, 0);
    assert_eq!(res, 0);

    TEE_DigestUpdate(src_op, b"abc".as_ptr() as _, b"abc".len());

    TEE_CopyOperation(dst_op, src_op);

    let src_hash: [u8; 32] = [0; 32];
    let mut src_len = src_hash.len();
    let res = TEE_DigestDoFinal(
        src_op,
        core::ptr::null(),
        0,
        src_hash.as_ptr() as _,
        &mut src_len,
    );
    assert_eq!(res, 0);
    assert_eq!(src_len, 32);

    let dst_hash: [u8; 32] = [0; 32];
    let mut dst_len = dst_hash.len();
    let res = TEE_DigestDoFinal(
        dst_op,
        core::ptr::null(),
        0,
        dst_hash.as_ptr() as _,
        &mut dst_len,
    );
    assert_eq!(res, 0);
    assert_eq!(dst_len, 32);

    assert_eq!(dst_hash, src_hash);
    assert_eq!(
        src_hash,
        [
            0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10,
            0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b,
            0x8f, 0x4b, 0xa8, 0xe0
        ]
    );

    TEE_FreeOperation(src_op);
    TEE_FreeOperation(dst_op);

    TEE_SUCCESS
}

/// 与内核 `test_cryp_hash_md5` 相同：分块 `DigestUpdate` → `CopyOperation` → `DigestDoFinal`。
fn cryp_hash_md5_test() -> TEE_Result {
    const HASH_DATA_MD5_IN1: [u8; 11] = [
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
    ];
    const HASH_DATA_MD5_OUT1: [u8; 16] = [
        0x61, 0x12, 0x71, 0x83, 0x70, 0x8d, 0x3a, 0xc7, 0xf1, 0x9b, 0x66, 0x06, 0xfc, 0xae, 0x7d,
        0xf6,
    ];
    const FIRST_CHUNK_LEN: usize = 6;

    let mut op1: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut op1, TEE_ALG_MD5, TEE_MODE_DIGEST, 0);
    assert_eq!(res, 0);

    let mut op2: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut op2, TEE_ALG_MD5, TEE_MODE_DIGEST, 0);
    assert_eq!(res, 0);

    TEE_DigestUpdate(op1, HASH_DATA_MD5_IN1.as_ptr() as _, FIRST_CHUNK_LEN);

    TEE_CopyOperation(op2, op1);

    let hash: [u8; 16] = [0; 16];
    let mut hash_len = hash.len();
    let res = TEE_DigestDoFinal(
        op2,
        HASH_DATA_MD5_IN1[FIRST_CHUNK_LEN..].as_ptr() as _,
        HASH_DATA_MD5_IN1.len() - FIRST_CHUNK_LEN,
        hash.as_ptr() as _,
        &mut hash_len,
    );
    assert_eq!(res, 0);
    assert_eq!(hash_len, 16);
    assert_eq!(hash, HASH_DATA_MD5_OUT1);

    TEE_FreeOperation(op1);
    TEE_FreeOperation(op2);

    TEE_SUCCESS
}

fn copy_operation_hmac_sm3_test() -> TEE_Result {
    let key = b"abcdefghabcdefgh";

    let mut key_obj: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SM3, 128, &mut key_obj);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key_obj.is_null());

    let mut attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    TEE_InitRefAttribute(
        &mut attr,
        TEE_ATTR_SECRET_VALUE,
        key.as_ptr() as *const _,
        key.len(),
    );
    let res = TEE_PopulateTransientObject(key_obj, &mut attr, 1);
    assert_eq!(res, TEE_SUCCESS);

    let mut src_op: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut src_op, TEE_ALG_HMAC_SM3, TEE_MODE_MAC, 128);
    assert_eq!(res, 0);
    TEE_SetOperationKey(src_op, key_obj);

    let mut dst_op: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut dst_op, TEE_ALG_HMAC_SM3, TEE_MODE_MAC, 128);
    assert_eq!(res, 0);

    TEE_MACInit(src_op, core::ptr::null(), 0);
    TEE_MACUpdate(src_op, b"abc".as_ptr() as _, b"abc".len());

    TEE_CopyOperation(dst_op, src_op);

    let src_mac: [u8; 32] = [0; 32];
    let mut src_mac_len = src_mac.len();
    let res = TEE_MACComputeFinal(
        src_op,
        core::ptr::null(),
        0,
        src_mac.as_ptr() as _,
        &mut src_mac_len,
    );
    assert_eq!(res, 0);

    let dst_mac: [u8; 32] = [0; 32];
    let mut dst_mac_len = dst_mac.len();
    let res = TEE_MACComputeFinal(
        dst_op,
        core::ptr::null(),
        0,
        dst_mac.as_ptr() as _,
        &mut dst_mac_len,
    );
    assert_eq!(res, 0);

    assert_eq!(dst_mac_len, src_mac_len);
    assert_eq!(dst_mac, src_mac);

    TEE_FreeOperation(src_op);
    TEE_FreeOperation(dst_op);
    TEE_FreeTransientObject(key_obj);

    TEE_SUCCESS
}

fn cryp_aes_cmac_test() -> TEE_Result {
    let key = [
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let data = [
        0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    let mut key_obj: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &mut key_obj);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key_obj.is_null());

    let mut attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    TEE_InitRefAttribute(
        &mut attr,
        TEE_ATTR_SECRET_VALUE,
        key.as_ptr() as *const _,
        key.len(),
    );
    let res = TEE_PopulateTransientObject(key_obj, &mut attr, 1);
    assert_eq!(res, TEE_SUCCESS);

    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_AES_CMAC, TEE_MODE_MAC, 128);
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, key_obj);

    TEE_MACInit(operation_ptr, core::ptr::null(), 0);
    TEE_MACUpdate(operation_ptr, data.as_ptr() as _, data.len());

    let mac: [u8; 16] = [0; 16];
    let mut mac_len = mac.len();
    let res = TEE_MACComputeFinal(
        operation_ptr,
        core::ptr::null(),
        0,
        mac.as_ptr() as _,
        &mut mac_len,
    );
    assert_eq!(res, 0);
    assert_eq!(mac_len, 16);
    assert_eq!(
        mac,
        [
            0x38, 0x7b, 0x36, 0x22, 0x8b, 0xa7, 0x77, 0x44, 0x5b, 0xaf, 0xa0, 0x36, 0x45, 0xb9,
            0x40, 0x10
        ]
    );

    TEE_FreeOperation(operation_ptr);
    TEE_FreeTransientObject(key_obj);

    TEE_SUCCESS
}

fn cryp_aes_ccm_test() -> TEE_Result {
    let key = [
        0x40u8, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    let nonce = [0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
    let aad = [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let plain = [0x20u8, 0x21, 0x22, 0x23];
    let cipher_expect = [0x71u8, 0x62, 0x01, 0x5b];
    let tag_expect = [0x4du8, 0xac, 0x25, 0x5d];

    let mut key_obj: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &mut key_obj);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key_obj.is_null());

    let mut attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    TEE_InitRefAttribute(
        &mut attr,
        TEE_ATTR_SECRET_VALUE,
        key.as_ptr() as *const _,
        key.len(),
    );
    let res = TEE_PopulateTransientObject(key_obj, &mut attr, 1);
    assert_eq!(res, TEE_SUCCESS);

    // Encrypt
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_AES_CCM, TEE_MODE_ENCRYPT, 128);
    assert_eq!(res, 0);
    TEE_SetOperationKey(operation_ptr, key_obj);

    let mut enc_output = [0u8; 20];
    let mut tag = [0u8; 4];
    let mut enc_tag_len = tag.len();
    let mut enc_len = enc_output.len();

    let res = TEE_AEInit(
        operation_ptr,
        nonce.as_ptr() as _,
        nonce.len(),
        (tag.len() * 8) as u32,
        aad.len(),
        plain.len(),
    );
    assert_eq!(res, 0);

    TEE_AEUpdateAAD(operation_ptr, aad.as_ptr() as _, aad.len());

    let res = TEE_AEUpdate(
        operation_ptr,
        plain.as_ptr() as _,
        plain.len(),
        enc_output.as_mut_ptr() as _,
        &mut enc_len,
    );
    assert_eq!(res, 0);
    assert_eq!(enc_len, 0);

    let mut final_len = enc_output[enc_len..].len();
    let res = TEE_AEEncryptFinal(
        operation_ptr,
        core::ptr::null(),
        0,
        enc_output[enc_len..].as_mut_ptr() as _,
        &mut final_len,
        tag.as_mut_ptr() as _,
        &mut enc_tag_len,
    );
    assert_eq!(res, 0);
    assert_eq!(final_len, plain.len());
    assert_eq!(&enc_output[..final_len], &cipher_expect);
    assert_eq!(enc_tag_len, tag_expect.len());
    assert_eq!(tag, tag_expect);

    TEE_FreeOperation(operation_ptr);

    // Decrypt
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_AES_CCM, TEE_MODE_DECRYPT, 128);
    assert_eq!(res, 0);
    TEE_SetOperationKey(operation_ptr, key_obj);

    let mut dec_output = [0u8; 20];
    let mut dec_len = dec_output.len();
    let res = TEE_AEInit(
        operation_ptr,
        nonce.as_ptr() as _,
        nonce.len(),
        (tag_expect.len() * 8) as u32,
        aad.len(),
        cipher_expect.len(),
    );
    assert_eq!(res, 0);

    TEE_AEUpdateAAD(operation_ptr, aad.as_ptr() as _, aad.len());

    let res = TEE_AEUpdate(
        operation_ptr,
        cipher_expect.as_ptr() as _,
        cipher_expect.len(),
        dec_output.as_mut_ptr() as _,
        &mut dec_len,
    );
    assert_eq!(res, 0);
    assert_eq!(dec_len, 0);

    let mut dec_final_len = dec_output[dec_len..].len();
    let res = TEE_AEDecryptFinal(
        operation_ptr,
        core::ptr::null(),
        0,
        dec_output[dec_len..].as_mut_ptr() as _,
        &mut dec_final_len,
        tag_expect.as_ptr() as _,
        tag_expect.len(),
    );
    assert_eq!(res, 0);
    assert_eq!(dec_final_len, plain.len());
    assert_eq!(&dec_output[..dec_final_len], &plain);

    TEE_FreeOperation(operation_ptr);
    TEE_FreeTransientObject(key_obj);

    TEE_SUCCESS
}

fn cryp_hmac_sm3_test() -> TEE_Result {
    // alloc a transient object
    let mut key1: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SM3, 128, &mut key1);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    // generate a sm3 hmac key
    let res = TEE_GenerateKey(key1, 128, core::ptr::null(), 0);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();

    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_HMAC_SM3, TEE_MODE_MAC, 128);
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, key1);

    let data = b"abc";

    TEE_MACInit(operation_ptr, core::ptr::null(), 0);

    TEE_MACUpdate(operation_ptr, data.as_ptr() as _, data.len());

    let mac: [u8; 32] = [0; 32];
    let mut mac_len = mac.len();
    let res = TEE_MACComputeFinal(
        operation_ptr,
        core::ptr::null(),
        0,
        mac.as_ptr() as _,
        &mut mac_len,
    );
    assert_eq!(res, 0);

    TEE_FreeOperation(operation_ptr);

    TEE_SUCCESS
}

fn cryp_sm4_ecb_test() -> TEE_Result {
    // alloc a transient object
    let mut key1: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_SM4, 128, &mut key1);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    // generate a sm4 key
    let res = TEE_GenerateKey(key1, 128, core::ptr::null(), 0);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    // Encrypt
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();

    let res = TEE_AllocateOperation(
        &mut operation_ptr,
        TEE_ALG_SM4_ECB_NOPAD,
        TEE_MODE_ENCRYPT,
        128,
    );
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, key1);

    let enc_data = b"abcdefghabcdefgh1234567890987654";
    let enc_output = [0u8; 48];
    let mut total_len = 0;
    let mut d_len = enc_output[total_len..].len();

    TEE_CipherInit(operation_ptr, core::ptr::null(), 0);

    let res = TEE_CipherUpdate(
        operation_ptr,
        enc_data[..16].as_ptr() as _,
        enc_data[..16].len(),
        enc_output[total_len..].as_ptr() as _,
        &mut d_len,
    );
    total_len += d_len;
    assert_eq!(res, 0);
    assert_eq!(total_len, 16);

    d_len = enc_output[total_len..].len();
    let res = TEE_CipherUpdate(
        operation_ptr,
        enc_data[16..].as_ptr() as _,
        enc_data[16..].len(),
        enc_output[total_len..].as_ptr() as _,
        &mut d_len,
    );
    total_len += d_len;
    assert_eq!(res, 0);
    assert_eq!(total_len, 32);

    d_len = enc_output[total_len..].len();
    let res = TEE_CipherDoFinal(
        operation_ptr,
        core::ptr::null(),
        0,
        enc_output[total_len..].as_ptr() as _,
        &mut d_len,
    );
    total_len += d_len;
    assert_eq!(res, 0);
    assert_eq!(total_len, 32);

    TEE_FreeOperation(operation_ptr);

    // Decrypt
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();

    let res = TEE_AllocateOperation(
        &mut operation_ptr,
        TEE_ALG_SM4_ECB_NOPAD,
        TEE_MODE_DECRYPT,
        128,
    );
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, key1);

    let dec_data = &enc_output[..32];
    let dec_output = [0u8; 48];
    let mut total_len = 0;
    let mut d_len = dec_output[total_len..].len();

    TEE_CipherInit(operation_ptr, core::ptr::null(), 0);

    let res = TEE_CipherUpdate(
        operation_ptr,
        dec_data[..16].as_ptr() as _,
        dec_data[..16].len(),
        dec_output[total_len..].as_ptr() as _,
        &mut d_len,
    );
    total_len += d_len;
    assert_eq!(res, 0);
    assert_eq!(total_len, 16);

    d_len = dec_output[total_len..].len();
    let res = TEE_CipherUpdate(
        operation_ptr,
        dec_data[16..].as_ptr() as _,
        dec_data[16..].len(),
        dec_output[total_len..].as_ptr() as _,
        &mut d_len,
    );
    total_len += d_len;
    assert_eq!(res, 0);
    assert_eq!(total_len, 32);

    d_len = dec_output[total_len..].len();
    let res = TEE_CipherDoFinal(
        operation_ptr,
        core::ptr::null(),
        0,
        dec_output[total_len..].as_ptr() as _,
        &mut d_len,
    );
    total_len += d_len;
    assert_eq!(res, 0);
    assert_eq!(total_len, 32);

    let data = &dec_output[..32];
    assert_eq!(data, enc_data);

    TEE_FreeOperation(operation_ptr);

    TEE_SUCCESS
}

fn cryp_sm4_cbc_test() -> TEE_Result {
    // alloc a transient object
    let mut key1: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_SM4, 128, &mut key1);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    // generate a sm4 key
    let res = TEE_GenerateKey(key1, 128, core::ptr::null(), 0);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    // Encrypt
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();

    let res = TEE_AllocateOperation(
        &mut operation_ptr,
        TEE_ALG_SM4_CBC_NOPAD,
        TEE_MODE_ENCRYPT,
        128,
    );
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, key1);

    let enc_data = b"abcdefghabcdefgh1234567890987654";
    let iv = b"1234qwerasdfzxcv";
    let enc_output = [0u8; 48];
    let mut total_len = 0;
    let mut d_len = enc_output[total_len..].len();

    TEE_CipherInit(operation_ptr, iv.as_ptr() as _, iv.len());

    let res = TEE_CipherUpdate(
        operation_ptr,
        enc_data[..16].as_ptr() as _,
        enc_data[..16].len(),
        enc_output[total_len..].as_ptr() as _,
        &mut d_len,
    );
    total_len += d_len;
    assert_eq!(res, 0);
    assert_eq!(total_len, 16);

    d_len = enc_output[total_len..].len();
    let res = TEE_CipherUpdate(
        operation_ptr,
        enc_data[16..].as_ptr() as _,
        enc_data[16..].len(),
        enc_output[total_len..].as_ptr() as _,
        &mut d_len,
    );
    total_len += d_len;
    assert_eq!(res, 0);
    assert_eq!(total_len, 32);

    d_len = enc_output[total_len..].len();
    let res = TEE_CipherDoFinal(
        operation_ptr,
        core::ptr::null(),
        0,
        enc_output[total_len..].as_ptr() as _,
        &mut d_len,
    );
    total_len += d_len;
    assert_eq!(res, 0);
    assert_eq!(total_len, 32);

    TEE_FreeOperation(operation_ptr);

    // Decrypt
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();

    let res = TEE_AllocateOperation(
        &mut operation_ptr,
        TEE_ALG_SM4_CBC_NOPAD,
        TEE_MODE_DECRYPT,
        128,
    );
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, key1);

    let dec_data = &enc_output[..32];
    let dec_output = [0u8; 48];
    let mut total_len = 0;
    let mut d_len = dec_output[total_len..].len();

    TEE_CipherInit(operation_ptr, iv.as_ptr() as _, iv.len());

    let res = TEE_CipherUpdate(
        operation_ptr,
        dec_data[..16].as_ptr() as _,
        dec_data[..16].len(),
        dec_output[total_len..].as_ptr() as _,
        &mut d_len,
    );
    total_len += d_len;
    assert_eq!(res, 0);
    assert_eq!(total_len, 16);

    d_len = dec_output[total_len..].len();
    let res = TEE_CipherUpdate(
        operation_ptr,
        dec_data[16..].as_ptr() as _,
        dec_data[16..].len(),
        dec_output[total_len..].as_ptr() as _,
        &mut d_len,
    );
    total_len += d_len;
    assert_eq!(res, 0);
    assert_eq!(total_len, 32);

    d_len = dec_output[total_len..].len();
    let res = TEE_CipherDoFinal(
        operation_ptr,
        core::ptr::null(),
        0,
        dec_output[total_len..].as_ptr() as _,
        &mut d_len,
    );
    total_len += d_len;
    assert_eq!(res, 0);
    assert_eq!(total_len, 32);

    let data = &dec_output[..32];
    assert_eq!(data, enc_data);

    TEE_FreeOperation(operation_ptr);

    TEE_SUCCESS
}

fn copy_operation_sm4_cbc_encrypt_test() -> TEE_Result {
    let key = b"abcdefghabcdefgh";
    let iv = b"1234qwerasdfzxcv";
    let data1 = b"abcdefghabcdefgh";
    let data2 = b"1234567890987654";

    let mut key_obj: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_SM4, 128, &mut key_obj);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key_obj.is_null());

    let mut attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    TEE_InitRefAttribute(
        &mut attr,
        TEE_ATTR_SECRET_VALUE,
        key.as_ptr() as *const _,
        key.len(),
    );
    let res = TEE_PopulateTransientObject(key_obj, &mut attr, 1);
    assert_eq!(res, TEE_SUCCESS);

    let mut src_op: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut src_op, TEE_ALG_SM4_CBC_NOPAD, TEE_MODE_ENCRYPT, 128);
    assert_eq!(res, 0);
    TEE_SetOperationKey(src_op, key_obj);

    let mut dst_op: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut dst_op, TEE_ALG_SM4_CBC_NOPAD, TEE_MODE_ENCRYPT, 128);
    assert_eq!(res, 0);

    TEE_CipherInit(src_op, iv.as_ptr() as _, iv.len());

    let mut out1 = [0u8; 32];
    let mut out1_len = out1.len();
    let res = TEE_CipherUpdate(
        src_op,
        data1.as_ptr() as _,
        data1.len(),
        out1.as_mut_ptr() as _,
        &mut out1_len,
    );
    assert_eq!(res, 0);
    assert_eq!(out1_len, 16);

    TEE_CopyOperation(dst_op, src_op);

    let mut out2_src = [0u8; 32];
    let mut out2_src_len = out2_src.len();
    let res = TEE_CipherUpdate(
        src_op,
        data2.as_ptr() as _,
        data2.len(),
        out2_src.as_mut_ptr() as _,
        &mut out2_src_len,
    );
    assert_eq!(res, 0);
    assert_eq!(out2_src_len, 16);

    let mut out2_dst = [0u8; 32];
    let mut out2_dst_len = out2_dst.len();
    let res = TEE_CipherUpdate(
        dst_op,
        data2.as_ptr() as _,
        data2.len(),
        out2_dst.as_mut_ptr() as _,
        &mut out2_dst_len,
    );
    assert_eq!(res, 0);
    assert_eq!(out2_dst_len, 16);

    assert_eq!(&out2_dst[..16], &out2_src[..16]);

    TEE_FreeOperation(src_op);
    TEE_FreeOperation(dst_op);
    TEE_FreeTransientObject(key_obj);

    TEE_SUCCESS
}

fn cryp_sm4_gcm_test() -> TEE_Result {
    // alloc a transient object
    let mut key1: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_SM4, 128, &mut key1);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    // generate a sm4 key
    let res = TEE_GenerateKey(key1, 128, core::ptr::null(), 0);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    // Encrypt
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();

    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_SM4_GCM, TEE_MODE_ENCRYPT, 128);
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, key1);

    let data: [u8; 64] = [
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
        0xDD, 0xDD, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA,
    ];
    let nonce: [u8; 12] = [
        0xA3, 0x33, 0x06, 0x38, 0xA8, 0x09, 0xBA, 0x35, 0x8D, 0x6C, 0x09, 0x8E,
    ];
    let ad: [u8; 20] = [
        0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE,
        0xEF, 0xAB, 0xAD, 0xDA, 0xD2,
    ];
    let tag: [u8; 16] = [0u8; 16];
    let enc_output = [0u8; 80];
    let mut total_len = 0;
    let mut enc_len = enc_output[total_len..].len();

    // 后三个参数不起作用
    let res = TEE_AEInit(operation_ptr, nonce.as_ptr() as _, nonce.len(), 0, 0, 0);
    assert_eq!(res, 0);

    TEE_AEUpdateAAD(operation_ptr, ad.as_ptr() as _, ad.len());

    let res = TEE_AEUpdate(
        operation_ptr,
        data[..32].as_ptr() as _,
        data[..32].len(),
        enc_output[total_len..].as_ptr() as _,
        &mut enc_len,
    );
    assert_eq!(res, 0);
    total_len += enc_len;
    assert_eq!(total_len, 32);

    // TAG长度是固定的16Bytes，因此实际上不会返回tag长度
    enc_len = enc_output[total_len..].len();
    let res = TEE_AEEncryptFinal(
        operation_ptr,
        data[32..].as_ptr() as _,
        data[32..].len(),
        enc_output[total_len..].as_ptr() as _,
        &mut enc_len,
        tag.as_ptr() as _,
        &mut tag.len(),
    );
    assert_eq!(res, 0);
    total_len += enc_len;
    assert_eq!(total_len, 64);

    TEE_FreeOperation(operation_ptr);

    // Decrypt
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();

    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_SM4_GCM, TEE_MODE_DECRYPT, 128);
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, key1);

    let dec_data = &enc_output[..64];
    let dec_output = [0u8; 80];
    let mut total_len = 0;
    let mut dec_len = enc_output[total_len..].len();

    // 后三个参数不起作用
    let res = TEE_AEInit(operation_ptr, nonce.as_ptr() as _, nonce.len(), 0, 0, 0);
    assert_eq!(res, 0);

    TEE_AEUpdateAAD(operation_ptr, ad.as_ptr() as _, ad.len());

    let res = TEE_AEUpdate(
        operation_ptr,
        dec_data[..32].as_ptr() as _,
        dec_data[..32].len(),
        dec_output[total_len..].as_ptr() as _,
        &mut dec_len,
    );
    assert_eq!(res, 0);
    total_len += dec_len;
    assert_eq!(total_len, 32);

    // TAG长度是固定的16Bytes，因此实际上不会返回tag长度
    dec_len = dec_output[total_len..].len();
    let res = TEE_AEDecryptFinal(
        operation_ptr,
        dec_data[32..].as_ptr() as _,
        dec_data[32..].len(),
        dec_output[total_len..].as_ptr() as _,
        &mut dec_len,
        tag.as_ptr() as _,
        tag.len(),
    );
    assert_eq!(res, 0);
    total_len += dec_len;
    assert_eq!(total_len, 64);
    assert_eq!(&dec_output[..64], data);

    TEE_FreeOperation(operation_ptr);

    TEE_SUCCESS
}

fn cryp_sm2_enc_dec_test() -> TEE_Result {
    // alloc a transient object
    let mut key1: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_SM2_PKE_KEYPAIR, 256, &mut key1);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    // generate a sm2 key
    let res = TEE_GenerateKey(key1, 256, core::ptr::null(), 0);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    // alloc a transient object
    let mut pubkey: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_SM2_PKE_PUBLIC_KEY, 256, &mut pubkey);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!pubkey.is_null());

    let res = TEE_CopyObjectAttributes1(pubkey, key1);
    assert_eq!(res, TEE_SUCCESS);

    let data = b"SIGNATURE TEST SIGNATURE TEST SI";
    let cipher1 = [0u8; 141];
    let cipher2 = [0u8; 141];
    let mut cipher1_len = cipher1.len();
    let mut cipher2_len = cipher2.len();

    // Encrypt
    let mut operation = TEE_OperationHandle::default();
    operation.key1 = pubkey;
    let mut operation_ptr: *mut TEE_OperationHandle = &mut operation;

    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_SM2_PKE, TEE_MODE_ENCRYPT, 256);
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, pubkey);

    let res = TEE_AsymmetricEncrypt(
        operation_ptr,
        core::ptr::null(),
        0,
        data.as_ptr() as _,
        data.len(),
        cipher1.as_ptr() as _,
        &mut cipher1_len,
    );
    assert_eq!(res, 0);

    let res = TEE_AsymmetricEncrypt(
        operation_ptr,
        core::ptr::null(),
        0,
        data.as_ptr() as _,
        data.len(),
        cipher2.as_ptr() as _,
        &mut cipher2_len,
    );
    assert_eq!(res, 0);

    assert_ne!(&cipher1[..cipher1_len], &cipher2[..cipher2_len]);
    TEE_FreeOperation(operation_ptr);

    // Decrypt
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();

    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_SM2_PKE, TEE_MODE_DECRYPT, 256);
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, key1);

    let clear1 = [0u8; 141];
    let clear2 = [0u8; 141];
    let mut clear1_len = clear1.len();
    let mut clear2_len = clear2.len();

    let res = TEE_AsymmetricDecrypt(
        operation_ptr,
        core::ptr::null(),
        0,
        cipher1[..cipher1_len].as_ptr() as _,
        cipher1_len,
        clear1.as_ptr() as _,
        &mut clear1_len,
    );
    assert_eq!(res, 0);

    let res = TEE_AsymmetricDecrypt(
        operation_ptr,
        core::ptr::null(),
        0,
        cipher2[..cipher2_len].as_ptr() as _,
        cipher2_len,
        clear2.as_ptr() as _,
        &mut clear2_len,
    );
    assert_eq!(res, 0);

    assert_eq!(&clear1[..clear1_len], &clear2[..clear2_len]);
    assert_eq!(&clear1[..clear1_len], data);

    TEE_FreeOperation(operation_ptr);

    TEE_SUCCESS
}

/// SM2 PKE 解密向量：用给定公钥坐标与私钥填充 `TEE_TYPE_SM2_PKE_KEYPAIR`，分别解密两份密文，
/// 并与标准 UTF-8 明文 `SIGNATURE TEST SIGNATURE TEST SI` 对照。
fn cryp_sm2_pke_decrypt_vector_test() -> TEE_Result {
    const PUBKEY: [u8; 64] = [
        0x16, 0x74, 0x7a, 0xec, 0x5c, 0x7c, 0x1d, 0x8a, 0x9f, 0xc6, 0x58, 0x87, 0xd8, 0x10, 0x98,
        0xa4, 0x89, 0x43, 0x14, 0x25, 0x59, 0x52, 0x57, 0xde, 0xd0, 0x0a, 0xb3, 0xc4, 0xea, 0xe8,
        0x36, 0x87, 0xb7, 0x7d, 0x9e, 0x68, 0xa8, 0x24, 0x34, 0x7f, 0x8f, 0x7f, 0x14, 0x59, 0x3d,
        0x8c, 0x37, 0xa6, 0x65, 0x54, 0xa4, 0x84, 0xec, 0x93, 0xe1, 0x9b, 0xb1, 0xb3, 0x38, 0x28,
        0xe8, 0xe2, 0x68, 0x24,
    ];
    const PRIVKEY: [u8; 32] = [
        0xc2, 0x3c, 0x51, 0xf4, 0x5c, 0x9e, 0x49, 0x59, 0x5f, 0x93, 0x3a, 0xf2, 0x72, 0x41, 0xf4,
        0x1c, 0xf7, 0x0a, 0x2b, 0x72, 0xc2, 0x32, 0xfa, 0x68, 0x64, 0x83, 0x5f, 0xa0, 0x60, 0xd7,
        0x1e, 0x02,
    ];
    const CIPHER1: [u8; 129] = [
        0x04, 0x06, 0x4e, 0xbf, 0xd3, 0xef, 0x53, 0x74, 0x83, 0x38, 0xfd, 0x3d, 0x2c, 0x82, 0x27,
        0x86, 0x15, 0xd9, 0x72, 0xee, 0x71, 0xe5, 0x77, 0xa3, 0xf8, 0xa9, 0xc0, 0x4a, 0xb1, 0xdf,
        0x81, 0x83, 0xbd, 0x80, 0xbf, 0x58, 0xe3, 0x6b, 0x07, 0x3e, 0xe8, 0xd4, 0xff, 0x93, 0x50,
        0x80, 0x45, 0xe1, 0xae, 0x42, 0x41, 0x84, 0xf2, 0xda, 0x1f, 0xb8, 0x03, 0x42, 0xfb, 0xd9,
        0x4e, 0xbe, 0x67, 0x47, 0x41, 0x22, 0x89, 0x0e, 0x0e, 0x0a, 0x65, 0x1d, 0xdb, 0x38, 0x34,
        0x6d, 0x11, 0x42, 0xa9, 0x85, 0x41, 0x62, 0x60, 0x55, 0x36, 0xa9, 0xfe, 0x6e, 0xc2, 0x32,
        0xae, 0x93, 0x4a, 0x3d, 0x7d, 0x42, 0x7f, 0x2b, 0x0d, 0x2f, 0x99, 0x6f, 0xc1, 0x2b, 0x60,
        0x42, 0x0a, 0x00, 0x3d, 0x53, 0xa5, 0x50, 0x1f, 0x9e, 0xde, 0x81, 0x14, 0xf7, 0xeb, 0x14,
        0x5a, 0xb5, 0xf2, 0x55, 0x34, 0xa3, 0x43, 0xe0, 0xe2,
    ];
    const CIPHER2: [u8; 129] = [
        0x04, 0x62, 0xfa, 0x88, 0x99, 0x29, 0xe0, 0xb4, 0x32, 0xa7, 0x35, 0xa9, 0x90, 0xd7, 0x01,
        0xc6, 0x58, 0x8a, 0xd0, 0x1d, 0x3d, 0x78, 0x45, 0x24, 0x95, 0x77, 0x15, 0x8b, 0x1d, 0xd3,
        0xc4, 0xe5, 0x4a, 0xad, 0xc2, 0x17, 0x46, 0x2a, 0xb0, 0x2d, 0x98, 0xba, 0x88, 0x9b, 0x69,
        0xc1, 0x13, 0x8c, 0x38, 0x45, 0x80, 0x06, 0x41, 0xab, 0xc2, 0xd8, 0x45, 0xfe, 0xed, 0x63,
        0xe4, 0x27, 0xac, 0x95, 0x5b, 0x89, 0xdf, 0x18, 0x5a, 0x7a, 0x5a, 0x5a, 0x1b, 0x26, 0xdc,
        0x51, 0x1f, 0x1a, 0xfd, 0xf8, 0xc3, 0xf4, 0x32, 0x41, 0xce, 0xb1, 0xae, 0x0a, 0x6d, 0x55,
        0xe6, 0x30, 0x95, 0xe4, 0x49, 0x8a, 0xc5, 0x83, 0xb0, 0x16, 0xda, 0xa2, 0xc0, 0x90, 0x75,
        0x42, 0x7c, 0x95, 0xf9, 0x32, 0x53, 0x20, 0x68, 0x00, 0x00, 0x24, 0x6a, 0x28, 0x19, 0xfc,
        0xcd, 0xd3, 0xa9, 0x31, 0x4c, 0xad, 0x46, 0x41, 0xe3,
    ];
    const EXPECT_PLAIN: &[u8] = b"SIGNATURE TEST SIGNATURE TEST SI";

    let mut keypair: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_SM2_PKE_KEYPAIR, 256, &mut keypair);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!keypair.is_null());

    let mut attrs = [
        TEE_Attribute {
            attributeID: 0,
            content: unsafe { core::mem::zeroed() },
        },
        TEE_Attribute {
            attributeID: 0,
            content: unsafe { core::mem::zeroed() },
        },
        TEE_Attribute {
            attributeID: 0,
            content: unsafe { core::mem::zeroed() },
        },
    ];
    TEE_InitRefAttribute(
        &mut attrs[0],
        TEE_ATTR_ECC_PUBLIC_VALUE_X,
        PUBKEY[..32].as_ptr().cast(),
        32,
    );
    TEE_InitRefAttribute(
        &mut attrs[1],
        TEE_ATTR_ECC_PUBLIC_VALUE_Y,
        PUBKEY[32..].as_ptr().cast(),
        32,
    );
    TEE_InitRefAttribute(
        &mut attrs[2],
        TEE_ATTR_ECC_PRIVATE_VALUE,
        PRIVKEY.as_ptr().cast(),
        PRIVKEY.len(),
    );
    let res = TEE_PopulateTransientObject(keypair, attrs.as_ptr(), 3);
    assert_eq!(res, TEE_SUCCESS);

    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_SM2_PKE, TEE_MODE_DECRYPT, 256);
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, keypair);

    let plain1 = [0u8; 64];
    let mut plain1_len = plain1.len();
    let res = TEE_AsymmetricDecrypt(
        operation_ptr,
        core::ptr::null(),
        0,
        CIPHER1.as_ptr() as _,
        CIPHER1.len(),
        plain1.as_ptr() as _,
        &mut plain1_len,
    );
    assert_eq!(res, 0);
    assert_eq!(&plain1[..plain1_len], EXPECT_PLAIN);

    let plain2 = [0u8; 64];
    let mut plain2_len = plain2.len();
    let res = TEE_AsymmetricDecrypt(
        operation_ptr,
        core::ptr::null(),
        0,
        CIPHER2.as_ptr() as _,
        CIPHER2.len(),
        plain2.as_ptr() as _,
        &mut plain2_len,
    );
    assert_eq!(res, 0);
    assert_eq!(&plain2[..plain2_len], EXPECT_PLAIN);
    assert_eq!(&plain1[..plain1_len], &plain2[..plain2_len]);

    TEE_FreeOperation(operation_ptr);

    TEE_SUCCESS
}

fn cryp_sm2_sign_verify_test() -> TEE_Result {
    // alloc a transient object
    let mut key1: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_SM2_DSA_KEYPAIR, 256, &mut key1);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    // generate a sm2 key
    let res = TEE_GenerateKey(key1, 256, core::ptr::null(), 0);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    // alloc a transient object
    let mut pubkey: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_SM2_DSA_PUBLIC_KEY, 256, &mut pubkey);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!pubkey.is_null());

    let res = TEE_CopyObjectAttributes1(pubkey, key1);
    assert_eq!(res, TEE_SUCCESS);

    let data = b"SIGNATURE TEST SIGNATURE TEST SI";

    // Sign
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();

    let signature1 = [0u8; 141];
    let signature2 = [0u8; 141];
    let mut sig1_len = signature1.len();
    let mut sig2_len = signature2.len();

    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_SM2_DSA_SM3, TEE_MODE_SIGN, 256);
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, key1);

    let res = TEE_AsymmetricSignDigest(
        operation_ptr,
        core::ptr::null(),
        0,
        data.as_ptr() as _,
        data.len(),
        signature1.as_ptr() as _,
        &mut sig1_len,
    );
    assert_eq!(res, 0);

    let res = TEE_AsymmetricSignDigest(
        operation_ptr,
        core::ptr::null(),
        0,
        data.as_ptr() as _,
        data.len(),
        signature2.as_ptr() as _,
        &mut sig2_len,
    );
    assert_eq!(res, 0);

    TEE_FreeOperation(operation_ptr);

    // Verify
    let mut verify_op: *mut TEE_OperationHandle = core::ptr::null_mut();

    let res = TEE_AllocateOperation(&mut verify_op, TEE_ALG_SM2_DSA_SM3, TEE_MODE_VERIFY, 256);
    assert_eq!(res, 0);

    TEE_SetOperationKey(verify_op, pubkey);

    let res = TEE_AsymmetricVerifyDigest(
        verify_op,
        core::ptr::null(),
        0,
        data.as_ptr() as _,
        data.len(),
        signature1.as_ptr() as _,
        sig1_len,
    );
    assert_eq!(res, 0);

    let res = TEE_AsymmetricVerifyDigest(
        verify_op,
        core::ptr::null(),
        0,
        data.as_ptr() as _,
        data.len(),
        signature2.as_ptr() as _,
        sig2_len,
    );
    assert_eq!(res, 0);

    TEE_FreeOperation(verify_op);

    TEE_SUCCESS
}

/// 与内核 `test_cryp_sm2_verify_with_pub_key_via_init_ref_attr` 相同向量。
///
/// x-kernel 的 SM2 验签走 `sm2_verify_digest_raw`：`digest` 为预计算的 E = SM3(Z||M)，
/// 签名为 64 字节 raw R||S（非 ASN.1 DER）。TA 侧用 `sm2_compute_sign_digest` 计算 E。
fn cryp_sm2_verify_with_fixed_pubkey_test() -> TEE_Result {
    const PUBKEY: [u8; 64] = [
        0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5,
        0xC6, 0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3,
        0x50, 0x20, 0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C,
        0xC1, 0xAA, 0x60, 0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07,
        0x2D, 0xA9, 0xAD, 0x13,
    ];
    const SIG: [u8; 64] = [
        0xF5, 0xA0, 0x3B, 0x06, 0x48, 0xD2, 0xC4, 0x63, 0x0E, 0xEA, 0xC5, 0x13, 0xE1, 0xBB, 0x81,
        0xA1, 0x59, 0x44, 0xDA, 0x38, 0x27, 0xD5, 0xB7, 0x41, 0x43, 0xAC, 0x7E, 0xAC, 0xEE, 0xE7,
        0x20, 0xB3, 0xB1, 0xB6, 0xAA, 0x29, 0xDF, 0x21, 0x2F, 0xD8, 0x76, 0x31, 0x82, 0xBC, 0x0D,
        0x42, 0x1C, 0xA1, 0xBB, 0x90, 0x38, 0xFD, 0x1F, 0x7F, 0x42, 0xD4, 0x84, 0x0B, 0x69, 0xC4,
        0x85, 0xBB, 0xC1, 0xAA,
    ];
    let msg = b"message digest";

    let mut pubkey_obj: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_SM2_DSA_PUBLIC_KEY, 256, &mut pubkey_obj);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!pubkey_obj.is_null());

    let mut attrs = [
        TEE_Attribute {
            attributeID: 0,
            content: unsafe { core::mem::zeroed() },
        },
        TEE_Attribute {
            attributeID: 0,
            content: unsafe { core::mem::zeroed() },
        },
    ];
    TEE_InitRefAttribute(
        &mut attrs[0],
        TEE_ATTR_ECC_PUBLIC_VALUE_X,
        PUBKEY[..32].as_ptr().cast(),
        32,
    );
    TEE_InitRefAttribute(
        &mut attrs[1],
        TEE_ATTR_ECC_PUBLIC_VALUE_Y,
        PUBKEY[32..].as_ptr().cast(),
        32,
    );
    let res = TEE_PopulateTransientObject(pubkey_obj, attrs.as_ptr(), 2);
    assert_eq!(res, TEE_SUCCESS);

    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(
        &mut operation_ptr,
        TEE_ALG_SM2_DSA_SM3,
        TEE_MODE_VERIFY,
        256,
    );
    assert_eq!(res, 0);

    TEE_SetOperationKey(operation_ptr, pubkey_obj);

    let digest = match sm2_compute_sign_digest(None, msg, &PUBKEY) {
        Ok(d) => d,
        Err(e) => return e,
    };

    let res = TEE_AsymmetricVerifyDigest(
        operation_ptr,
        core::ptr::null(),
        0,
        digest.as_ptr() as _,
        digest.len(),
        SIG.as_ptr() as _,
        SIG.len(),
    );
    assert_eq!(res, 0);

    TEE_FreeOperation(operation_ptr);

    TEE_SUCCESS
}

/// 与内核 `test_cryp_ed25519_verify_sig_structure_vector` 相同向量。
fn cryp_ed25519_verify_sig_structure_vector_test() -> TEE_Result {
    const PUBKEY: [u8; 32] = [
        0x72, 0x0e, 0x96, 0x83, 0x20, 0xf6, 0xd3, 0x24, 0xd2, 0x94, 0x23, 0xd5, 0x46, 0x52, 0x4c,
        0x7a, 0xcb, 0xb5, 0x49, 0xc1, 0x2a, 0x49, 0xe0, 0x59, 0xdb, 0xc5, 0x08, 0xc5, 0x60, 0x99,
        0xf8, 0x2e,
    ];
    const SIG: [u8; 64] = [
        0x83, 0x99, 0xc9, 0x44, 0x82, 0x42, 0x7c, 0x98, 0x31, 0x77, 0x60, 0x73, 0xc2, 0xe5, 0xc3,
        0xb7, 0x3f, 0x4f, 0x8a, 0x65, 0x96, 0x01, 0x60, 0x6f, 0x3c, 0x56, 0xaa, 0xb6, 0xb2, 0x7c,
        0x68, 0x54, 0x39, 0x48, 0xcb, 0x57, 0x8a, 0x1c, 0x7b, 0x17, 0xf1, 0x78, 0xac, 0x20, 0x35,
        0x46, 0xd6, 0x9f, 0x61, 0x74, 0x44, 0x3a, 0x88, 0x54, 0x48, 0xe8, 0x37, 0x16, 0x59, 0x78,
        0x81, 0x62, 0xa4, 0x00,
    ];
    const MESSAGE: [u8; 412] = [
        0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xa1, 0x01,
        0x27, 0x40, 0x59, 0x01, 0x88, 0xa9, 0x01, 0x78, 0x28, 0x30, 0x32, 0x38, 0x36, 0x30, 0x61,
        0x33, 0x30, 0x35, 0x33, 0x63, 0x32, 0x62, 0x62, 0x63, 0x39, 0x66, 0x63, 0x36, 0x39, 0x62,
        0x62, 0x38, 0x32, 0x35, 0x66, 0x31, 0x34, 0x65, 0x31, 0x34, 0x33, 0x31, 0x36, 0x39, 0x39,
        0x65, 0x32, 0x39, 0x30, 0x02, 0x78, 0x28, 0x37, 0x62, 0x66, 0x38, 0x65, 0x62, 0x32, 0x38,
        0x66, 0x39, 0x39, 0x34, 0x32, 0x38, 0x30, 0x37, 0x30, 0x62, 0x36, 0x38, 0x62, 0x34, 0x62,
        0x63, 0x35, 0x65, 0x34, 0x32, 0x31, 0x63, 0x37, 0x31, 0x66, 0x31, 0x37, 0x65, 0x30, 0x61,
        0x66, 0x31, 0x3a, 0x00, 0x47, 0x44, 0x50, 0x58, 0x40, 0x0b, 0xde, 0x5e, 0x13, 0x6f, 0xce,
        0xb2, 0xc6, 0xfd, 0xed, 0xa5, 0x3e, 0xc8, 0xfa, 0xac, 0x59, 0x5e, 0x88, 0xf4, 0x6c, 0x5b,
        0x5a, 0x93, 0xfe, 0x03, 0xa3, 0xd1, 0x7f, 0x76, 0xf5, 0x75, 0x3c, 0xe9, 0x4d, 0x57, 0x48,
        0xd2, 0xf8, 0x70, 0x9a, 0xc5, 0x46, 0x58, 0x5d, 0xa5, 0xaa, 0x1c, 0xc1, 0x3b, 0xdb, 0xa7,
        0xb0, 0x13, 0xe0, 0x0f, 0xe6, 0xb4, 0xd1, 0x64, 0x6e, 0xb0, 0x54, 0x23, 0xbf, 0x3a, 0x00,
        0x47, 0x44, 0x53, 0x54, 0xa2, 0x3a, 0x00, 0x01, 0x11, 0x71, 0x63, 0x41, 0x56, 0x42, 0x3a,
        0x00, 0x01, 0x11, 0x72, 0x1a, 0x1a, 0x00, 0x01, 0x73, 0x3a, 0x00, 0x47, 0x44, 0x52, 0x58,
        0x40, 0xa6, 0x79, 0x3f, 0x45, 0x09, 0x5c, 0x98, 0xd1, 0x2b, 0x19, 0x7f, 0xd2, 0x55, 0xc2,
        0x40, 0x1c, 0x88, 0x5d, 0x04, 0x2d, 0xf3, 0x4c, 0x25, 0x77, 0x9f, 0xeb, 0xef, 0xbb, 0xd1,
        0x79, 0xe7, 0xf3, 0xfc, 0xe6, 0xb0, 0x39, 0x35, 0x26, 0xa5, 0x7e, 0x76, 0x37, 0xa3, 0xa7,
        0x88, 0x4d, 0x78, 0xe7, 0x04, 0x7c, 0x15, 0x2d, 0x64, 0xfc, 0xc0, 0x19, 0x28, 0xdb, 0xc5,
        0x7a, 0x00, 0xe2, 0x5f, 0x6d, 0x3a, 0x00, 0x47, 0x44, 0x54, 0x58, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x3a, 0x00, 0x47, 0x44, 0x56, 0x41, 0x02, 0x3a, 0x00, 0x47, 0x44, 0x57, 0x58, 0x2d,
        0xa5, 0x01, 0x01, 0x03, 0x27, 0x04, 0x81, 0x02, 0x20, 0x06, 0x21, 0x58, 0x20, 0x2c, 0xe5,
        0x04, 0x23, 0x62, 0x88, 0x5a, 0x95, 0xd0, 0x89, 0x7c, 0x03, 0x33, 0x59, 0x51, 0x6f, 0xd8,
        0xe9, 0x8c, 0xd2, 0xf5, 0xb8, 0xe3, 0x05, 0x2d, 0xd0, 0xa1, 0xcd, 0x54, 0x0d, 0xdb, 0x28,
        0x3a, 0x00, 0x47, 0x44, 0x58, 0x41, 0x20,
    ];

    let mut pubkey_obj: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_ED25519_PUBLIC_KEY, 256, &mut pubkey_obj);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!pubkey_obj.is_null());

    let mut attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    TEE_InitRefAttribute(
        &mut attr,
        TEE_ATTR_ED25519_PUBLIC_VALUE,
        PUBKEY.as_ptr().cast(),
        PUBKEY.len(),
    );
    let res = TEE_PopulateTransientObject(pubkey_obj, &attr, 1);
    assert_eq!(res, TEE_SUCCESS);

    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_ED25519, TEE_MODE_VERIFY, 256);
    assert_eq!(res, TEE_SUCCESS);

    TEE_SetOperationKey(operation_ptr, pubkey_obj);

    let res = TEE_AsymmetricVerifyDigest(
        operation_ptr,
        core::ptr::null(),
        0,
        MESSAGE.as_ptr().cast(),
        MESSAGE.len(),
        SIG.as_ptr().cast(),
        SIG.len(),
    );
    assert_eq!(res, TEE_SUCCESS);

    let mut bad_sig = SIG;
    bad_sig[63] ^= 0xff;
    let res = TEE_AsymmetricVerifyDigest(
        operation_ptr,
        core::ptr::null(),
        0,
        MESSAGE.as_ptr().cast(),
        MESSAGE.len(),
        bad_sig.as_ptr().cast(),
        bad_sig.len(),
    );
    assert_eq!(res, TEE_ERROR_SIGNATURE_INVALID);

    TEE_FreeOperation(operation_ptr);

    TEE_SUCCESS
}

fn cryp_rsa_pkcs1_v15_encrypt_decrypt_test() -> TEE_Result {
    const RSA_BITS: u32 = 2048;

    let mut keypair: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, RSA_BITS, &mut keypair);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!keypair.is_null());

    let res = TEE_GenerateKey(keypair, RSA_BITS, core::ptr::null(), 0);
    assert_eq!(res, TEE_SUCCESS);

    let mut pubkey: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, RSA_BITS, &mut pubkey);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!pubkey.is_null());

    let res = TEE_CopyObjectAttributes1(pubkey, keypair);
    assert_eq!(res, TEE_SUCCESS);

    let plain = b"random 2048-bit rsa pkcs#1 v1.5";
    let mut cipher = [0u8; 256];
    let mut cipher_len = cipher.len();

    let mut op_enc: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(
        &mut op_enc,
        TEE_ALG_RSAES_PKCS1_V1_5,
        TEE_MODE_ENCRYPT,
        RSA_BITS,
    );
    assert_eq!(res, TEE_SUCCESS);
    let res = TEE_SetOperationKey(op_enc, pubkey);
    assert_eq!(res, TEE_SUCCESS);

    let res = TEE_AsymmetricEncrypt(
        op_enc,
        core::ptr::null(),
        0,
        plain.as_ptr() as _,
        plain.len(),
        cipher.as_mut_ptr() as _,
        &mut cipher_len,
    );
    assert_eq!(res, TEE_SUCCESS);
    assert_eq!(cipher_len, cipher.len());

    TEE_FreeOperation(op_enc);

    let mut op_dec: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(
        &mut op_dec,
        TEE_ALG_RSAES_PKCS1_V1_5,
        TEE_MODE_DECRYPT,
        RSA_BITS,
    );
    assert_eq!(res, TEE_SUCCESS);
    let res = TEE_SetOperationKey(op_dec, keypair);
    assert_eq!(res, TEE_SUCCESS);

    let mut out = [0u8; 256];
    let mut out_len = out.len();
    let res = TEE_AsymmetricDecrypt(
        op_dec,
        core::ptr::null(),
        0,
        cipher.as_ptr() as _,
        cipher_len,
        out.as_mut_ptr() as _,
        &mut out_len,
    );
    assert_eq!(res, TEE_SUCCESS);
    assert_eq!(out_len, plain.len());
    assert_eq!(&out[..out_len], plain.as_slice());

    TEE_FreeOperation(op_dec);

    TEE_SUCCESS
}

fn cryp_rsa_oaep_sha256_encrypt_decrypt_with_label_test() -> TEE_Result {
    const RSA_BITS: u32 = 2048;

    let mut keypair: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, RSA_BITS, &mut keypair);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!keypair.is_null());

    let res = TEE_GenerateKey(keypair, RSA_BITS, core::ptr::null(), 0);
    assert_eq!(res, TEE_SUCCESS);

    let mut pubkey: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, RSA_BITS, &mut pubkey);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!pubkey.is_null());

    let res = TEE_CopyObjectAttributes1(pubkey, keypair);
    assert_eq!(res, TEE_SUCCESS);

    let plain = b"testing123";
    let label = b"MY_LABEL";
    let mut label_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    TEE_InitRefAttribute(
        &mut label_attr,
        TEE_ATTR_RSA_OAEP_LABEL,
        label.as_ptr() as *const _,
        label.len(),
    );

    let mut cipher = [0u8; 256];
    let mut cipher_len = cipher.len();

    let mut op_enc: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(
        &mut op_enc,
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256,
        TEE_MODE_ENCRYPT,
        RSA_BITS,
    );
    assert_eq!(res, TEE_SUCCESS);
    let res = TEE_SetOperationKey(op_enc, pubkey);
    assert_eq!(res, TEE_SUCCESS);

    let res = TEE_AsymmetricEncrypt(
        op_enc,
        core::ptr::from_ref(&label_attr),
        1,
        plain.as_ptr() as _,
        plain.len(),
        cipher.as_mut_ptr() as _,
        &mut cipher_len,
    );
    assert_eq!(res, TEE_SUCCESS);
    assert_eq!(cipher_len, cipher.len());

    TEE_FreeOperation(op_enc);

    let mut op_dec: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(
        &mut op_dec,
        TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256,
        TEE_MODE_DECRYPT,
        RSA_BITS,
    );
    assert_eq!(res, TEE_SUCCESS);
    let res = TEE_SetOperationKey(op_dec, keypair);
    assert_eq!(res, TEE_SUCCESS);

    let mut out = [0u8; 256];
    let mut out_len = out.len();
    let res = TEE_AsymmetricDecrypt(
        op_dec,
        core::ptr::from_ref(&label_attr),
        1,
        cipher.as_ptr() as _,
        cipher_len,
        out.as_mut_ptr() as _,
        &mut out_len,
    );
    assert_eq!(res, TEE_SUCCESS);
    assert_eq!(out_len, plain.len());
    assert_eq!(&out[..out_len], plain.as_slice());

    let mut wrong_label_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    TEE_InitRefAttribute(
        &mut wrong_label_attr,
        TEE_ATTR_RSA_OAEP_LABEL,
        b"WRONG_LABEL".as_ptr() as *const _,
        b"WRONG_LABEL".len(),
    );
    out_len = out.len();
    let res = TEE_AsymmetricDecrypt(
        op_dec,
        core::ptr::from_ref(&wrong_label_attr),
        1,
        cipher.as_ptr() as _,
        cipher_len,
        out.as_mut_ptr() as _,
        &mut out_len,
    );
    assert_eq!(res, TEE_ERROR_BAD_PARAMETERS);

    TEE_FreeOperation(op_dec);

    TEE_SUCCESS
}

fn cryp_rsa_pss_sha256_sign_verify_test() -> TEE_Result {
    const RSA_BITS: u32 = 2048;

    let mut keypair: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, RSA_BITS, &mut keypair);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!keypair.is_null());

    let res = TEE_GenerateKey(keypair, RSA_BITS, core::ptr::null(), 0);
    assert_eq!(res, TEE_SUCCESS);

    let mut pubkey: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, RSA_BITS, &mut pubkey);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!pubkey.is_null());

    let res = TEE_CopyObjectAttributes1(pubkey, keypair);
    assert_eq!(res, TEE_SUCCESS);

    let digest = b"SIGNATURE TEST SIGNATURE TEST SI";

    let mut op_sign: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(
        &mut op_sign,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
        TEE_MODE_SIGN,
        RSA_BITS,
    );
    assert_eq!(res, TEE_SUCCESS);
    let res = TEE_SetOperationKey(op_sign, keypair);
    assert_eq!(res, TEE_SUCCESS);

    let mut sig = [0u8; 256];
    let mut sig_len = sig.len();
    let res = TEE_AsymmetricSignDigest(
        op_sign,
        core::ptr::null(),
        0,
        digest.as_ptr() as _,
        digest.len(),
        sig.as_mut_ptr() as _,
        &mut sig_len,
    );
    assert_eq!(res, TEE_SUCCESS);

    let mut op_vfy: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(
        &mut op_vfy,
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
        TEE_MODE_VERIFY,
        RSA_BITS,
    );
    assert_eq!(res, TEE_SUCCESS);
    let res = TEE_SetOperationKey(op_vfy, pubkey);
    assert_eq!(res, TEE_SUCCESS);

    let res = TEE_AsymmetricVerifyDigest(
        op_vfy,
        core::ptr::null(),
        0,
        digest.as_ptr() as _,
        digest.len(),
        sig.as_ptr() as _,
        sig_len,
    );
    assert_eq!(res, TEE_SUCCESS);

    TEE_FreeOperation(op_sign);
    TEE_FreeOperation(op_vfy);

    TEE_SUCCESS
}

const SM4_BLOCK_SIZE: usize = 16;
const SM4_IV_SIZE: usize = 16;
const SM4_BIT_SIZE: usize = 128;
/// box 加密数据
///
/// # 参数
/// - `key`: 加密密钥字节切片
/// - `iv`: 初始化向量字节切片
/// - `plain_data`: 待加密的明文数据字节切片
///
/// # 返回
/// - `Ok(Vec<u8>)`: 加密后的密文数据
/// - `Err(Error)`: 加密过程中发生的错误
fn encrypt_box_data(key: &[u8], iv: &[u8], plain_data: &[u8]) -> TEE_Result {
    if key.len() != SM4_BLOCK_SIZE {
        println!("TA KyBox: invalid key size");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if iv.len() != SM4_IV_SIZE {
        println!("TA KyBox: invalid IV size");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if plain_data.is_empty() {
        println!("TA KyBox: invalid plaintext");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    let mut key_obj: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_SM4, SM4_BIT_SIZE as u32, &mut key_obj);
    if res != TEE_SUCCESS || key_obj.is_null() {
        println!("TA KyBox: failed to allocate transient object: {}", res);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    let mut attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };

    TEE_InitRefAttribute(
        &mut attr,
        TEE_ATTR_SECRET_VALUE,
        key.as_ptr() as *const _,
        key.len(),
    );
    let res = TEE_PopulateTransientObject(key_obj, &mut attr, 1);
    if res != TEE_SUCCESS {
        println!("TA KyBox: failed to populate key: {}", res);
        TEE_FreeTransientObject(key_obj);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(
        &mut operation_ptr,
        TEE_ALG_SM4_CTR,
        TEE_MODE_ENCRYPT,
        (SM4_BIT_SIZE) as u32,
    );
    if res != TEE_SUCCESS {
        println!("TA KyBox: failed to allocate operation: {}", res);
        TEE_FreeTransientObject(key_obj);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_SetOperationKey(operation_ptr, key_obj);

    TEE_CipherInit(operation_ptr, iv.as_ptr() as *const _, iv.len());

    const CHUNK_SIZE: usize = 1024 * 1024; // 1MB 分段
    let mut encrypted_data = Vec::with_capacity(plain_data.len() + SM4_BLOCK_SIZE);
    let mut processed = 0;

    while processed < plain_data.len() {
        let remaining = plain_data.len() - processed;
        let current_chunk_size = CHUNK_SIZE.min(remaining);

        let mut chunk_buffer = vec![0u8; current_chunk_size];
        let mut out_len = current_chunk_size + SM4_BLOCK_SIZE;

        let is_last_chunk = processed + current_chunk_size == plain_data.len();

        let res = if is_last_chunk {
            TEE_CipherDoFinal(
                operation_ptr,
                plain_data[processed..].as_ptr() as *const _,
                current_chunk_size,
                chunk_buffer.as_mut_ptr() as *mut _,
                &mut out_len,
            )
        } else {
            TEE_CipherUpdate(
                operation_ptr,
                plain_data[processed..].as_ptr() as *const _,
                current_chunk_size,
                chunk_buffer.as_mut_ptr() as *mut _,
                &mut out_len,
            )
        };
        if res != TEE_SUCCESS {
            TEE_FreeOperation(operation_ptr);
            TEE_FreeTransientObject(key_obj);
            println!(
                "TA KyBox: ENCRYPT: TEE_CipherUpdate/DoFinal failed: {}",
                res
            );
            return TEE_ERROR_BAD_PARAMETERS;
        }

        // 使用实际输出的长度截取有效数据
        chunk_buffer.truncate(out_len);
        encrypted_data.extend_from_slice(&chunk_buffer);

        processed += current_chunk_size;
    }

    TEE_FreeOperation(operation_ptr);
    TEE_FreeTransientObject(key_obj);

    TEE_SUCCESS
}

fn cryp_generate_random_number() -> TEE_Result {
    let mut buf1 = [0u8; 256];
    let mut buf2 = [0u8; 256];
    TEE_GenerateRandom(buf1.as_mut_ptr() as _, buf1.len());
    TEE_GenerateRandom(buf2.as_mut_ptr() as _, buf2.len());
    assert_ne!(buf1, buf2);
    TEE_SUCCESS
}

fn hkdf_sha256_derive_okm(
    ikm_obj: TEE_ObjectHandle,
    max_key_size: u32,
    salt: &[u8],
    info: &[u8],
    okm_len: usize,
) -> [u8; 42] {
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(
        &mut operation_ptr,
        TEE_ALG_HKDF_SHA256_DERIVE_KEY,
        TEE_MODE_DERIVE,
        max_key_size,
    );
    assert_eq!(res, TEE_SUCCESS);

    let res = TEE_SetOperationKey(operation_ptr, ikm_obj);
    assert_eq!(res, TEE_SUCCESS);

    let mut derived_key: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(
        TEE_TYPE_GENERIC_SECRET,
        (okm_len * 8) as u32,
        &mut derived_key,
    );
    assert_eq!(res, TEE_SUCCESS);
    assert!(!derived_key.is_null());

    let mut len_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    TEE_InitValueAttribute(&mut len_attr, TEE_ATTR_HKDF_OKM_LENGTH, okm_len as u32, 0);

    let mut salt_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    let mut info_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    TEE_InitRefAttribute(
        &mut salt_attr,
        TEE_ATTR_HKDF_SALT,
        salt.as_ptr() as *const _,
        salt.len(),
    );
    TEE_InitRefAttribute(
        &mut info_attr,
        TEE_ATTR_HKDF_INFO,
        info.as_ptr() as *const _,
        info.len(),
    );
    let attrs = [salt_attr, info_attr, len_attr];

    TEE_DeriveKey(
        operation_ptr,
        attrs.as_ptr(),
        attrs.len() as u32,
        derived_key,
    );

    let mut okm = [0u8; 42];
    let mut okm_sz = okm.len();
    let res = TEE_GetObjectBufferAttribute(
        derived_key,
        TEE_ATTR_SECRET_VALUE,
        okm.as_mut_ptr() as *mut core::ffi::c_void,
        &mut okm_sz,
    );
    assert_eq!(res, TEE_SUCCESS);
    assert_eq!(okm_sz, okm_len);

    TEE_FreeOperation(operation_ptr);
    TEE_FreeTransientObject(derived_key);

    okm
}

fn cryp_derive_key_hkdf_sha256_test() -> TEE_Result {
    // RFC 5869 HKDF-SHA256 test case 1 (tee_crypto/tests/hkdf.rs)
    let ikm = [0x0bu8; 22];
    let salt = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let okm_len = 42usize;
    let max_key_size = 2048u32;
    let expected_okm: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];

    let mut ikm_obj: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_HKDF_IKM, max_key_size, &mut ikm_obj);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!ikm_obj.is_null());

    let mut ikm_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    TEE_InitRefAttribute(
        &mut ikm_attr,
        TEE_ATTR_HKDF_IKM,
        ikm.as_ptr() as *const _,
        ikm.len(),
    );
    let res = TEE_PopulateTransientObject(ikm_obj, &ikm_attr, 1);
    assert_eq!(res, TEE_SUCCESS);

    let okm = hkdf_sha256_derive_okm(ikm_obj, max_key_size, &salt, &info, okm_len);
    assert_eq!(okm, expected_okm);

    TEE_FreeTransientObject(ikm_obj);

    TEE_SUCCESS
}

fn read_sm2_kep_pubkey_xy(key: TEE_ObjectHandle) -> ([u8; 32], [u8; 32]) {
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    let mut sz = x.len();
    let res = TEE_GetObjectBufferAttribute(
        key,
        TEE_ATTR_ECC_PUBLIC_VALUE_X,
        x.as_mut_ptr() as *mut core::ffi::c_void,
        &mut sz,
    );
    assert_eq!(res, TEE_SUCCESS);
    // Integer attributes may omit leading zeros; preserve the fixed-width value.
    assert!((1..=32).contains(&sz));
    x.copy_within(..sz, 32 - sz);
    x[..32 - sz].fill(0);
    sz = y.len();
    let res = TEE_GetObjectBufferAttribute(
        key,
        TEE_ATTR_ECC_PUBLIC_VALUE_Y,
        y.as_mut_ptr() as *mut core::ffi::c_void,
        &mut sz,
    );
    assert_eq!(res, TEE_SUCCESS);
    assert!((1..=32).contains(&sz));
    y.copy_within(..sz, 32 - sz);
    y[..32 - sz].fill(0);
    (x, y)
}

fn sm2_kep_derive_shared_secret(
    static_key: TEE_ObjectHandle,
    eph_key: TEE_ObjectHandle,
    is_initiator: bool,
    initiator_id: &[u8],
    responder_id: &[u8],
    peer_static_x: &[u8; 32],
    peer_static_y: &[u8; 32],
    peer_eph_x: &[u8; 32],
    peer_eph_y: &[u8; 32],
    conf_in: Option<&[u8; 32]>,
    conf_out: Option<&mut [u8; 32]>,
) -> [u8; 32] {
    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(&mut operation_ptr, TEE_ALG_SM2_KEP, TEE_MODE_DERIVE, 512);
    assert_eq!(res, TEE_SUCCESS);

    let res = TEE_SetOperationKey2(operation_ptr, static_key, eph_key);
    assert_eq!(res, TEE_SUCCESS);

    let mut derived_key: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, 256, &mut derived_key);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!derived_key.is_null());

    let mut user_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    TEE_InitValueAttribute(
        &mut user_attr,
        TEE_ATTR_SM2_KEP_USER,
        if is_initiator { 0 } else { 1 },
        0,
    );

    let mut peer_static_x_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    let mut peer_static_y_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    let mut peer_eph_x_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    let mut peer_eph_y_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    let mut initiator_id_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    let mut responder_id_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    let mut conf_in_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };
    let mut conf_out_attr = TEE_Attribute {
        attributeID: 0,
        content: unsafe { core::mem::zeroed() },
    };

    TEE_InitRefAttribute(
        &mut peer_static_x_attr,
        TEE_ATTR_ECC_PUBLIC_VALUE_X,
        peer_static_x.as_ptr() as *const _,
        peer_static_x.len(),
    );
    TEE_InitRefAttribute(
        &mut peer_static_y_attr,
        TEE_ATTR_ECC_PUBLIC_VALUE_Y,
        peer_static_y.as_ptr() as *const _,
        peer_static_y.len(),
    );
    TEE_InitRefAttribute(
        &mut peer_eph_x_attr,
        TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_X,
        peer_eph_x.as_ptr() as *const _,
        peer_eph_x.len(),
    );
    TEE_InitRefAttribute(
        &mut peer_eph_y_attr,
        TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_Y,
        peer_eph_y.as_ptr() as *const _,
        peer_eph_y.len(),
    );
    TEE_InitRefAttribute(
        &mut initiator_id_attr,
        TEE_ATTR_SM2_ID_INITIATOR,
        initiator_id.as_ptr() as *const _,
        initiator_id.len(),
    );
    TEE_InitRefAttribute(
        &mut responder_id_attr,
        TEE_ATTR_SM2_ID_RESPONDER,
        responder_id.as_ptr() as *const _,
        responder_id.len(),
    );

    let has_conf_in = conf_in.is_some();
    let has_conf_out = conf_out.is_some();

    if let Some(buf) = conf_in {
        TEE_InitRefAttribute(
            &mut conf_in_attr,
            TEE_ATTR_SM2_KEP_CONFIRMATION_IN,
            buf.as_ptr() as *const _,
            buf.len(),
        );
    }
    if let Some(buf) = conf_out {
        TEE_InitRefAttribute(
            &mut conf_out_attr,
            TEE_ATTR_SM2_KEP_CONFIRMATION_OUT,
            buf.as_mut_ptr() as *const _,
            buf.len(),
        );
    }

    // 数组必须活过 TEE_DeriveKey：match 分支里的局部数组在分支结束时就释放，
    // as_ptr() 传出去是悬空指针，内核会按垃圾 length 去拷用户内存。
    let mut attrs = [
        peer_static_x_attr,
        peer_static_y_attr,
        peer_eph_x_attr,
        peer_eph_y_attr,
        initiator_id_attr,
        responder_id_attr,
        user_attr,
        conf_in_attr,
        conf_out_attr,
    ];
    let attrs_count = match (has_conf_in, has_conf_out) {
        (false, false) => 7u32,
        (false, true) => {
            attrs[7] = conf_out_attr;
            8
        }
        (true, false) => 8,
        (true, true) => 9,
    };

    TEE_DeriveKey(operation_ptr, attrs.as_ptr(), attrs_count, derived_key);

    let mut shared = [0u8; 32];
    let mut shared_sz = shared.len();
    let res = TEE_GetObjectBufferAttribute(
        derived_key,
        TEE_ATTR_SECRET_VALUE,
        shared.as_mut_ptr() as *mut core::ffi::c_void,
        &mut shared_sz,
    );
    assert_eq!(res, TEE_SUCCESS);
    assert_eq!(shared_sz, 32);

    TEE_FreeOperation(operation_ptr);
    TEE_FreeTransientObject(derived_key);

    shared
}

/// SM2 KEP 密钥协商：Alice（发起方）与 Bob（响应方）应派生出相同的 32 字节共享密钥。
/// 对齐内核 `test_syscall_cryp_derive_key_sm2_kep` 的双边流程，无需 TA 侧参考实现。
fn cryp_derive_key_sm2_kep_test() -> TEE_Result {
    let initiator_id = b"Alice";
    let responder_id = b"Bob";

    let mut alice_static: TEE_ObjectHandle = core::ptr::null_mut();
    let mut alice_eph: TEE_ObjectHandle = core::ptr::null_mut();
    let mut bob_static: TEE_ObjectHandle = core::ptr::null_mut();
    let mut bob_eph: TEE_ObjectHandle = core::ptr::null_mut();

    for key in [
        &mut alice_static,
        &mut alice_eph,
        &mut bob_static,
        &mut bob_eph,
    ] {
        let res = TEE_AllocateTransientObject(TEE_TYPE_SM2_KEP_KEYPAIR, 256, key);
        assert_eq!(res, TEE_SUCCESS);
        assert!(!key.is_null());
        let res = TEE_GenerateKey(*key, 256, core::ptr::null(), 0);
        assert_eq!(res, TEE_SUCCESS);
    }

    let (bob_static_x, bob_static_y) = read_sm2_kep_pubkey_xy(bob_static);
    let (bob_eph_x, bob_eph_y) = read_sm2_kep_pubkey_xy(bob_eph);
    let (alice_static_x, alice_static_y) = read_sm2_kep_pubkey_xy(alice_static);
    let (alice_eph_x, alice_eph_y) = read_sm2_kep_pubkey_xy(alice_eph);

    let alice_shared = sm2_kep_derive_shared_secret(
        alice_static,
        alice_eph,
        true,
        initiator_id,
        responder_id,
        &bob_static_x,
        &bob_static_y,
        &bob_eph_x,
        &bob_eph_y,
        None,
        None,
    );

    let bob_shared = sm2_kep_derive_shared_secret(
        bob_static,
        bob_eph,
        false,
        initiator_id,
        responder_id,
        &alice_static_x,
        &alice_static_y,
        &alice_eph_x,
        &alice_eph_y,
        None,
        None,
    );

    assert_eq!(alice_shared, bob_shared);

    TEE_FreeTransientObject(alice_static);
    TEE_FreeTransientObject(alice_eph);
    TEE_FreeTransientObject(bob_static);
    TEE_FreeTransientObject(bob_eph);

    TEE_SUCCESS
}

/// SM2 KEP 带 confirmation：Alice 输出 conf_out，Bob 以之为 conf_in 并输出己方 conf_out。
/// 对齐内核 `test_syscall_cryp_derive_key_sm2_kep_with_confirmation`。
fn cryp_derive_key_sm2_kep_with_confirmation_test() -> TEE_Result {
    let initiator_id = b"Alice";
    let responder_id = b"Bob";

    let mut alice_static: TEE_ObjectHandle = core::ptr::null_mut();
    let mut alice_eph: TEE_ObjectHandle = core::ptr::null_mut();
    let mut bob_static: TEE_ObjectHandle = core::ptr::null_mut();
    let mut bob_eph: TEE_ObjectHandle = core::ptr::null_mut();

    for key in [
        &mut alice_static,
        &mut alice_eph,
        &mut bob_static,
        &mut bob_eph,
    ] {
        let res = TEE_AllocateTransientObject(TEE_TYPE_SM2_KEP_KEYPAIR, 256, key);
        assert_eq!(res, TEE_SUCCESS);
        assert!(!key.is_null());
        let res = TEE_GenerateKey(*key, 256, core::ptr::null(), 0);
        assert_eq!(res, TEE_SUCCESS);
    }

    let (bob_static_x, bob_static_y) = read_sm2_kep_pubkey_xy(bob_static);
    let (bob_eph_x, bob_eph_y) = read_sm2_kep_pubkey_xy(bob_eph);
    let (alice_static_x, alice_static_y) = read_sm2_kep_pubkey_xy(alice_static);
    let (alice_eph_x, alice_eph_y) = read_sm2_kep_pubkey_xy(alice_eph);

    let mut alice_conf_out = [0u8; 32];
    let alice_shared = sm2_kep_derive_shared_secret(
        alice_static,
        alice_eph,
        true,
        initiator_id,
        responder_id,
        &bob_static_x,
        &bob_static_y,
        &bob_eph_x,
        &bob_eph_y,
        None,
        Some(&mut alice_conf_out),
    );
    assert_ne!(alice_conf_out, [0u8; 32]);

    let mut bob_conf_out = [0u8; 32];
    let bob_shared = sm2_kep_derive_shared_secret(
        bob_static,
        bob_eph,
        false,
        initiator_id,
        responder_id,
        &alice_static_x,
        &alice_static_y,
        &alice_eph_x,
        &alice_eph_y,
        Some(&alice_conf_out),
        Some(&mut bob_conf_out),
    );
    assert_ne!(bob_conf_out, [0u8; 32]);
    assert_eq!(alice_shared, bob_shared);

    TEE_FreeTransientObject(alice_static);
    TEE_FreeTransientObject(alice_eph);
    TEE_FreeTransientObject(bob_static);
    TEE_FreeTransientObject(bob_eph);

    TEE_SUCCESS
}

fn cryp_key_free_test() -> TEE_Result {
    let mut key1: TEE_ObjectHandle = core::ptr::null_mut();
    let res = TEE_AllocateTransientObject(TEE_TYPE_SM4, 128, &mut key1);
    assert_eq!(res, TEE_SUCCESS);
    assert!(!key1.is_null());

    let res = TEE_GenerateKey(key1, 128, core::ptr::null(), 0);
    assert_eq!(res, TEE_SUCCESS);

    let mut operation_ptr: *mut TEE_OperationHandle = core::ptr::null_mut();
    let res = TEE_AllocateOperation(
        &mut operation_ptr,
        TEE_ALG_SM4_CBC_NOPAD,
        TEE_MODE_ENCRYPT,
        128,
    );
    assert_eq!(res, 0);

    let res = TEE_SetOperationKey(operation_ptr, key1);
    assert_eq!(res, TEE_SUCCESS);

    let internal_key = unsafe { (*operation_ptr).key1 };
    let mut buf = [0u8; 16];
    let mut sz = buf.len();
    let res = TEE_GetObjectBufferAttribute(
        internal_key,
        TEE_ATTR_SECRET_VALUE,
        buf.as_mut_ptr() as *mut core::ffi::c_void,
        &mut sz,
    );
    assert_eq!(res, TEE_SUCCESS);
    assert_eq!(sz, 16);

    TEE_FreeOperation(operation_ptr);

    let mut sz = buf.len();
    let res = TEE_GetObjectBufferAttribute1(
        internal_key,
        TEE_ATTR_SECRET_VALUE,
        buf.as_mut_ptr() as *mut core::ffi::c_void,
        &mut sz,
    );
    assert_ne!(
        res, TEE_SUCCESS,
        "operation internal key must not remain readable after TEE_FreeOperation"
    );

    TEE_SUCCESS
}
