// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! 安全指针操作模块，封装 unsafe 操作并提供错误处理
//!
//! **注意**: 此模块仅在 teec 模块内部使用，不对外公开。

use std::ptr::NonNull;

use crate::{Error, ErrorKind, ErrorOrigin, Result};

/// 创建统一的“参数错误” Error 实例（`BadParameters` + `API` 来源）。
///
/// 用于安全指针操作中所有因空指针/无效参数导致的错误，避免重复构造。
fn bad_params() -> Error {
    Error::new(ErrorKind::BadParameters).with_origin(ErrorOrigin::API)
}

/// 安全地解引用可变指针，返回 NonNull 包装
pub(super) fn deref_mut<T>(ptr: *mut T) -> Result<NonNull<T>> {
    NonNull::new(ptr).ok_or_else(bad_params)
}

/// 安全地解引用不可变指针，返回 NonNull 包装
pub(super) fn deref<T>(ptr: *const T) -> Result<NonNull<T>> {
    NonNull::new(ptr as *mut T).ok_or_else(bad_params)
}

/// 安全地向指针指向的内存写入值
#[allow(dead_code)]
pub(super) fn write_raw<T>(ptr: *mut T, value: T) -> Result<()> {
    let nn = NonNull::new(ptr).ok_or_else(bad_params)?;
    // SAFETY: `nn` 已通过上面的 `NonNull::new` 检查为非空。
    // 调用方保证传入的 `ptr` 的所有权/有效性，因此向 `nn.as_ptr()` 写入
    // `value` 是安全的（内存对齐正确且可写）。
    unsafe { nn.as_ptr().write(value) };
    Ok(())
}

/// 安全地从指针读取指定长度的数据到 Vec
pub(super) fn read_to_vec<T: Copy>(src: *const T, len: usize) -> Result<Vec<T>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if src.is_null() {
        return Err(bad_params());
    }
    let _nn = NonNull::new(src as *mut T).ok_or_else(bad_params)?;
    // SAFETY: 当 `len > 0` 时 `src` 已被检查为非空。调用方保证
    // `src..src+len` 可安全读取且内存对齐正确。
    let slice = unsafe { std::slice::from_raw_parts(src, len) };
    Ok(slice.to_vec())
}

/// 安全地将切片数据写入指针指向的内存
pub(super) fn write_from_slice<T: Copy>(dst: *mut T, src: &[T]) -> Result<()> {
    if dst.is_null() && !src.is_empty() {
        return Err(bad_params());
    }

    if src.is_empty() {
        return Ok(());
    }

    let _nn = NonNull::new(dst).ok_or_else(bad_params)?;
    // SAFETY: 当 `src` 非空时已检查 `dst` 为非空。调用方保证 `dst` 指向
    // `src.len()` 个可写元素，且内存对齐适合 `T`。
    let dst_slice = unsafe { std::slice::from_raw_parts_mut(dst, src.len()) };
    dst_slice.copy_from_slice(src);
    Ok(())
}

#[cfg(test)]
mod safe_ptr_tests {
    use super::*;

    #[test]
    fn test_read_to_vec_and_write_from_slice() {
        // 测试从指针读取数据到 Vec 和从切片写入到指针
        let arr = [1u8, 2, 3, 4, 5];
        let vec = read_to_vec(arr.as_ptr(), arr.len()).expect("从指针读取到 Vec 应该成功");
        assert_eq!(vec, arr.to_vec(), "从数组读取的数据应该与原始数组相同");

        let mut buf = [0u8; 5];
        write_from_slice(buf.as_mut_ptr(), &vec).expect("从切片写入指针应该成功");
        assert_eq!(buf.to_vec(), vec, "写入缓冲区后应该与原始数据相同");
    }

    #[test]
    fn test_deref_null() {
        use std::ptr;
        assert!(deref(ptr::null::<u8>()).is_err());
        assert!(deref_mut(ptr::null_mut::<u8>()).is_err());
    }

    #[test]
    fn test_write_from_slice_empty() {
        let mut buf = [0u8; 5];
        let empty_slice: &[u8] = &[];
        let result = write_from_slice(buf.as_mut_ptr(), empty_slice);
        assert!(result.is_ok());
    }

    #[test]
    fn test_read_to_vec_zero_length() {
        // 测试读取零长度数据
        let arr = [1u8, 2, 3];
        let result = read_to_vec(arr.as_ptr(), 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0, "零长度读取应该返回空向量");
    }

    #[test]
    fn test_write_from_slice_null_dst_with_empty_src() {
        use std::ptr;
        let empty_slice: &[u8] = &[];
        let result = write_from_slice(ptr::null_mut(), empty_slice);
        assert!(result.is_ok());
    }

    #[test]
    fn test_read_to_vec_large_size() {
        // 测试读取较大数据
        let large_arr = vec![42u8; 1000];
        let result = read_to_vec(large_arr.as_ptr(), large_arr.len());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1000);
    }

    #[test]
    fn test_write_from_slice_various_sizes() {
        // 测试不同大小的切片写入

        // 测试 1: 单字节
        let mut buf1 = [0u8; 1];
        let data1 = [1u8];
        assert!(write_from_slice(buf1.as_mut_ptr(), &data1).is_ok());
        assert_eq!(buf1[0], 1);

        // 测试 2: 中等大小
        let mut buf2 = [0u8; 100];
        let data2 = vec![42u8; 100];
        assert!(write_from_slice(buf2.as_mut_ptr(), &data2).is_ok());
        assert_eq!(buf2.to_vec(), data2);

        // 测试 3: 较大数据
        let mut buf3 = vec![0u8; 1000];
        let data3 = vec![99u8; 1000];
        assert!(write_from_slice(buf3.as_mut_ptr(), &data3).is_ok());
        assert_eq!(buf3, data3);
    }

    #[test]
    fn test_deref_and_deref_mut_consistency() {
        // 测试 deref 和 deref_mut 的一致性
        let mut value = 123u32;

        // 使用 deref 读取
        let const_ptr = &value as *const u32;
        let result_read = deref(const_ptr);
        assert!(result_read.is_ok());
        assert_eq!(unsafe { *result_read.unwrap().as_ptr() }, 123);

        // 使用 deref_mut 写入
        let mut_ptr = &mut value as *mut u32;
        let result_write = deref_mut(mut_ptr);
        assert!(result_write.is_ok());
        unsafe {
            *result_write.unwrap().as_ptr() = 456;
        }
        assert_eq!(value, 456);
    }
}
