// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! TEE 操作参数管理模块
//!
//! 提供安全的 TEEC_Operation 参数访问和转换功能。
//!
//! 此模块负责将 TEEC_Operation 中的参数（VALUE、MEMREF 等）转换为可序列化的格式，
//! 以便通过机密通信通道发送给 TA。MEMREF 参数引用的数据来自共享内存缓冲区，
//! 这些数据会被读取并序列化到请求数据包中，通过网络传输到 TA。

use log::{debug, warn};

use teec_protocol::{TEE_ParamType, TEE_Parameters};

use super::{safe_ptr, shared_memory::SharedMemoryManager, vmem};
use crate::{Error, ErrorKind, Result, raw};

/// 操作参数包装器，提供安全的操作参数访问
///
/// **注意**: 此结构体仅在 teec 模块内部使用，不对外公开。
pub(super) struct OperationParams<'a> {
    operation: &'a mut raw::TEEC_Operation,
}

impl<'a> OperationParams<'a> {
    /// 验证并包装 TEEC_Operation 指针
    pub(super) fn new(operation: *mut raw::TEEC_Operation) -> Result<Self> {
        let mut op_nn = safe_ptr::deref_mut(operation)?;
        // SAFETY: `op_nn` 已由 `deref_mut` 验证为非空。`as_mut()` 返回可变引用，
        // 生命周期与 `operation` 指向的对象绑定。
        let op_ref = unsafe { op_nn.as_mut() };

        Ok(Self { operation: op_ref })
    }

    /// 获取参数类型位掩码
    pub(super) fn param_types(&self) -> u32 {
        self.operation.paramTypes
    }

    /// 读取 VALUE 类型参数的 (a, b) 值
    pub(super) fn get_value(&self, idx: usize) -> Result<(u32, u32)> {
        if idx >= raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        let param = &self.operation.params[idx];
        // SAFETY: 从 `param.value` 读取简单的 `u32` 字段是安全的。
        unsafe { Ok((param.value.a, param.value.b)) }
    }

    /// 写入 VALUE 类型参数的 (a, b) 值
    pub(super) fn set_value(&mut self, idx: usize, a: u32, b: u32) -> Result<()> {
        if idx >= raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        let param = &mut self.operation.params[idx];
        param.value.a = a;
        param.value.b = b;

        Ok(())
    }

    /// 读取 TEMPREF 参数的数据缓冲区
    pub(super) fn get_tmpref_data(&self, idx: usize) -> Result<Vec<u8>> {
        if idx >= raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // SAFETY: `idx` 已做边界检查；`tmpref` 是 union 的有效成员，
        // 由 paramTypes 确定。
        let tmp = unsafe { &self.operation.params[idx].tmpref };

        if tmp.buffer.is_null() && tmp.size > 0 {
            warn!(
                "[HOST] get_tmpref_data: 参数 {idx} buffer 为空但 size={}，拒绝读取",
                tmp.size
            );
            return Err(Error::new(ErrorKind::BadParameters));
        }

        if tmp.size > 0 && !tmp.buffer.is_null() {
            // 按 CA 声明的 size 读取前，校验 [buffer, buffer+size) 完整
            // 位于单个可读 VMA 内，防止 size 大于实际分配导致越界读。
            if !vmem::range_readable(tmp.buffer as *const u8, tmp.size) {
                warn!(
                    "[HOST] get_tmpref_data: 参数 {idx} 区间校验拒绝 buffer={:p} size={}，拒绝读取",
                    tmp.buffer, tmp.size
                );
                return Err(Error::new(ErrorKind::BadParameters));
            }
            safe_ptr::read_to_vec(tmp.buffer as *const u8, tmp.size)
        } else {
            Ok(Vec::new())
        }
    }

    /// 写入 TEMPREF 参数并更新 size 字段
    pub(super) fn set_tmpref_data(&mut self, idx: usize, data: &[u8]) -> Result<()> {
        if idx >= raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // SAFETY: `idx` 已做边界检查；`tmpref` 是 union 的有效成员。
        let tmp = unsafe { &mut self.operation.params[idx].tmpref };

        if tmp.buffer.is_null() {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        let dest_len = data.len().min(tmp.size);
        if dest_len > 0 {
            if data.len() > tmp.size {
                warn!(
                    "set_tmpref_data: 响应数据长度 {} 超过 tmpref size {}，已截断",
                    data.len(),
                    tmp.size
                );
            }
            // 写回前校验目标区间完整位于单个可写 VMA 内，防止 CA 声明的
            // size 大于实际分配导致越界写 CA 进程内存。
            if !vmem::range_writable(tmp.buffer as *mut u8, dest_len) {
                return Err(Error::new(ErrorKind::BadParameters));
            }
            safe_ptr::write_from_slice(tmp.buffer as *mut u8, &data[..dest_len])?;
        }
        tmp.size = dest_len;

        Ok(())
    }

    /// 获取 MEMREF 参数的父内存标志（用于判断 IN/OUT 方向）
    pub(super) fn get_memref_parent_flags(&self, idx: usize) -> Result<u32> {
        if idx >= raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // SAFETY: `idx` 已做边界检查；`memref` 是 union 的有效成员。
        let mem: &raw::TEEC_RegisteredMemoryReference =
            unsafe { &self.operation.params[idx].memref };

        // parent 必须是本库分配/注册过的共享内存结构体；按地址校验（不解引用），
        // 对任意非法非空指针直接拒绝，避免解引用垃圾指针崩溃。
        if !SharedMemoryManager::is_registered(mem.parent) {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        let parent_nn = safe_ptr::deref(mem.parent)?;
        // SAFETY: `parent_nn` 已由 `deref` 验证为非空。
        let parent = unsafe { parent_nn.as_ref() };

        Ok(parent.flags)
    }

    /// 读取 WHOLE MEMREF 参数（从父共享内存缓冲区）
    ///
    /// 注意：这里读取的是本地缓冲区的数据，这些数据将被序列化并通过网络发送给 TA。
    pub(super) fn get_memref_data_whole(&self, idx: usize) -> Result<Vec<u8>> {
        if idx >= raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // SAFETY: `idx` 已做边界检查；`memref` 是 union 的有效成员。
        let mem: &raw::TEEC_RegisteredMemoryReference =
            unsafe { &self.operation.params[idx].memref };

        // parent 必须是本库分配/注册过的共享内存结构体；按地址校验（不解引用），
        // 对任意非法非空指针直接拒绝，避免解引用垃圾指针崩溃。
        if !SharedMemoryManager::is_registered(mem.parent) {
            warn!(
                "[HOST] get_memref_data_whole: 参数 {idx} parent={:p} 未注册为共享内存，拒绝读取",
                mem.parent
            );
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // 在持有 SHMS 读锁期间完成一致性校验和数据读取：
        // 1. 读取长度不能超过库内部 ShmEntry 记录的权威分配大小（CA 无法
        //    篡改），防止越界读取；
        // 2. 锁守卫在拷贝完成前不释放，期间并发的 TEEC_ReleaseSharedMemory
        //    会在 SHMS.remove 处阻塞，防止读取已释放内存（UAF）。
        SharedMemoryManager::read_buffer_locked(mem.parent, 0, mem.size)
    }

    /// 写入 WHOLE MEMREF 参数到父共享内存缓冲区
    ///
    /// 注意：这里写入的是本地缓冲区，这些数据将从 TA 返回的响应中反序列化得到。
    pub(super) fn set_memref_data_whole(&mut self, idx: usize, data: &[u8]) -> Result<()> {
        if idx >= raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // SAFETY: `idx` 已做边界检查；`memref` 是 union 的有效成员。
        let mem = unsafe { &self.operation.params[idx].memref };

        // parent 必须是本库分配/注册过的共享内存结构体；按地址校验（不解引用），
        // 对任意非法非空指针直接拒绝，避免解引用垃圾指针崩溃。
        if !SharedMemoryManager::is_registered(mem.parent) {
            warn!(
                "[HOST] set_memref_data_whole: 参数 {idx} parent={:p} 未注册为共享内存，拒绝写入",
                mem.parent
            );
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // 在持有 SHMS 读锁期间完成一致性校验和数据写入：
        // 1. 写入长度不能超过库内部 ShmEntry 记录的权威分配大小（CA 无法
        //    篡改），防止 TA 返回超长数据造成堆溢出；
        // 2. 锁守卫在写入完成前不释放，期间并发的 TEEC_ReleaseSharedMemory
        //    会被阻塞，防止写入已释放内存（UAF）。
        SharedMemoryManager::write_buffer_locked(mem.parent, 0, data)
    }

    /// 读取 PARTIAL MEMREF 参数（带方向标志检查）
    pub(super) fn get_memref_data_partial(&self, idx: usize, req_flags: u32) -> Result<Vec<u8>> {
        if idx >= raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // SAFETY: `idx` 已做边界检查；`memref` 是 union 的有效成员。
        let mem: &raw::TEEC_RegisteredMemoryReference =
            unsafe { &self.operation.params[idx].memref };

        // parent 必须是本库分配/注册过的共享内存结构体；按地址校验（不解引用），
        // 对任意非法非空指针直接拒绝，避免解引用垃圾指针崩溃。
        if !SharedMemoryManager::is_registered(mem.parent) {
            warn!(
                "[HOST] get_memref_data_partial: 参数 {idx} parent={:p} 未注册为共享内存，拒绝读取",
                mem.parent
            );
            return Err(Error::new(ErrorKind::BadParameters));
        }

        let parent_nn = safe_ptr::deref(mem.parent)?;
        // SAFETY: `parent_nn` 已由 `deref` 验证为非空。
        let parent = unsafe { parent_nn.as_ref() };

        if parent.flags & req_flags != req_flags {
            warn!(
                "[HOST] get_memref_data_partial: 参数 {idx} 方向标志不满足 flags=0x{:x} 需要=0x{:x}，拒绝读取",
                parent.flags, req_flags
            );
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // 在持有 SHMS 读锁期间完成一致性校验和数据读取：
        // 1. 读取区间（offset..offset+size）不能超出库内部 ShmEntry 记录的
        //    权威分配大小（CA 无法篡改），防止越界读取；
        // 2. 锁守卫在拷贝完成前不释放，期间并发的 TEEC_ReleaseSharedMemory
        //    会在 SHMS.remove 处阻塞，防止读取已释放内存（UAF）。
        SharedMemoryManager::read_buffer_locked(mem.parent, mem.offset, mem.size)
    }

    /// 写入 PARTIAL MEMREF 参数（带 offset 偏移）
    pub(super) fn set_memref_data_partial(&mut self, idx: usize, data: &[u8]) -> Result<()> {
        if idx >= raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // SAFETY: `idx` 已做边界检查；`memref` 是 union 的有效成员。
        let mem = unsafe { &self.operation.params[idx].memref };

        // parent 必须是本库分配/注册过的共享内存结构体；按地址校验（不解引用），
        // 对任意非法非空指针直接拒绝，避免解引用垃圾指针崩溃。
        if !SharedMemoryManager::is_registered(mem.parent) {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // 在持有 SHMS 读锁期间完成一致性校验和数据写入：
        // 1. 写入区间（offset..offset+len）不能超出库内部 ShmEntry 记录的
        //    权威分配大小（CA 无法篡改），与读取路径的边界校验对称，
        //    防止越界写入；
        // 2. 锁守卫在写入完成前不释放，期间并发的 TEEC_ReleaseSharedMemory
        //    会被阻塞，防止写入已释放内存（UAF）。
        SharedMemoryManager::write_buffer_locked(mem.parent, mem.offset, data)
    }

    pub(super) fn get_tmpref_size(&self, idx: usize) -> Result<usize> {
        if idx >= raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // SAFETY: `idx` 已做边界检查；`tmpref` 是 union 的有效成员。
        let tmp = unsafe { &self.operation.params[idx].tmpref };

        Ok(tmp.size)
    }

    pub(super) fn get_memref_size(&self, idx: usize) -> Result<usize> {
        if idx >= raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
            return Err(Error::new(ErrorKind::BadParameters));
        }

        // SAFETY: `idx` 已做边界检查；`memref` 是 union 的有效成员。
        let mem = unsafe { &self.operation.params[idx].memref };

        Ok(mem.size)
    }
}

/// 从 TEEC_Operation 构建协议参数
pub fn build_parameters_from_operation(
    operation: *mut raw::TEEC_Operation,
) -> Result<TEE_Parameters> {
    let op_params = OperationParams::new(operation)?;
    let param_types = op_params.param_types();
    let mut params = TEE_Parameters::default();

    let param_tuples = [
        (&mut params.0, 0),
        (&mut params.1, 1),
        (&mut params.2, 2),
        (&mut params.3, 3),
    ];

    for (param, idx) in param_tuples {
        let param_type = raw::TEEC_PARAM_TYPE_GET(param_types, idx);

        match param_type {
            raw::TEEC_NONE => {
                param.param_type = TEE_ParamType::None;
            }
            raw::TEEC_VALUE_INPUT => {
                param.param_type = TEE_ParamType::ValueInput;
                if let Ok((a, b)) = op_params.get_value(idx) {
                    param.param.values.a = a;
                    param.param.values.b = b;
                }
            }
            raw::TEEC_VALUE_OUTPUT => {
                // 输出参数只需设置类型，数据从 TEE 返回后填充
                param.param_type = TEE_ParamType::ValueOutput;
            }
            raw::TEEC_VALUE_INOUT => {
                param.param_type = TEE_ParamType::ValueInout;
                if let Ok((a, b)) = op_params.get_value(idx) {
                    param.param.values.a = a;
                    param.param.values.b = b;
                }
            }
            raw::TEEC_MEMREF_TEMP_INPUT => {
                param.param_type = TEE_ParamType::MemrefInput;
                param.param.data = op_params.get_tmpref_data(idx)?;
            }
            raw::TEEC_MEMREF_TEMP_OUTPUT => {
                param.param_type = TEE_ParamType::MemrefOutput;

                // 输出参数只需传递缓冲区大小，不需要传输实际数据
                // 注意：对于 MemrefOutput 参数，TA 可能需要知道 CA 期望的缓冲区大小。
                // 因此我们复用 values.a 字段传递 size 信息（这是一种特殊约定）。
                param.param.values.a = op_params.get_tmpref_size(idx)? as u32;

                debug!("TEEC_MEMREF_TEMP_OUTPUT: values.a={}", param.param.values.a);
            }
            raw::TEEC_MEMREF_TEMP_INOUT => {
                param.param_type = TEE_ParamType::MemrefInout;
                param.param.data = op_params.get_tmpref_data(idx)?;
            }
            raw::TEEC_MEMREF_WHOLE => {
                // 完整内存引用根据父内存标志确定方向
                const INOUT: u32 = raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT;
                let flags = op_params.get_memref_parent_flags(idx)? & INOUT;

                if flags == INOUT {
                    param.param_type = TEE_ParamType::MemrefInout;
                } else if flags & raw::TEEC_MEM_INPUT != 0 {
                    param.param_type = TEE_ParamType::MemrefInput;
                } else if flags & raw::TEEC_MEM_OUTPUT != 0 {
                    param.param_type = TEE_ParamType::MemrefOutput;

                    // 对于 OUTPUT 方向，通过 values.a 传递缓冲区大小（特殊约定）
                    param.param.values.a = op_params.get_memref_size(idx)? as u32;
                    debug!(
                        "TEEC_MEMREF_WHOLE OUTPUT: values.a={}",
                        param.param.values.a
                    );
                } else {
                    return Err(Error::new(ErrorKind::BadParameters));
                }

                if flags & raw::TEEC_MEM_INPUT != 0 {
                    param.param.data = op_params.get_memref_data_whole(idx)?;
                }
            }
            raw::TEEC_MEMREF_PARTIAL_INPUT => {
                param.param_type = TEE_ParamType::MemrefInput;
                let req_flags = raw::TEEC_MEM_INPUT;
                param.param.data = op_params.get_memref_data_partial(idx, req_flags)?;
            }
            raw::TEEC_MEMREF_PARTIAL_OUTPUT => {
                param.param_type = TEE_ParamType::MemrefOutput;

                // 输出参数只需传递缓冲区大小
                // 同 TEMP_OUTPUT，通过 values.a 传递 size（特殊约定）
                param.param.values.a = op_params.get_memref_size(idx)? as u32;

                debug!(
                    "TEEC_MEMREF_PARTIAL_OUTPUT: values.a={}",
                    param.param.values.a
                );
            }
            raw::TEEC_MEMREF_PARTIAL_INOUT => {
                param.param_type = TEE_ParamType::MemrefInout;
                let req_flags = raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT;
                param.param.data = op_params.get_memref_data_partial(idx, req_flags)?;
            }
            _ => {
                debug!("Unsupported parameter type: {param_type}");
                return Err(Error::new(ErrorKind::BadParameters));
            }
        }
    }

    Ok(params)
}

/// 将协议参数更新回 TEEC_Operation 结构。
///
/// 从 TA 返回的响应中提取参数数据，按原始 paramTypes 指示的方向写回：
/// - `VALUE_OUTPUT` / `VALUE_INOUT`：写回 (a, b) 值
/// - `MEMREF_TEMP_OUTPUT` / `MEMREF_TEMP_INOUT`：写回临时内存缓冲区
/// - `MEMREF_WHOLE`：写回整个共享内存缓冲区
/// - `MEMREF_PARTIAL_OUTPUT` / `MEMREF_PARTIAL_INOUT`：按 offset 写回部分区域
///
/// NONE 及纯输入参数不会被修改。
pub fn update_operation_from_parameters(
    operation: *mut raw::TEEC_Operation,
    params: TEE_Parameters,
) -> Result<()> {
    let mut op_params = OperationParams::new(operation)?;
    let param_types = op_params.param_types();
    let param_slice = [&params.0, &params.1, &params.2, &params.3];

    for (idx, param) in param_slice
        .iter()
        .enumerate()
        .take(raw::TEEC_CONFIG_PAYLOAD_REF_COUNT)
    {
        let param_type = raw::TEEC_PARAM_TYPE_GET(param_types, idx);

        match param_type {
            raw::TEEC_NONE
            | raw::TEEC_VALUE_INPUT
            | raw::TEEC_MEMREF_TEMP_INPUT
            | raw::TEEC_MEMREF_PARTIAL_INPUT => {
                // NONE 及纯输入参数无需更新
            }
            raw::TEEC_VALUE_OUTPUT | raw::TEEC_VALUE_INOUT => {
                let value = &param.param.values;
                op_params.set_value(idx, value.a, value.b)?;
            }
            raw::TEEC_MEMREF_TEMP_OUTPUT | raw::TEEC_MEMREF_TEMP_INOUT => {
                let data = &param.param.data;
                op_params.set_tmpref_data(idx, data)?;
            }
            raw::TEEC_MEMREF_WHOLE => {
                let data = &param.param.data;
                op_params.set_memref_data_whole(idx, data)?;
            }
            raw::TEEC_MEMREF_PARTIAL_OUTPUT | raw::TEEC_MEMREF_PARTIAL_INOUT => {
                let data = &param.param.data;
                op_params.set_memref_data_partial(idx, data)?;
            }
            _ => {
                debug!("Unsupported parameter type: {param_type}");
                return Err(Error::new(ErrorKind::BadParameters));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod operation_tests {
    use super::*;
    use std::ffi::c_void;

    #[test]
    fn test_operation_params_value() {
        // 测试值参数（Value 参数）
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [raw::TEEC_Parameter {
                value: raw::TEEC_Value { a: 1, b: 2 },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let mut op_params = OperationParams::new(op_ptr).unwrap();

        // 读取现有值
        let (a, b) = op_params.get_value(0).unwrap();
        assert_eq!((a, b), (1, 2), "应该能正确读取值参数");

        // 设置新值
        op_params.set_value(0, 10, 20).unwrap();
        let (a2, b2) = op_params.get_value(0).unwrap();
        assert_eq!((a2, b2), (10, 20), "应该能正确设置值参数");
    }

    #[test]
    fn test_operation_params_tmpref() {
        // 测试临时内存引用参数（TempMemoryReference）
        let mut tmp_buf = vec![0u8; 6];
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [raw::TEEC_Parameter {
                value: raw::TEEC_Value { a: 0, b: 0 },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        op.params[1] = raw::TEEC_Parameter {
            tmpref: raw::TEEC_TempMemoryReference {
                buffer: tmp_buf.as_mut_ptr() as *mut c_void,
                size: tmp_buf.len(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let mut op_params = OperationParams::new(op_ptr).unwrap();

        // 写入临时内存引用
        let to_write = [9u8, 8, 7];
        op_params.set_tmpref_data(1, &to_write).unwrap();
        assert_eq!(tmp_buf[0..3], to_write[..], "应该正确写入临时内存");

        // 读取临时内存引用
        let got = op_params.get_tmpref_data(1).unwrap();
        assert_eq!(got, to_write.to_vec(), "应该正确读取临时内存");
    }

    #[test]
    fn test_build_parameters_from_operation() {
        // 测试从 operation 构建参数
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_VALUE_INPUT,
            params: [raw::TEEC_Parameter {
                value: raw::TEEC_Value { a: 42, b: 100 },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let params = build_parameters_from_operation(op_ptr).unwrap();

        // TEE_Parameters 是元组结构体，检查第一个参数的类型
        assert_eq!(params.0.param_type as u32, raw::TEEC_VALUE_INPUT);
    }

    #[test]
    fn test_operation_params_index_boundary() {
        // 测试 OperationParams 的索引边界检查
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [raw::TEEC_Parameter {
                value: raw::TEEC_Value { a: 0, b: 0 },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let mut op_params = OperationParams::new(op_ptr).unwrap();

        // 测试所有有效索引 (0-3)
        for i in 0..raw::TEEC_CONFIG_PAYLOAD_REF_COUNT {
            // 这些调用应该成功（虽然可能返回默认值）
            let _ = op_params.get_value(i);
        }

        // 测试超出边界的索引
        assert!(
            op_params
                .get_value(raw::TEEC_CONFIG_PAYLOAD_REF_COUNT)
                .is_err(),
            "超出范围的索引应该返回错误"
        );
        assert!(
            op_params
                .set_value(raw::TEEC_CONFIG_PAYLOAD_REF_COUNT, 1, 2)
                .is_err(),
            "超出范围的索引设置应该返回错误"
        );
    }

    #[test]
    fn test_set_tmpref_null_buffer() {
        // 测试设置临时内存引用时缓冲区为空的情况
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [raw::TEEC_Parameter {
                tmpref: raw::TEEC_TempMemoryReference {
                    buffer: std::ptr::null_mut(),
                    size: 10, // 有大小但缓冲区为空
                },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let op_params = OperationParams::new(op_ptr).unwrap();

        // 尝试读取空缓冲区的临时内存引用
        assert!(
            op_params.get_tmpref_data(0).is_err(),
            "缓冲区为空但有大小应该返回错误"
        );
    }

    #[test]
    fn test_build_parameters_with_all_param_types() {
        // 测试 build_parameters_from_operation 支持的所有参数类型
        use teec_protocol::TEE_ParamType;

        // 创建一个包含各种参数类型的操作
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [unsafe { std::mem::zeroed() }; 4],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        // 测试 TEEC_NONE 类型
        op.paramTypes = raw::TEEC_PARAM_TYPES(
            raw::TEEC_NONE,
            raw::TEEC_NONE,
            raw::TEEC_NONE,
            raw::TEEC_NONE,
        );

        let params = build_parameters_from_operation(&mut op).unwrap();
        assert_eq!(params.0.param_type, TEE_ParamType::None);
        assert_eq!(params.1.param_type, TEE_ParamType::None);
        assert_eq!(params.2.param_type, TEE_ParamType::None);
        assert_eq!(params.3.param_type, TEE_ParamType::None);
    }

    #[test]
    fn test_update_operation_with_output_params() {
        // 测试 update_operation_from_parameters 的输出参数更新
        use teec_protocol::{TEE_Param, TEE_ParamType, TEE_Parameter, TEE_Value};

        // 为临时内存引用准备缓冲区
        let mut tmp_buffer = [0u8; 10];

        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_VALUE_OUTPUT,
                raw::TEEC_MEMREF_TEMP_OUTPUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                // param0: value 输出
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                // param1: temp memory reference 输出
                raw::TEEC_Parameter {
                    tmpref: raw::TEEC_TempMemoryReference {
                        buffer: tmp_buffer.as_mut_ptr() as *mut std::ffi::c_void,
                        size: tmp_buffer.len(),
                    },
                },
                // param2: none
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                // param3: none
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        // 创建模拟参数数据
        let params = TEE_Parameters(
            TEE_Parameter {
                param_type: TEE_ParamType::ValueOutput,
                param: TEE_Param {
                    values: TEE_Value { a: 100, b: 200 },
                    data: vec![],
                },
            },
            TEE_Parameter {
                param_type: TEE_ParamType::MemrefOutput,
                param: TEE_Param {
                    values: TEE_Value::default(),
                    data: vec![1, 2, 3],
                },
            },
            TEE_Parameter::default(),
            TEE_Parameter::default(),
        );

        let result = update_operation_from_parameters(&mut op, params);
        assert!(result.is_ok());

        // 验证值参数被更新 - 访问 union 字段需要 unsafe
        unsafe {
            assert_eq!(op.params[0].value.a, 100);
            assert_eq!(op.params[0].value.b, 200);
        }
    }

    #[test]
    fn test_operation_params_new_null_ptr() {
        // 测试 OperationParams::new 传入空指针（应该失败）
        let result = OperationParams::new(std::ptr::null_mut());
        assert!(result.is_err(), "空指针应该导致失败");
    }

    #[test]
    fn test_get_value_all_invalid_indices() {
        // 测试 get_value 的所有无效索引
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [raw::TEEC_Parameter {
                value: raw::TEEC_Value { a: 0, b: 0 },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let op_params = OperationParams::new(op_ptr).unwrap();

        // 测试刚好超出边界的索引
        assert!(
            op_params
                .get_value(raw::TEEC_CONFIG_PAYLOAD_REF_COUNT)
                .is_err()
        );

        // 测试远超出边界的索引
        assert!(op_params.get_value(100).is_err());
        assert!(op_params.get_value(usize::MAX).is_err());
    }

    #[test]
    fn test_set_value_all_invalid_indices() {
        // 测试 set_value 的所有无效索引
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [raw::TEEC_Parameter {
                value: raw::TEEC_Value { a: 0, b: 0 },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let mut op_params = OperationParams::new(op_ptr).unwrap();

        // 测试刚好超出边界的索引
        assert!(
            op_params
                .set_value(raw::TEEC_CONFIG_PAYLOAD_REF_COUNT, 1, 2)
                .is_err()
        );

        // 测试远超出边界的索引
        assert!(op_params.set_value(100, 1, 2).is_err());
        assert!(op_params.set_value(usize::MAX, 1, 2).is_err());
    }

    #[test]
    #[allow(unused_assignments)]
    fn test_get_tmpref_data_all_error_paths() {
        // 测试 get_tmpref_data 的所有错误路径
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [raw::TEEC_Parameter {
                tmpref: raw::TEEC_TempMemoryReference {
                    buffer: std::ptr::null_mut(),
                    size: 0,
                },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let op_params = OperationParams::new(op_ptr).unwrap();

        // 测试 1: 索引越界
        assert!(
            op_params
                .get_tmpref_data(raw::TEEC_CONFIG_PAYLOAD_REF_COUNT)
                .is_err()
        );
        assert!(op_params.get_tmpref_data(100).is_err());

        // 测试 2: 缓冲区为空但大小 > 0
        op.params[0] = raw::TEEC_Parameter {
            tmpref: raw::TEEC_TempMemoryReference {
                buffer: std::ptr::null_mut(),
                size: 10,
            },
        };
        assert!(op_params.get_tmpref_data(0).is_err());

        // 测试 3: 正常情况 - 缓冲区为空且大小为 0（应该返回空 Vec）
        op.params[0] = raw::TEEC_Parameter {
            tmpref: raw::TEEC_TempMemoryReference {
                buffer: std::ptr::null_mut(),
                size: 0,
            },
        };
        let result = op_params.get_tmpref_data(0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    #[allow(unused_assignments)]
    fn test_set_tmpref_data_all_error_paths() {
        // 测试 set_tmpref_data 的所有错误路径
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [raw::TEEC_Parameter {
                tmpref: raw::TEEC_TempMemoryReference {
                    buffer: std::ptr::null_mut(),
                    size: 0,
                },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let mut op_params = OperationParams::new(op_ptr).unwrap();

        // 测试 1: 索引越界
        let data = vec![1u8, 2, 3];
        assert!(
            op_params
                .set_tmpref_data(raw::TEEC_CONFIG_PAYLOAD_REF_COUNT, &data)
                .is_err()
        );
        assert!(op_params.set_tmpref_data(100, &data).is_err());

        // 测试 2: 正常写入（应该有缓冲区）
        let mut buffer = vec![0u8; 10];
        op.params[0] = raw::TEEC_Parameter {
            tmpref: raw::TEEC_TempMemoryReference {
                buffer: buffer.as_mut_ptr() as *mut std::ffi::c_void,
                size: buffer.len(),
            },
        };
        let small_data = vec![1u8, 2, 3];
        let result = op_params.set_tmpref_data(0, &small_data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_parameters_null_operation() {
        // 测试 build_parameters_from_operation 传入空指针
        let result = build_parameters_from_operation(std::ptr::null_mut());
        assert!(result.is_err(), "空指针应该导致失败");
    }

    #[test]
    fn test_update_operation_null_operation() {
        // 测试 update_operation_from_parameters 传入空指针
        use teec_protocol::{TEE_Param, TEE_ParamType, TEE_Parameter, TEE_Value};

        let params = TEE_Parameters(
            TEE_Parameter {
                param_type: TEE_ParamType::ValueOutput,
                param: TEE_Param {
                    values: TEE_Value { a: 100, b: 200 },
                    data: vec![],
                },
            },
            TEE_Parameter::default(),
            TEE_Parameter::default(),
            TEE_Parameter::default(),
        );

        let result = update_operation_from_parameters(std::ptr::null_mut(), params);
        assert!(result.is_err(), "空指针应该导致失败");
    }

    #[test]
    fn test_mixed_valid_and_invalid_operations() {
        // 测试混合有效和无效操作的场景
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_VALUE_INPUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 42, b: 100 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let mut op_params = OperationParams::new(op_ptr).unwrap();

        // 有效操作应该成功
        assert!(op_params.get_value(0).is_ok());
        assert!(op_params.set_value(0, 1, 2).is_ok());

        // 无效操作应该失败
        assert!(op_params.get_value(4).is_err());
        assert!(op_params.set_value(4, 1, 2).is_err());
    }

    #[test]
    fn test_memref_partial_operations() {
        // 测试 PARTIAL MEMREF 的读写操作
        use std::ptr;

        // 准备父共享内存：模拟 CA 先分配/注册共享内存，再构造 MEMREF
        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: 55,
                reg_mem: false,
                memref_null: false,
            },
        };
        let mut parent_shm = raw::TEEC_SharedMemory {
            buffer: ptr::null_mut(),
            size: 100,
            flags: raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT,
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                registered_fd: -1,
                shadow_buffer: ptr::null_mut(),
                alloced_size: 0,
                flags: 0,
            },
        };
        SharedMemoryManager::allocate(&mut ctx, &mut parent_shm, false).unwrap();
        // 填充已知数据 0..99
        let parent_data: Vec<u8> = (0u8..100).collect();
        unsafe {
            std::ptr::copy_nonoverlapping(parent_data.as_ptr(), parent_shm.buffer as *mut u8, 100);
        }

        // 创建带有 PARTIAL MEMREF 的操作
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_PARTIAL_INPUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    memref: raw::TEEC_RegisteredMemoryReference {
                        parent: &mut parent_shm as *mut _,
                        size: 10,
                        offset: 5,
                    },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let mut op_params = OperationParams::new(op_ptr).unwrap();

        // 测试读取 PARTIAL MEMREF
        let data = op_params.get_memref_data_partial(0, raw::TEEC_MEM_INPUT);
        assert!(data.is_ok());
        let data = data.unwrap();
        assert_eq!(data.len(), 10);
        // 验证读取的是偏移 5-14 的数据
        for (i, &byte) in data.iter().enumerate() {
            assert_eq!(byte, (i + 5) as u8);
        }

        // 测试写入 PARTIAL MEMREF
        let write_data = vec![0xFF; 10];
        let result = op_params.set_memref_data_partial(0, &write_data);
        assert!(result.is_ok());

        // 验证写入成功（数据写入注册后的 buffer）
        let buf = unsafe { std::slice::from_raw_parts(parent_shm.buffer as *const u8, 100) };
        for item in buf.iter().take(15).skip(5) {
            assert_eq!(*item, 0xFF);
        }

        // 清理，避免全局共享内存表残留
        SharedMemoryManager::release(&mut parent_shm);
    }

    #[test]
    fn test_build_parameters_memref_output() {
        // 测试 build_parameters_from_operation 处理 MEMREF_OUTPUT
        use std::ptr;

        let mut buffer = vec![0u8; 50];
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_TEMP_OUTPUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    tmpref: raw::TEEC_TempMemoryReference {
                        buffer: buffer.as_mut_ptr() as *mut _,
                        size: 50,
                    },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };

        let params = build_parameters_from_operation(&mut op).unwrap();
        assert_eq!(params.0.param_type, TEE_ParamType::MemrefOutput);
        // MEMREF_OUTPUT 不应该包含数据，只传递大小
        assert_eq!(params.0.param.data.len(), 0);
    }

    #[test]
    fn test_update_operation_memref_output() {
        // 测试 update_operation_from_parameters 更新 MEMREF 输出参数
        use std::ptr;
        use teec_protocol::{TEE_Param, TEE_Parameter};

        let mut output_buffer = vec![0u8; 20];
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_TEMP_OUTPUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    tmpref: raw::TEEC_TempMemoryReference {
                        buffer: output_buffer.as_mut_ptr() as *mut _,
                        size: 20,
                    },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };

        // 模拟 TA 返回的数据
        let returned_data = vec![0xAA; 10];
        let params = TEE_Parameters(
            TEE_Parameter {
                param_type: TEE_ParamType::MemrefOutput,
                param: TEE_Param {
                    data: returned_data.clone(),
                    values: Default::default(),
                },
            },
            Default::default(),
            Default::default(),
            Default::default(),
        );

        let result = update_operation_from_parameters(&mut op, params);
        assert!(result.is_ok());

        // 验证数据已写回缓冲区
        for (i, item) in output_buffer.iter().enumerate().take(10) {
            assert_eq!(*item, 0xAA, "output_buffer[{i}] should be 0xAA");
        }
    }

    #[test]
    #[allow(unused_assignments)]
    fn test_get_memref_parent_flags_errors() {
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [raw::TEEC_Parameter {
                value: raw::TEEC_Value { a: 0, b: 0 },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let op_params = OperationParams::new(op_ptr).unwrap();

        assert!(
            op_params
                .get_memref_parent_flags(raw::TEEC_CONFIG_PAYLOAD_REF_COUNT)
                .is_err()
        );

        op.params[0] = raw::TEEC_Parameter {
            memref: raw::TEEC_RegisteredMemoryReference {
                parent: std::ptr::null_mut(),
                size: 0,
                offset: 0,
            },
        };
        assert!(op_params.get_memref_parent_flags(0).is_err());
    }

    #[test]
    #[allow(unused_assignments)]
    fn test_set_memref_data_whole_errors() {
        use std::ptr;

        // 注册父共享内存（flags=INPUT），未注册的 parent 会先被登记校验拒绝，
        // 无法走到 buffer 为 null 的检查；注册后再置空 buffer 验证该防御分支。
        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: 57,
                reg_mem: false,
                memref_null: false,
            },
        };
        let mut parent_shm = raw::TEEC_SharedMemory {
            buffer: ptr::null_mut(),
            size: 10,
            flags: raw::TEEC_MEM_INPUT,
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                registered_fd: -1,
                shadow_buffer: ptr::null_mut(),
                alloced_size: 0,
                flags: 0,
            },
        };
        SharedMemoryManager::allocate(&mut ctx, &mut parent_shm, false).unwrap();

        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [raw::TEEC_Parameter {
                value: raw::TEEC_Value { a: 0, b: 0 },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let mut op_params = OperationParams::new(op_ptr).unwrap();

        // null parent
        op.params[0] = raw::TEEC_Parameter {
            memref: raw::TEEC_RegisteredMemoryReference {
                parent: ptr::null_mut(),
                size: 10,
                offset: 0,
            },
        };
        assert!(op_params.set_memref_data_whole(0, &[1u8, 2]).is_err());

        // registered parent but null buffer
        op.params[0] = raw::TEEC_Parameter {
            memref: raw::TEEC_RegisteredMemoryReference {
                parent: &mut parent_shm as *mut _,
                size: 10,
                offset: 0,
            },
        };
        let orig_buffer = parent_shm.buffer;
        parent_shm.buffer = ptr::null_mut();
        assert!(op_params.set_memref_data_whole(0, &[1u8, 2]).is_err());
        parent_shm.buffer = orig_buffer;

        // 清理，避免全局共享内存表残留
        SharedMemoryManager::release(&mut parent_shm);
    }

    #[test]
    fn test_memref_unregistered_parent_rejected() {
        // 未登记的非空 parent：指向有效的栈上结构体，但从未通过
        // SharedMemoryManager 分配/注册。加固后所有 memref 访问器应
        // 在解引用前按地址登记校验将其拒绝（此前会成功解引用）。
        use std::ptr;

        let mut buf = vec![0u8; 64];
        let unregistered_shm = raw::TEEC_SharedMemory {
            buffer: buf.as_mut_ptr() as *mut _,
            size: 64,
            flags: raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT,
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                registered_fd: -1,
                shadow_buffer: ptr::null_mut(),
                alloced_size: 0,
                flags: 0,
            },
        };

        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_WHOLE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    memref: raw::TEEC_RegisteredMemoryReference {
                        parent: &unregistered_shm as *const _ as *mut _,
                        size: 8,
                        offset: 0,
                    },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let mut op_params = OperationParams::new(op_ptr).unwrap();

        assert!(
            op_params.get_memref_parent_flags(0).is_err(),
            "未登记 parent 应被 get_memref_parent_flags 拒绝"
        );
        assert!(
            op_params.get_memref_data_whole(0).is_err(),
            "未登记 parent 应被 get_memref_data_whole 拒绝"
        );
        assert!(
            op_params.set_memref_data_whole(0, &[1u8, 2]).is_err(),
            "未登记 parent 应被 set_memref_data_whole 拒绝"
        );
        // 覆盖 build_parameters_from_operation 的 MEMREF_WHOLE 路径
        assert!(build_parameters_from_operation(op_ptr).is_err());
    }

    #[test]
    fn test_memref_oversize_rejected() {
        // 已注册 parent 但请求读写长度超过 parent.size：必须被拒绝，
        // 防止越界读写。
        use std::ptr;

        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: 58,
                reg_mem: false,
                memref_null: false,
            },
        };
        let mut parent_shm = raw::TEEC_SharedMemory {
            buffer: ptr::null_mut(),
            size: 16,
            flags: raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT,
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                registered_fd: -1,
                shadow_buffer: ptr::null_mut(),
                alloced_size: 0,
                flags: 0,
            },
        };
        SharedMemoryManager::allocate(&mut ctx, &mut parent_shm, false).unwrap();

        // WHOLE：读 mem.size=32 > parent.size=16
        let mut op_whole = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_WHOLE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    memref: raw::TEEC_RegisteredMemoryReference {
                        parent: &mut parent_shm as *mut _,
                        size: 32,
                        offset: 0,
                    },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };
        {
            let op_ptr = &mut op_whole as *mut _;
            let mut op_params = OperationParams::new(op_ptr).unwrap();
            assert!(
                op_params.get_memref_data_whole(0).is_err(),
                "WHOLE 读取超过 parent.size 应被拒绝"
            );
            assert!(
                op_params.set_memref_data_whole(0, &[1u8; 32]).is_err(),
                "WHOLE 写入超过 parent.size 应被拒绝"
            );
        }

        // PARTIAL：offset=12 + len=8 > parent.size=16
        let mut op_partial = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_PARTIAL_INOUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    memref: raw::TEEC_RegisteredMemoryReference {
                        parent: &mut parent_shm as *mut _,
                        size: 16,
                        offset: 12,
                    },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };
        {
            let op_ptr = &mut op_partial as *mut _;
            let mut op_params = OperationParams::new(op_ptr).unwrap();
            assert!(
                op_params.set_memref_data_partial(0, &[1u8; 8]).is_err(),
                "PARTIAL 写入 offset+len 超过 parent.size 应被拒绝"
            );
        }

        // 清理，避免全局共享内存表残留
        SharedMemoryManager::release(&mut parent_shm);
    }

    #[test]
    #[allow(unused_assignments)]
    fn test_get_memref_data_partial_errors() {
        use std::ptr;

        // 注册父共享内存（flags=INPUT），使 flag mismatch 分支真实可达；
        // 未注册的 parent 会在登记校验处被拒绝，无法走到标志位检查。
        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: 56,
                reg_mem: false,
                memref_null: false,
            },
        };
        let mut parent_shm = raw::TEEC_SharedMemory {
            buffer: ptr::null_mut(),
            size: 20,
            flags: raw::TEEC_MEM_INPUT,
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                registered_fd: -1,
                shadow_buffer: ptr::null_mut(),
                alloced_size: 0,
                flags: 0,
            },
        };
        SharedMemoryManager::allocate(&mut ctx, &mut parent_shm, false).unwrap();

        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: 0,
            params: [raw::TEEC_Parameter {
                value: raw::TEEC_Value { a: 0, b: 0 },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let op_params = OperationParams::new(op_ptr).unwrap();

        // index out of bounds
        assert!(
            op_params
                .get_memref_data_partial(raw::TEEC_CONFIG_PAYLOAD_REF_COUNT, 0)
                .is_err()
        );

        // null parent
        op.params[0] = raw::TEEC_Parameter {
            memref: raw::TEEC_RegisteredMemoryReference {
                parent: ptr::null_mut(),
                size: 10,
                offset: 0,
            },
        };
        assert!(op_params.get_memref_data_partial(0, 0).is_err());

        // flag mismatch (parent has INPUT only, request OUTPUT)
        op.params[0] = raw::TEEC_Parameter {
            memref: raw::TEEC_RegisteredMemoryReference {
                parent: &mut parent_shm as *mut _,
                size: 5,
                offset: 0,
            },
        };
        assert!(
            op_params
                .get_memref_data_partial(0, raw::TEEC_MEM_OUTPUT)
                .is_err()
        );

        // 清理，避免全局共享内存表残留
        SharedMemoryManager::release(&mut parent_shm);
    }

    #[test]
    fn test_memref_tampered_parent_size_rejected() {
        // CA 篡改 parent.size 场景：分配 16 字节后将 parent.size 放大为
        // 4096，memref 边界校验必须以 imp.alloced_size（权威分配大小）为准
        // 拒绝越界读写，而不是被放大后的 parent.size 蒙骗。
        use std::ptr;

        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: 59,
                reg_mem: false,
                memref_null: false,
            },
        };
        let mut parent_shm = raw::TEEC_SharedMemory {
            buffer: ptr::null_mut(),
            size: 16,
            flags: raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT,
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                registered_fd: -1,
                shadow_buffer: ptr::null_mut(),
                alloced_size: 0,
                flags: 0,
            },
        };
        SharedMemoryManager::allocate(&mut ctx, &mut parent_shm, false).unwrap();
        assert_eq!(parent_shm.imp.alloced_size, 16);

        // 模拟恶意/缺陷 CA 在分配后放大公开的 size 字段
        parent_shm.size = 4096;

        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_WHOLE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    memref: raw::TEEC_RegisteredMemoryReference {
                        parent: &mut parent_shm as *mut _,
                        size: 32,
                        offset: 0,
                    },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let mut op_params = OperationParams::new(op_ptr).unwrap();

        // 32 <= 篡改后的 parent.size(4096)，但 > 实际分配 16：必须拒绝
        assert!(
            op_params.set_memref_data_whole(0, &[1u8; 32]).is_err(),
            "TA 返回数据超过实际分配大小（尽管 parent.size 被放大）应被拒绝"
        );
        assert!(
            op_params.get_memref_data_whole(0).is_err(),
            "读取长度超过实际分配大小（尽管 parent.size 被放大）应被拒绝"
        );

        // 清理，避免全局共享内存表残留
        SharedMemoryManager::release(&mut parent_shm);
    }

    #[test]
    fn test_memref_tampered_alloced_size_rejected() {
        // CA 篡改 imp.alloced_size 场景：分配 16 字节后将 imp.alloced_size
        // 放大为 4096。该字段与 parent.size 一样位于 CA 可写内存，不可作为
        // 权威边界；边界校验必须取自库内部 ShmEntry 记录的实际分配大小，
        // 拒绝越界读写。
        use std::ptr;

        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: 60,
                reg_mem: false,
                memref_null: false,
            },
        };
        let mut parent_shm = raw::TEEC_SharedMemory {
            buffer: ptr::null_mut(),
            size: 16,
            flags: raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT,
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                registered_fd: -1,
                shadow_buffer: ptr::null_mut(),
                alloced_size: 0,
                flags: 0,
            },
        };
        SharedMemoryManager::allocate(&mut ctx, &mut parent_shm, false).unwrap();
        assert_eq!(parent_shm.imp.alloced_size, 16);

        // 模拟恶意/缺陷 CA 在分配后放大 imp.alloced_size
        parent_shm.imp.alloced_size = 4096;

        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_WHOLE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    memref: raw::TEEC_RegisteredMemoryReference {
                        parent: &mut parent_shm as *mut _,
                        size: 32,
                        offset: 0,
                    },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let mut op_params = OperationParams::new(op_ptr).unwrap();

        // 32 <= 被篡改的 imp.alloced_size(4096)，但 > ShmEntry 记录的 16：
        // 必须以库内部权威大小为准拒绝
        assert!(
            op_params.get_memref_data_whole(0).is_err(),
            "读取长度超过库内部记录的实际分配大小（尽管 alloced_size 被篡改）应被拒绝"
        );
        assert!(
            op_params.set_memref_data_whole(0, &[1u8; 32]).is_err(),
            "写入长度超过库内部记录的实际分配大小（尽管 alloced_size 被篡改）应被拒绝"
        );

        // 清理，避免全局共享内存表残留
        SharedMemoryManager::release(&mut parent_shm);
    }

    #[test]
    fn test_memref_tampered_buffer_pointer_rejected() {
        // CA 将 parent.buffer 改指向其他（更小的）缓冲区：权威大小查询中的
        // buffer 指针一致性校验应拒绝，防止绕过边界校验后向小缓冲区越界写。
        use std::ptr;

        let mut ctx = raw::TEEC_Context {
            imp: raw::TEEC_Context__Imp {
                fd: 61,
                reg_mem: false,
                memref_null: false,
            },
        };
        let mut parent_shm = raw::TEEC_SharedMemory {
            buffer: ptr::null_mut(),
            size: 16,
            flags: raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT,
            imp: raw::TEEC_SharedMemory__Imp {
                id: -1,
                registered_fd: -1,
                shadow_buffer: ptr::null_mut(),
                alloced_size: 0,
                flags: 0,
            },
        };
        SharedMemoryManager::allocate(&mut ctx, &mut parent_shm, false).unwrap();

        // 模拟 CA 将 buffer 改指向一个 4 字节的栈缓冲区
        let mut small_buf = [0u8; 4];
        let orig_buffer = parent_shm.buffer;
        parent_shm.buffer = small_buf.as_mut_ptr() as *mut _;

        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_WHOLE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    memref: raw::TEEC_RegisteredMemoryReference {
                        parent: &mut parent_shm as *mut _,
                        size: 8,
                        offset: 0,
                    },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };

        let op_ptr: *mut raw::TEEC_Operation = &mut op;
        let mut op_params = OperationParams::new(op_ptr).unwrap();

        // 8 <= 库内权威大小 16，但 buffer 已被改指向 4 字节缓冲区：必须拒绝
        assert!(
            op_params.get_memref_data_whole(0).is_err(),
            "buffer 与登记指针不一致时应被拒绝"
        );
        assert!(
            op_params.set_memref_data_whole(0, &[1u8; 8]).is_err(),
            "buffer 与登记指针不一致时写入应被拒绝"
        );

        // 恢复并清理，避免全局共享内存表残留
        parent_shm.buffer = orig_buffer;
        SharedMemoryManager::release(&mut parent_shm);
    }

    #[test]
    fn test_build_parameters_value_inout() {
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_VALUE_INOUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 77, b: 88 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        let params = build_parameters_from_operation(&mut op).unwrap();
        assert_eq!(params.0.param_type, TEE_ParamType::ValueInout);
        assert_eq!(params.0.param.values.a, 77);
        assert_eq!(params.0.param.values.b, 88);
    }

    #[test]
    fn test_build_parameters_tmpref_input() {
        let mut buf = vec![10u8, 20, 30];
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_TEMP_INPUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    tmpref: raw::TEEC_TempMemoryReference {
                        buffer: buf.as_mut_ptr() as *mut _,
                        size: buf.len(),
                    },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        let params = build_parameters_from_operation(&mut op).unwrap();
        assert_eq!(params.0.param_type, TEE_ParamType::MemrefInput);
        assert_eq!(params.0.param.data, buf);
    }

    #[test]
    fn test_build_parameters_memref_partial_output() {
        use std::ptr;

        let mut buf = vec![0u8; 30];
        let mut parent_shm = raw::TEEC_SharedMemory {
            buffer: buf.as_mut_ptr() as *mut _,
            size: 30,
            flags: raw::TEEC_MEM_OUTPUT,
            imp: raw::TEEC_SharedMemory__Imp {
                id: 1,
                registered_fd: -1,
                shadow_buffer: ptr::null_mut(),
                alloced_size: 30,
                flags: 1,
            },
        };

        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_PARTIAL_OUTPUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [
                raw::TEEC_Parameter {
                    memref: raw::TEEC_RegisteredMemoryReference {
                        parent: &mut parent_shm as *mut _,
                        size: 10,
                        offset: 0,
                    },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
                raw::TEEC_Parameter {
                    value: raw::TEEC_Value { a: 0, b: 0 },
                },
            ],
            imp: raw::TEEC_Operation__Imp {
                session: ptr::null_mut(),
            },
        };

        let params = build_parameters_from_operation(&mut op).unwrap();
        assert_eq!(params.0.param_type, TEE_ParamType::MemrefOutput);
        assert_eq!(params.0.param.data.len(), 0);
    }

    #[test]
    fn test_build_parameters_unsupported_type() {
        let mut op = raw::TEEC_Operation {
            started: 0,
            paramTypes: raw::TEEC_PARAM_TYPES(
                0x4, // unsupported type (4 is not a valid TEEC param type)
                raw::TEEC_NONE,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
            params: [raw::TEEC_Parameter {
                value: raw::TEEC_Value { a: 0, b: 0 },
            }; raw::TEEC_CONFIG_PAYLOAD_REF_COUNT],
            imp: raw::TEEC_Operation__Imp {
                session: std::ptr::null_mut(),
            },
        };

        assert!(build_parameters_from_operation(&mut op).is_err());
    }
}
