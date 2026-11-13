// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! rust-libteec CA 示例程序
//!
//! 演示如何使用 rust-libteec 库与 TEE Trusted Application 进行交互
//! 展示所有 TEEC 参数类型的使用方法

#![allow(non_camel_case_types)]

use std::{
    ffi::c_void,
    io::{Error, ErrorKind},
    mem, ptr,
};

use num_enum::{FromPrimitive, IntoPrimitive};
use uuid::Uuid;

use cc_teec::{
    TEEC_AllocateSharedMemory, TEEC_CloseSession, TEEC_FinalizeContext, TEEC_InitializeContext,
    TEEC_InvokeCommand, TEEC_OpenSession, TEEC_RegisterSharedMemory, TEEC_ReleaseSharedMemory, raw,
};

const EXAMPLE_TA_UUID: &str = "9b28392f-39d2-497d-91af-b6600e3d6a3e";

#[derive(FromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum Command {
    // VALUE 类型
    ValueInputOutput = 0, // VALUE_INPUT + VALUE_OUTPUT
    ValueInout = 1,       // VALUE_INOUT

    // MEMREF TEMP 类型
    MemrefTempInputOutput = 10, // TEMP_INPUT + TEMP_OUTPUT
    MemrefTempInout = 11,       // TEMP_INOUT

    // MEMREF WHOLE 类型
    MemrefWholeInputOutput = 20, // WHOLE_INPUT + WHOLE_OUTPUT
    MemrefWholeInout = 21,       // WHOLE_INOUT

    // MEMREF PARTIAL 类型
    MemrefPartialInputOutput = 30, // PARTIAL_INPUT + PARTIAL_OUTPUT
    MemrefPartialInout = 31,       // PARTIAL_INOUT

    // 混合参数
    MixedParams = 100,

    #[default]
    Unknown = 0xFF,
}

type Result<T> = std::result::Result<T, Error>;

/// TEE 客户端会话封装结构
///
/// 使用 RAII 模式管理 TEE Context 和 Session 的生命周期，确保资源正确释放。
struct Client_Session {
    /// TEE 上下文指针，使用 Box 包裹的原因：
    /// 1. TEEC_InitializeContext 需要可变指针，Box 提供稳定的内存地址
    /// 2. Box 确保 ctx 在堆上分配，避免栈上的生命周期问题
    /// 3. Drop 实现中需要调用 TEEC_FinalizeContext，Box 保证指针有效性
    ctx: Box<raw::TEEC_Context>,
    /// TEE 会话结构，由 TEEC_OpenSession 初始化
    session: raw::TEEC_Session,
}

impl Client_Session {
    fn new(uuid: &raw::TEEC_UUID) -> Result<Self> {
        // SAFETY: `TEEC_Context` 和 `TEEC_Session` 是 POD 类型，没有无效的位模式。
        // `mem::zeroed()` 在这里是安全的，因为这些结构体只包含整数和指针。
        let mut ctx: Box<raw::TEEC_Context> = Box::new(unsafe { mem::zeroed() });
        let mut session: raw::TEEC_Session = unsafe { mem::zeroed() };
        let mut origin = 0_u32;

        let res = TEEC_InitializeContext(ptr::null(), ctx.as_mut());
        if res != raw::TEEC_SUCCESS {
            return Err(Error::from_raw_os_error(res as i32));
        }

        let res = TEEC_OpenSession(
            ctx.as_mut(),
            &mut session,
            uuid,
            raw::TEEC_LOGIN_PUBLIC,
            ptr::null(),
            ptr::null_mut(),
            &mut origin,
        );

        if res != raw::TEEC_SUCCESS {
            TEEC_FinalizeContext(ctx.as_mut());
            return Err(Error::from_raw_os_error(res as i32));
        }

        Ok(Self { ctx, session })
    }

    fn invoke_command(&self, cmd_id: u32, op: &mut raw::TEEC_Operation) -> Result<()> {
        let mut origin = 0_u32;
        let res = TEEC_InvokeCommand(&self.session as *const _ as *mut _, cmd_id, op, &mut origin);

        if res != raw::TEEC_SUCCESS {
            return Err(Error::from_raw_os_error(res as i32));
        }

        Ok(())
    }

    /// 获取 TEE Context 的可变引用
    fn context_mut(&mut self) -> &mut raw::TEEC_Context {
        self.ctx.as_mut()
    }
}

impl Drop for Client_Session {
    fn drop(&mut self) {
        TEEC_CloseSession(&mut self.session);
        TEEC_FinalizeContext(self.ctx.as_mut());
    }
}

fn main() -> Result<()> {
    let uuid = Uuid::parse_str(EXAMPLE_TA_UUID)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "无效 UUID"))?;
    let teec_uuid = uuid_to_teec_uuid(&uuid)?;
    let mut session = Client_Session::new(&teec_uuid)?;

    value_types(&session)?;
    memref_temp_types(&session)?;
    memref_whole(&mut session)?;
    memref_partial(&mut session)?;
    mixed_params(&session)?;

    Ok(())
}

// VALUE 类型演示
fn value_types(session: &Client_Session) -> Result<()> {
    println!("\nVALUE 参数类型");

    // VALUE_INPUT + VALUE_OUTPUT: 计算两数之和
    {
        // SAFETY: `TEEC_Operation` 是 POD 类型，零初始化是有效的。
        let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };

        op.paramTypes = raw::TEEC_PARAM_TYPES(
            raw::TEEC_VALUE_INPUT,
            raw::TEEC_VALUE_OUTPUT,
            raw::TEEC_NONE,
            raw::TEEC_NONE,
        );
        op.params[0].value.a = 100;
        op.params[0].value.b = 200;

        session.invoke_command(Command::ValueInputOutput.into(), &mut op)?;

        // SAFETY: `InvokeCommand` 成功后，`params[1]` 包含有效的 VALUE 输出。
        // TA 保证为 VALUE_OUTPUT 命令写入 `value.a`。
        let result = unsafe { op.params[1].value.a };
        println!("  VALUE_INPUT+OUTPUT: {} + {} = {}", 100, 200, result);
    }

    // VALUE_INOUT: 数值翻倍
    {
        // SAFETY: `TEEC_Operation` 是 POD 类型，零初始化是有效的。
        let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };

        op.paramTypes = raw::TEEC_PARAM_TYPES(
            raw::TEEC_VALUE_INOUT,
            raw::TEEC_NONE,
            raw::TEEC_NONE,
            raw::TEEC_NONE,
        );
        op.params[0].value.a = 42;
        op.params[0].value.b = 99;

        session.invoke_command(Command::ValueInout.into(), &mut op)?;

        // SAFETY: `InvokeCommand` 成功后，`params[0]` 包含有效的 VALUE 输出。
        // TA 保证将翻倍后的值写入 `value.a` 和 `value.b`。
        let a_out = unsafe { op.params[0].value.a };
        let b_out = unsafe { op.params[0].value.b };
        println!("  VALUE_INOUT: (42, 99) → ({}, {})", a_out, b_out);
    }

    Ok(())
}

// MEMREF TEMP 类型演示
fn memref_temp_types(session: &Client_Session) -> Result<()> {
    println!("\nMEMREF TEMP 参数类型");

    // TEMP_INPUT + TEMP_OUTPUT: 输入数据，TA 返回递增序列
    {
        let input_data = vec![1u8, 2, 3, 4, 5];
        let mut output_data = vec![0u8; 16];

        // SAFETY: `TEEC_Operation` 是 POD 类型，零初始化是有效的。
        let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };

        op.paramTypes = raw::TEEC_PARAM_TYPES(
            raw::TEEC_MEMREF_TEMP_INPUT,
            raw::TEEC_MEMREF_TEMP_OUTPUT,
            raw::TEEC_NONE,
            raw::TEEC_NONE,
        );
        op.params[0].tmpref.buffer = input_data.as_ptr() as *mut _;
        op.params[0].tmpref.size = input_data.len();
        op.params[1].tmpref.buffer = output_data.as_mut_ptr() as *mut _;
        op.params[1].tmpref.size = output_data.len();

        session.invoke_command(Command::MemrefTempInputOutput.into(), &mut op)?;

        println!(
            "  TEMP_INPUT+OUTPUT: {:?} → {:?}",
            input_data,
            &output_data[..8]
        );
    }

    // TEMP_INOUT: 按位取反
    {
        let mut inout_data: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD];

        // SAFETY: `TEEC_Operation` 是 POD 类型，零初始化是有效的。
        let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };

        op.paramTypes = raw::TEEC_PARAM_TYPES(
            raw::TEEC_MEMREF_TEMP_INOUT,
            raw::TEEC_NONE,
            raw::TEEC_NONE,
            raw::TEEC_NONE,
        );
        op.params[0].tmpref.buffer = inout_data.as_mut_ptr() as *mut _;
        op.params[0].tmpref.size = inout_data.len();

        session.invoke_command(Command::MemrefTempInout.into(), &mut op)?;
        println!(
            "  TEMP_INOUT: {:?} → {:?}",
            [0xAA, 0xBB, 0xCC, 0xDD],
            inout_data
        );
    }

    Ok(())
}

// MEMREF WHOLE INPUT + OUTPUT 演示
fn memref_whole_input_output(session: &mut Client_Session) -> Result<()> {
    let input_data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    let output_size = 8;

    // 分配输入共享内存
    let mut input_shm =
        allocate_shared_memory(session.context_mut(), input_data.len(), raw::TEEC_MEM_INPUT)?;
    copy_to_shm(&input_data, &input_shm);

    // 分配输出共享内存
    let mut output_shm =
        allocate_shared_memory(session.context_mut(), output_size, raw::TEEC_MEM_OUTPUT)?;

    // 创建操作：参数0为INPUT，参数1为OUTPUT
    // SAFETY: `TEEC_Operation` 是 POD 类型，零初始化是有效的。
    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_MEMREF_WHOLE,
        raw::TEEC_MEMREF_WHOLE,
        raw::TEEC_NONE,
        raw::TEEC_NONE,
    );
    op.params[0].memref.parent = &mut input_shm as *mut _;
    op.params[0].memref.size = input_data.len();
    op.params[1].memref.parent = &mut output_shm as *mut _;
    op.params[1].memref.size = output_size;

    session.invoke_command(Command::MemrefWholeInputOutput.into(), &mut op)?;

    let output_data = read_from_shm(&output_shm, output_size);
    println!("  WHOLE_INPUT+OUTPUT: {:?} → {:?}", input_data, output_data);

    TEEC_ReleaseSharedMemory(&mut input_shm);
    TEEC_ReleaseSharedMemory(&mut output_shm);

    Ok(())
}

// MEMREF WHOLE INOUT 演示（使用 AllocateSharedMemory）
fn memref_whole_inout_allocated(session: &mut Client_Session) -> Result<()> {
    let mut data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    let original = data.clone();
    let flags = raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT;
    let mut shm = allocate_shared_memory(session.context_mut(), data.len(), flags)?;

    copy_to_shm(&data, &shm);

    let mut op = create_memref_operation(&mut shm, data.len());

    session.invoke_command(Command::MemrefWholeInout.into(), &mut op)?;

    copy_from_shm(&shm, &mut data);

    println!("  WHOLE_INOUT (Alloc): {:?} → {:?}", original, data);

    TEEC_ReleaseSharedMemory(&mut shm);

    Ok(())
}

// MEMREF WHOLE INOUT 演示（使用 RegisterSharedMemory）
fn memref_whole_inout_registered(session: &mut Client_Session) -> Result<()> {
    let mut data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    let original = data.clone();
    let flags = raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT;

    // 注册栈上分配的缓冲区为共享内存
    let mut shm = register_shared_memory(
        session.context_mut(),
        data.as_mut_ptr() as *mut c_void,
        data.len(),
        flags,
    )?;

    let mut op = create_memref_operation(&mut shm, data.len());
    session.invoke_command(Command::MemrefWholeInout.into(), &mut op)?;

    // RegisterSharedMemory 直接操作 CA 的栈内存，TA 修改后数据应自动可见
    // 但通过 vsock-manager 通信时，数据经过序列化/反序列化，需要手动同步
    copy_from_shm(&shm, &mut data);

    println!("  WHOLE_INOUT (Register): {:?} → {:?}", original, data);

    TEEC_ReleaseSharedMemory(&mut shm);

    Ok(())
}

fn memref_whole(session: &mut Client_Session) -> Result<()> {
    println!("\nMEMREF WHOLE 参数类型");
    memref_whole_input_output(session)?;
    memref_whole_inout_allocated(session)?;
    memref_whole_inout_registered(session)?;
    Ok(())
}

fn allocate_shared_memory(
    ctx: &mut raw::TEEC_Context,
    size: usize,
    flags: u32,
) -> Result<raw::TEEC_SharedMemory> {
    // SAFETY: `TEEC_SharedMemory` 是 POD 类型，零初始化是有效的。
    let mut shm: raw::TEEC_SharedMemory = unsafe { mem::zeroed() };
    shm.size = size;
    shm.flags = flags;

    let res = TEEC_AllocateSharedMemory(ctx, &mut shm);
    if res != raw::TEEC_SUCCESS {
        return Err(Error::from_raw_os_error(res as i32));
    }

    Ok(shm)
}

// 注册已有的内存块为共享内存
fn register_shared_memory(
    ctx: &mut raw::TEEC_Context,
    buffer: *mut c_void,
    size: usize,
    flags: u32,
) -> Result<raw::TEEC_SharedMemory> {
    // SAFETY: `TEEC_SharedMemory` 是 POD 类型，零初始化是有效的。
    let mut shm: raw::TEEC_SharedMemory = unsafe { mem::zeroed() };
    shm.buffer = buffer;
    shm.size = size;
    shm.flags = flags;

    let res = TEEC_RegisterSharedMemory(ctx, &mut shm);
    if res != raw::TEEC_SUCCESS {
        return Err(Error::from_raw_os_error(res as i32));
    }

    Ok(shm)
}

// 复制数据到共享内存
fn copy_to_shm(data: &[u8], shm: &raw::TEEC_SharedMemory) {
    // SAFETY:
    // - `data.as_ptr()` 对读取 `data.len()` 字节有效（来自 slice 保证）
    // - `shm.buffer` 对写入有效（由 TEEC_AllocateSharedMemory 分配或注册）
    // - 源和目标不重叠（不同的内存区域）
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), shm.buffer as *mut u8, data.len());
    }
}

// 从共享内存复制数据到缓冲区
fn copy_from_shm(shm: &raw::TEEC_SharedMemory, data: &mut [u8]) {
    // SAFETY:
    // - `shm.buffer` 对读取有效（已分配/注册的共享内存）
    // - `data.as_mut_ptr()` 对写入 `data.len()` 字节有效（来自可变 slice）
    // - 源和目标不重叠
    unsafe {
        ptr::copy_nonoverlapping(shm.buffer as *const u8, data.as_mut_ptr(), data.len());
    }
}

// 从共享内存读取数据
fn read_from_shm(shm: &raw::TEEC_SharedMemory, size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    // SAFETY:
    // - `shm.buffer` 对读取 `size` 字节有效（共享内存保证）
    // - `data.as_mut_ptr()` 对写入有效（新分配的 Vec）
    // - 源和目标不重叠
    unsafe {
        ptr::copy_nonoverlapping(shm.buffer as *const u8, data.as_mut_ptr(), size);
    }
    data
}

// 从共享内存指定偏移量读取数据
fn read_from_shm_offset(shm: &raw::TEEC_SharedMemory, offset: usize, size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    // SAFETY:
    // - `(shm.buffer as *const u8).add(offset)` 在边界内（调用者确保 offset + size <= shm.size）
    // - `data.as_mut_ptr()` 对写入有效（新分配的 Vec）
    // - 源和目标不重叠
    unsafe {
        ptr::copy_nonoverlapping(
            (shm.buffer as *const u8).add(offset),
            data.as_mut_ptr(),
            size,
        );
    }
    data
}

// 复制数据到共享内存指定偏移量
fn copy_to_shm_offset(data: &[u8], shm: &raw::TEEC_SharedMemory, offset: usize) {
    // SAFETY:
    // - `data.as_ptr()` 对读取有效（来自 slice 保证）
    // - `(shm.buffer as *mut u8).add(offset)` 在边界内（调用者确保 offset + data.len() <= shm.size）
    // - 源和目标不重叠
    unsafe {
        ptr::copy_nonoverlapping(
            data.as_ptr(),
            (shm.buffer as *mut u8).add(offset),
            data.len(),
        );
    }
}

// 创建 MEMREF 操作参数
fn create_memref_operation(shm: &mut raw::TEEC_SharedMemory, size: usize) -> raw::TEEC_Operation {
    // SAFETY: `TEEC_Operation` 是 POD 类型，零初始化是有效的。
    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_MEMREF_WHOLE,
        raw::TEEC_NONE,
        raw::TEEC_NONE,
        raw::TEEC_NONE,
    );
    op.params[0].memref.parent = shm;
    op.params[0].memref.size = size;
    op
}

// MEMREF PARTIAL INPUT + OUTPUT 演示
fn memref_partial_input_output(
    session: &mut Client_Session,
    shm: &mut raw::TEEC_SharedMemory,
    page_size: usize,
) -> Result<()> {
    let input_data = vec![0x10, 0x20, 0x30, 0x40];
    let output_size = 8;
    let input_offset = 0; // 使用共享内存的起始区域
    let output_offset = page_size; // 使用共享内存的第 2 个页（偏移 4096）

    // 将输入数据复制到共享内存的指定偏移位置
    copy_to_shm_offset(&input_data, shm, input_offset);

    // SAFETY: `TEEC_Operation` 是 POD 类型，零初始化是有效的。
    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_MEMREF_PARTIAL_INPUT,
        raw::TEEC_MEMREF_PARTIAL_OUTPUT,
        raw::TEEC_NONE,
        raw::TEEC_NONE,
    );
    // 参数 0: PARTIAL INPUT
    op.params[0].memref.parent = shm;
    op.params[0].memref.offset = input_offset;
    op.params[0].memref.size = input_data.len();
    // 参数 1: PARTIAL OUTPUT
    op.params[1].memref.parent = shm;
    op.params[1].memref.offset = output_offset;
    op.params[1].memref.size = output_size;

    session.invoke_command(Command::MemrefPartialInputOutput.into(), &mut op)?;

    // 从共享内存的指定偏移位置读取结果
    let output_data = read_from_shm_offset(shm, output_offset, output_size);
    println!(
        "  PARTIAL_INPUT+OUTPUT:\toffset[0]={:?} → offset[{}]={:?}",
        input_data, output_offset, output_data
    );

    Ok(())
}

// MEMREF PARTIAL INOUT 演示
fn memref_partial_inout(
    session: &mut Client_Session,
    shm: &mut raw::TEEC_SharedMemory,
    page_size: usize,
) -> Result<()> {
    let data = vec![0x01, 0x02, 0x03, 0x04];
    let key = 0x55u8;
    let original = data.clone();

    let offset = 2 * page_size; // 使用共享内存的第 3 个页（偏移 8192）

    // 将数据复制到共享内存的指定偏移位置
    copy_to_shm_offset(&data, shm, offset);

    // SAFETY: `TEEC_Operation` 是 POD 类型，零初始化是有效的。
    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };

    // 混合参数：VALUE_INPUT + MEMREF_PARTIAL_INOUT
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_VALUE_INPUT,
        raw::TEEC_MEMREF_PARTIAL_INOUT,
        raw::TEEC_NONE,
        raw::TEEC_NONE,
    );
    op.params[0].value.a = key as u32;
    // PARTIAL 参数：只引用共享内存的一部分
    op.params[1].memref.parent = shm;
    op.params[1].memref.offset = offset;
    op.params[1].memref.size = data.len();

    session.invoke_command(Command::MemrefPartialInout.into(), &mut op)?;

    // 从共享内存的指定偏移位置读取 XOR 加密后的结果
    let result = read_from_shm_offset(shm, offset, data.len());
    println!(
        "  PARTIAL_INOUT: offset[{}]={:?} ^ 0x{:02X} → {:?}",
        offset, original, key, result
    );

    Ok(())
}

fn memref_partial(session: &mut Client_Session) -> Result<()> {
    println!("\nMEMREF PARTIAL 参数类型");
    // 分配共享内存（需要足够大以支持多个 PARTIAL 引用）
    // 内存布局：
    //   [0 ~ 4095]       : PARTIAL INPUT 使用的区域
    //   [4096 ~ 8191]    : PARTIAL OUTPUT 使用的区域
    //   [8192 ~ 12287]   : PARTIAL INOUT 使用的区域
    //   [12288 ~ 32767]  : 未使用
    let page_size = 4096;
    let shm_size = 8 * page_size; // 32KB
    let mut shm = allocate_shared_memory(
        session.context_mut(),
        shm_size,
        raw::TEEC_MEM_INPUT | raw::TEEC_MEM_OUTPUT,
    )?;

    memref_partial_input_output(session, &mut shm, page_size)?;
    memref_partial_inout(session, &mut shm, page_size)?;

    TEEC_ReleaseSharedMemory(&mut shm);

    Ok(())
}

// 混合参数演示
fn mixed_params(session: &Client_Session) -> Result<()> {
    println!("\n混合参数示例");
    let input_data = vec![10u8, 20, 30, 40, 50];
    let mut output_hash = vec![0u8; 4];

    // SAFETY: `TEEC_Operation` 是 POD 类型，零初始化是有效的。
    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_VALUE_INOUT,
        raw::TEEC_MEMREF_TEMP_INPUT,
        raw::TEEC_MEMREF_TEMP_OUTPUT,
        raw::TEEC_VALUE_OUTPUT,
    );

    op.params[0].value.a = 7; // counter
    op.params[1].tmpref.buffer = input_data.as_ptr() as *mut _;
    op.params[1].tmpref.size = input_data.len();
    op.params[2].tmpref.buffer = output_hash.as_mut_ptr() as *mut _;
    op.params[2].tmpref.size = output_hash.len();

    session.invoke_command(Command::MixedParams.into(), &mut op)?;

    let counter = unsafe { op.params[0].value.a };
    let status = unsafe { op.params[3].value.a };
    let processed = unsafe { op.params[3].value.b };

    println!("  输入: counter={}, data={:?}", 7, input_data);
    println!(
        "  输出: counter={}, hash=0x{:02X}{:02X}{:02X}{:02X}, status=0x{:08X}, bytes={}",
        counter, output_hash[3], output_hash[2], output_hash[1], output_hash[0], status, processed
    );

    Ok(())
}

fn uuid_to_teec_uuid(uuid: &Uuid) -> Result<raw::TEEC_UUID> {
    let (time_low, time_mid, time_hi_and_version, clock_seq_and_node) = uuid.as_fields();

    Ok(raw::TEEC_UUID {
        timeLow: time_low,
        timeMid: time_mid,
        timeHiAndVersion: time_hi_and_version,
        clockSeqAndNode: *clock_seq_and_node,
    })
}
