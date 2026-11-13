// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//
// This file was modified by KylinSoft Co., Ltd. on 2025.

//! 此模块定义了 GlobalPlatform TEE 客户端 API 规范的常量、类型和结构体。

#![allow(non_camel_case_types, non_snake_case)]

use std::ffi::{c_int, c_void};

/// 定义在打开会话或调用命令的操作负载中可用的内存引用数量。
pub const TEEC_CONFIG_PAYLOAD_REF_COUNT: usize = 4;

/// 定义单个数据内存块（包括 API 分配和 API 注册内存）的最大字节大小。
/// 这里没有一个通用的合理值（限制取决于具体配置），因此在本实现中
/// 不会强制任何限制。
pub const TEEC_CONFIG_SHAREDMEM_MAX_SIZE: u64 = u64::MAX;

/// 未使用该参数
pub const TEEC_NONE: u32 = 0x00000000;

/// 参数为 TEEC_Value，作为输入传递
pub const TEEC_VALUE_INPUT: u32 = 0x00000001;

/// 参数为 TEEC_Value，作为输出传递
pub const TEEC_VALUE_OUTPUT: u32 = 0x00000002;

/// 参数为 TEEC_Value，既作为输入又作为输出，同时具备 TEEC_VALUE_INPUT 和 TEEC_VALUE_OUTPUT 的语义
pub const TEEC_VALUE_INOUT: u32 = 0x00000003;

/// 参数为 TEEC_TempMemoryReference，描述一段在操作期间需要临时注册的内存区域，且为输入
pub const TEEC_MEMREF_TEMP_INPUT: u32 = 0x00000005;

/// 与 TEEC_MEMREF_TEMP_INPUT 类似，但内存引用为输出。实现可以在某些用例中更新 size 字段以反映所需的输出大小
pub const TEEC_MEMREF_TEMP_OUTPUT: u32 = 0x00000006;

/// 临时内存引用，同时作为输入和输出
pub const TEEC_MEMREF_TEMP_INOUT: u32 = 0x00000007;

/// 参数为已注册的内存引用，指向其父内存块的整个区域。该参数结构为 TEEC_RegisteredMemoryReference，
/// 实现必须只读取 parent 字段，并且在操作完成后可选择更新 size 字段
pub const TEEC_MEMREF_WHOLE: u32 = 0x0000000C;

/// 已注册内存引用，指向父内存块的部分区域，且为输入
pub const TEEC_MEMREF_PARTIAL_INPUT: u32 = 0x0000000D;

/// 已注册内存引用，指向父内存块的部分区域，且为输出
pub const TEEC_MEMREF_PARTIAL_OUTPUT: u32 = 0x0000000E;

/// 已注册内存引用，指向父内存块的部分区域，同时作为输入和输出
pub const TEEC_MEMREF_PARTIAL_INOUT: u32 = 0x0000000F;

/// 内存可用于将数据从客户端应用传递给受信任应用（TA）
pub const TEEC_MEM_INPUT: u32 = 0x00000001;

/// 内存可用于将数据从受信任应用（TA）传回客户端应用
pub const TEEC_MEM_OUTPUT: u32 = 0x00000002;

/// 操作成功
pub const TEEC_SUCCESS: u32 = 0x00000000;

/// 一般性错误，原因不明确
pub const TEEC_ERROR_GENERIC: u32 = 0xFFFF0000;

/// 访问权限不足
pub const TEEC_ERROR_ACCESS_DENIED: u32 = 0xFFFF0001;

/// 操作被取消
pub const TEEC_ERROR_CANCEL: u32 = 0xFFFF0002;

/// 并发访问导致冲突
pub const TEEC_ERROR_ACCESS_CONFLICT: u32 = 0xFFFF0003;

/// 传入的数据超过请求操作允许的大小
pub const TEEC_ERROR_EXCESS_DATA: u32 = 0xFFFF0004;

/// 输入数据格式无效
pub const TEEC_ERROR_BAD_FORMAT: u32 = 0xFFFF0005;

/// 输入参数无效
pub const TEEC_ERROR_BAD_PARAMETERS: u32 = 0xFFFF0006;

/// 当前状态下不允许执行该操作
pub const TEEC_ERROR_BAD_STATE: u32 = 0xFFFF0007;

/// 未找到请求的数据项
pub const TEEC_ERROR_ITEM_NOT_FOUND: u32 = 0xFFFF0008;

/// 请求的操作应存在但尚未实现
pub const TEEC_ERROR_NOT_IMPLEMENTED: u32 = 0xFFFF0009;

/// 请求的操作在本实现中不受支持
pub const TEEC_ERROR_NOT_SUPPORTED: u32 = 0xFFFF000A;

/// 缺少预期的数据
pub const TEEC_ERROR_NO_DATA: u32 = 0xFFFF000B;

/// 系统资源耗尽
pub const TEEC_ERROR_OUT_OF_MEMORY: u32 = 0xFFFF000C;

/// 系统正忙于处理其他任务
pub const TEEC_ERROR_BUSY: u32 = 0xFFFF000D;

/// 与远端通信失败
pub const TEEC_ERROR_COMMUNICATION: u32 = 0xFFFF000E;

/// 检测到安全错误
pub const TEEC_ERROR_SECURITY: u32 = 0xFFFF000F;

/// 提供的缓冲区太短，无法容纳输出
pub const TEEC_ERROR_SHORT_BUFFER: u32 = 0xFFFF0010;

/// 由 Trusted User Interface 规范定义：外部事件导致用户界面操作被中止
pub const TEEC_ERROR_EXTERNAL_CANCEL: u32 = 0xFFFF0011;

/// TA 已终止
pub const TEEC_ERROR_TARGET_DEAD: u32 = 0xFFFF3024;

/// 错误来源于 TEE 客户端 API 的实现
pub const TEEC_ORIGIN_API: u32 = 0x00000001;

/// 错误来源于底层通信栈（负责连接 rich OS 与 TEE）
pub const TEEC_ORIGIN_COMMS: u32 = 0x00000002;

/// 错误来源于通用的 TEE 代码
pub const TEEC_ORIGIN_TEE: u32 = 0x00000003;

/// 错误来源于受信任应用（TA）代码
pub const TEEC_ORIGIN_TRUSTED_APP: u32 = 0x00000004;

/// 不提供登录数据
pub const TEEC_LOGIN_PUBLIC: u32 = 0x00000000;

/// 提供关于运行客户端进程的用户的登录数据
pub const TEEC_LOGIN_USER: u32 = 0x00000001;

/// 提供关于运行客户端进程的组的登录数据
pub const TEEC_LOGIN_GROUP: u32 = 0x00000002;

/// 提供关于运行的客户端应用自身的登录数据
pub const TEEC_LOGIN_APPLICATION: u32 = 0x00000004;

/// 提供关于用户和运行的客户端应用自身的登录数据
pub const TEEC_LOGIN_USER_APPLICATION: u32 = 0x00000005;

/// 提供关于组和运行的客户端应用自身的登录数据
pub const TEEC_LOGIN_GROUP_APPLICATION: u32 = 0x00000006;

/// 根据提供的类型对 `paramTypes` 进行编码
///
/// 该函数根据四个参数的类型值，将它们编码为一个组合的参数类型值，
/// 用于描述 TEEC_Operation 中参数数组中每个参数的类型。
///
/// # 参数
///
/// * `p0` - 第一个参数的类型
/// * `p1` - 第二个参数的类型
/// * `p2` - 第三个参数的类型
/// * `p3` - 第四个参数的类型
///
/// # 返回值
///
/// 返回编码后的参数类型组合值
#[inline]
pub fn TEEC_PARAM_TYPES(p0: u32, p1: u32, p2: u32, p3: u32) -> u32 {
    let tmp = p1 << 4 | p2 << 8 | p3 << 12;
    p0 | tmp
}

/// 从 `paramType` 中获取第 i 个参数的类型
///
/// 该函数从组合的参数类型值中提取指定位置参数的类型，
/// 用于解析 TEEC_Operation 中参数数组中特定参数的类型。
///
/// # 参数
///
/// * `p` - `paramType` 的值
/// * `i` - 要获取类型的第 i 个参数（从 0 开始）
///
/// # 返回值
///
/// 返回指定位置参数的类型值
#[inline]
pub fn TEEC_PARAM_TYPE_GET(p: u32, i: usize) -> u32 {
    (p >> ((i as u32) * 4)) & 0xF
}

/// TEE 操作返回值类型（u32）。
///
/// 大多数 TEE Client API 函数返回此类型的值，指示操作的成功或失败。
/// 成功时为 `TEEC_SUCCESS`（0），失败时为各类 `TEEC_ERROR_*` 错误码。
#[allow(non_camel_case_types)]
pub type TEEC_Result = u32;

/// 表示客户端应用与 TEE 之间的连接上下文
///
/// `TEEC_Context` 结构体用于保存与可信执行环境（TEE）的连接信息，
/// 它是所有 TEE 操作的基础，用于管理客户端应用与 TEE 之间的通信会话。
#[derive(Debug)]
#[repr(C)]
pub struct TEEC_Context {
    pub imp: TEEC_Context__Imp,
}

/// `TEEC_Context` 的实现定义字段。
///
/// - `fd`：上下文 ID（唯一标识符），由 `CONTEXT_ID_COUNTER` 原子递增分配
/// - `reg_mem`：是否已启用共享内存注册功能
/// - `memref_null`：MEMREF 类型参数是否允许 NULL 缓冲区
#[derive(Debug)]
#[repr(C)]
pub struct TEEC_Context__Imp {
    pub fd: c_int,
    pub reg_mem: bool,
    pub memref_null: bool,
}

/// 按照 RFC4122 定义的全局唯一资源标识符（UUID）
///
/// `TEEC_UUID` 结构体用于标识受信任应用（TA），
/// 它是识别特定可信应用的重要标识符，确保客户端能够连接到正确的可信应用。
#[derive(Debug)]
#[repr(C)]
pub struct TEEC_UUID {
    pub timeLow: u32,
    pub timeMid: u16,
    pub timeHiAndVersion: u16,
    pub clockSeqAndNode: [u8; 8usize],
}

/// 在客户端应用和受信任代码之间传输数据的共享内存
///
/// `TEEC_SharedMemory` 结构体定义了客户端应用与可信应用之间共享的内存区域，
/// 用于高效的数据传输。共享内存块是在客户端应用程序地址空间中分配的一段内存，
/// 可用于在客户端应用与受信任应用之间传输数据。
///
/// # 字段
///
/// * `buffer` - 要与 TEE 共享或已共享的内存缓冲区
/// * `size` - 缓冲区的字节大小
/// * `flags` - 表示缓冲区属性的位向量，可以包含 TEEC_MEM_INPUT 和/或 TEEC_MEM_OUTPUT 标志
#[derive(Debug)]
#[repr(C)]
pub struct TEEC_SharedMemory {
    pub buffer: *mut c_void,
    pub size: usize,
    pub flags: u32,
    pub imp: TEEC_SharedMemory__Imp,
}

/// `TEEC_SharedMemory` 的实现定义字段。
///
/// - `id`：共享内存唯一 ID，由 `SHM_ID_COUNTER` 原子递增分配，
///   `-1` 表示已释放
/// - `alloced_size`：实际分配的内存大小（字节）
/// - `shadow_buffer`：保留，当前未使用
/// - `registered_fd`：保留，当前固定为 `-1`
/// - `flags`：内部标志位（如 `SHM_FLAG_BUFFER_ALLOCED`）
#[derive(Debug)]
#[repr(C)]
pub struct TEEC_SharedMemory__Imp {
    pub id: c_int,
    pub alloced_size: usize,
    pub shadow_buffer: *mut c_void,
    pub registered_fd: c_int,
    pub flags: u32,
}

/// 临时内存引用，用于在客户端应用和受信任代码之间传输数据
///
/// `TEEC_TempMemoryReference` 结构体表示在单次操作的持续期间有效的临时内存引用，
/// 用于在客户端应用和可信应用之间传输数据。该结构表示在操作期间临时注册的内存缓冲区。
///
/// # 字段
///
/// * `buffer` - 要传输数据给 TEE 的内存缓冲区
/// * `size` - 缓冲区的字节大小
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct TEEC_TempMemoryReference {
    pub buffer: *mut c_void,
    pub size: usize,
}

/// 使用预先注册或预分配的内存块在客户端应用和受信任代码之间传输数据
///
/// `TEEC_RegisteredMemoryReference` 结构体用于使用预先注册或预分配的内存块
/// 在客户端应用和可信应用之间传输数据，提供了对已注册内存块的引用机制。
///
/// # 字段
///
/// * `parent` - 指向一个 `TEEC_SharedMemory` 结构，该内存引用可以表示整个内存或其中的一部分，不得为 NULL
/// * `size` - 引用区域的字节大小
/// * `offset` - 从内存块起始处到被引用区域的字节偏移量
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct TEEC_RegisteredMemoryReference {
    pub parent: *mut TEEC_SharedMemory,
    pub size: usize,
    pub offset: usize,
}

/// 小型原始数据容器
///
/// `TEEC_Value` 结构体可用于在客户端应用与受信任代码之间传递少量原始数据，
/// 作为一种替代分配共享内存缓冲区的轻量级机制，减少了系统开销。
///
/// # 字段
///
/// * `a` - 第一个整数字段
/// * `b` - 第二个整数字段
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct TEEC_Value {
    pub a: u32,
    pub b: u32,
}

/// 传递数据时使用的内存容器
///
/// `TEEC_Parameter` 联合体用于在TEE客户端API操作中传递不同类型的数据，
/// 可以包含共享内存引用、其部分区域或小型原始数据容器，提供了灵活的数据传递机制。
///
/// # 成员
///
/// * `tmpref` - 临时内存引用，仅在操作期间有效
/// * `memref` - 整个内存或其部分区域的引用
/// * `value` - 小型原始数据容器
#[derive(Copy, Clone)]
#[repr(C)]
pub union TEEC_Parameter {
    pub tmpref: TEEC_TempMemoryReference,
    pub memref: TEEC_RegisteredMemoryReference,
    pub value: TEEC_Value,
}

/// 表示客户端应用与受信任应用之间的会话连接
///
/// `TEEC_Session` 结构体用于管理客户端应用与特定可信应用之间的会话，
/// 一旦会话建立，就可以通过该会话执行各种操作和命令调用。
#[derive(Debug)]
#[repr(C)]
pub struct TEEC_Session {
    pub imp: TEEC_Session__Imp,
}

/// `TEEC_Session` 的实现定义字段。
///
/// - `ctx`：指向关联 `TEEC_Context` 的指针，会话关闭后置为 NULL
/// - `session_id`：TA 侧分配的唯一会话标识符
#[derive(Debug)]
#[repr(C)]
pub struct TEEC_Session__Imp {
    pub ctx: *mut TEEC_Context,
    pub session_id: u32,
}

/// 保存用于 `TEEC_InvokeCommand()` 的信息和内存引用
///
/// `TEEC_Operation` 结构体用于保存调用命令所需的信息和内存引用，
/// 包括参数类型、参数值以及与操作关联的会话信息，是执行可信应用命令的核心数据结构。
///
/// # 字段
///
/// * `started` - 如果客户端希望能够取消即将执行的操作，必须将该字段初始化为 0
/// * `paramTypes` - 表示传递参数类型，使用 `TEEC_PARAM_TYPES` 来生成正确的标志，若为 0，则表示所有参数均为 `TEEC_NONE`
/// * `params` - 类型为 `TEEC_Parameter` 的参数数组
/// * `imp` - 实现定义字段，包含 `session` 字段，表示与该操作关联的最近一次会话的内部指针
#[repr(C)]
pub struct TEEC_Operation {
    pub started: u32,
    pub paramTypes: u32,
    pub params: [TEEC_Parameter; TEEC_CONFIG_PAYLOAD_REF_COUNT],
    pub imp: TEEC_Operation__Imp,
}

/// `TEEC_Operation` 的实现定义字段。
///
/// - `session`：指向与本次操作关联的 `TEEC_Session` 的指针，
///   用于 `TEEC_RequestCancellation` 中定位目标会话
#[derive(Debug)]
#[repr(C)]
pub struct TEEC_Operation__Imp {
    pub session: *mut TEEC_Session,
}
