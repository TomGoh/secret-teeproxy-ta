// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

pub mod acl;
pub mod error;
pub mod logger;
pub mod panic_notify;
pub mod stdout;
pub mod ta_manager;
#[macro_use]
mod macros;

pub use rust_utee::*;
pub use teec_protocol::{ParamType, Parameters, TARequest, TEE_Request, TEE_Response};

mod registration_protocol;

mod invoke_cancellation;
mod invoke_protocol;
