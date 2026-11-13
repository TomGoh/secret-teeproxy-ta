// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.
//
// This file has been modified by KylinSoft on 2025.

#![allow(non_camel_case_types, non_snake_case, ambiguous_glob_reexports)]

pub mod api;
pub mod syscalls;
pub mod tee_api_defines;
pub mod tee_api_types;
pub mod trace;
pub mod user_ta_header;
pub mod utee_types;
#[macro_use]
mod macros;

// Crate-root re-exports: dependents may use `rust_utee::<symbol>` (see `[lib] name` in Cargo.toml).
// `api::user_ta_headers` is not glob-reexported: its `TA_PROP_STR_*` / `TA_FLAG_*` names overlap with `user_ta_header`.
pub use tee_api_defines::*;
pub use tee_api_types::*;
pub use trace::*;
pub use user_ta_header::*;
pub use utee_types::*;

pub use api::tee_api_arith_mpi::*;
pub use api::tee_api_cancel::*;
pub use api::tee_api_internal_client::*;
pub use api::tee_api_mm::*;
pub use api::tee_api_objects::*;
pub use api::tee_api_operations::*;
pub use api::tee_api_panic::*;
pub use api::tee_api_property::*;
pub use api::tee_api_time::*;

pub use syscalls::syscall_table::*;

mod libc_compat {
    pub type size_t = usize;
    #[allow(dead_code)]
    pub type intmax_t = i64;
}
