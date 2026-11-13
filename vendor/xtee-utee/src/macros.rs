// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! # Trace macros (`trace_error!`, …)
//!
//! Five macros mirror [`log::Level`] and gate output with [`log::log_enabled!`], so the same
//! `TaConfig.trace_level` → [`crate::logger::init_with_trace_level`] mapping controls both
//! `log::info!` / `warn!` / … and these macros. Output still goes through [`crate::trace_println!`]
//! (TEE syscall path), not the `log` formatter.
//!
//! Use **`trace_trace!`** for the finest level (same as [`log::Level::Trace`]), not `trace!`, to
//! avoid confusion with [`log::trace!`].
//!
//! # Stdout macros (`stdout_print!`, `stdout_println!`)
//!
//! Write to the TA process **standard output** via [`crate::stdout::StdoutTrace`] (Rust [`print!`] /
//! [`println!`] semantics). This is **not** the same as [`trace_println!`], which goes through the
//! TEE `_utee_log` syscall path.

/// Print to **stdout** without a trailing newline (same role as [`print!`]).
#[macro_export]
macro_rules! stdout_print {
    ($($arg:tt)*) => {
        $crate::stdout::StdoutTrace::_print(format_args!($($arg)*))
    };
}

/// Print to **stdout** with a trailing newline (same role as [`println!`]).
#[macro_export]
macro_rules! stdout_println {
    () => {
        $crate::stdout::StdoutTrace::_print(format_args!("\n"))
    };
    ($s:expr) => {
        $crate::stdout::StdoutTrace::_print(format_args!(concat!($s, "\n")))
    };
    ($s:expr, $($tt:tt)*) => {
        $crate::stdout::StdoutTrace::_print(format_args!(concat!($s, "\n"), $($tt)*))
    };
}

/// Deprecated alias for [`stdout_print!`].
#[macro_export]
#[deprecated(note = "renamed to `stdout_print`")]
macro_rules! ta_print {
    ($($arg:tt)*) => {
        $crate::stdout_print!($($arg)*)
    };
}

/// Deprecated alias for [`stdout_println!`].
#[macro_export]
#[deprecated(note = "renamed to `stdout_println`")]
macro_rules! ta_println {
    () => {
        $crate::stdout_println!()
    };
    ($s:expr) => {
        $crate::stdout_println!($s)
    };
    ($s:expr, $($tt:tt)*) => {
        $crate::stdout_println!($s, $($tt)*)
    };
}

/// Syscall trace at **error** verbosity; enabled when [`log::Level::Error`] passes
/// [`log::log_enabled!`].
#[macro_export]
macro_rules! trace_error {
    ($($arg:tt)*) => {
        if ::log::log_enabled!(::log::Level::Error) {
            $crate::trace_println!($($arg)*);
        }
    };
}

/// Syscall trace at **warn** verbosity.
#[macro_export]
macro_rules! trace_warn {
    ($($arg:tt)*) => {
        if ::log::log_enabled!(::log::Level::Warn) {
            $crate::trace_println!($($arg)*);
        }
    };
}

/// Syscall trace at **info** verbosity.
#[macro_export]
macro_rules! trace_info {
    ($($arg:tt)*) => {
        if ::log::log_enabled!(::log::Level::Info) {
            $crate::trace_println!($($arg)*);
        }
    };
}

/// Syscall trace at **debug** verbosity.
#[macro_export]
macro_rules! trace_debug {
    ($($arg:tt)*) => {
        if ::log::log_enabled!(::log::Level::Debug) {
            $crate::trace_println!($($arg)*);
        }
    };
}

/// Syscall trace at **trace** verbosity (finest); mirrors [`log::Level::Trace`]. Named
/// `trace_trace!` rather than `trace!` to avoid colliding with [`log::trace!`].
#[macro_export]
macro_rules! trace_trace {
    ($($arg:tt)*) => {
        if ::log::log_enabled!(::log::Level::Trace) {
            $crate::trace_println!($($arg)*);
        }
    };
}
