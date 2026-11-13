// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};

/// Logger that forwards `log` crate records to TA trace output.
pub struct TaTraceLogger;

static LOGGER: TaTraceLogger = TaTraceLogger;

impl Log for TaTraceLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let level = match record.level() {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        };

        let file = record.file().unwrap_or("<unknown>");
        let line = record.line().unwrap_or(0);
        let module = record.module_path().unwrap_or("<unknown>");
        crate::stdout::StdoutTrace::_print(format_args!(
            "[{}] {}:{} {} - {}\n",
            level,
            file,
            line,
            module,
            record.args()
        ));
    }

    fn flush(&self) {}
}

/// Convert TA trace level (from `TaConfig.trace_level`) to `log::LevelFilter`.
pub fn ta_trace_level_to_filter(level: i32) -> LevelFilter {
    match level {
        l if l <= 0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

/// Initialize global logger using TA trace level.
///
/// Safe to call multiple times: repeated calls are ignored.
pub fn init_with_trace_level(level: i32) {
    let _ = try_init_with_trace_level(level);
}

/// Try to initialize global logger using TA trace level.
pub fn try_init_with_trace_level(level: i32) -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER)?;
    log::set_max_level(ta_trace_level_to_filter(level));
    Ok(())
}
