// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

use core::fmt::{Arguments, Result, Write};

pub struct StdoutTrace;

impl StdoutTrace {
    fn new() -> Self {
        Self
    }

    pub fn _print(fmt: Arguments<'_>) {
        let mut writer = Self::new();
        let _ = writer.write_fmt(fmt);
    }
}

impl Write for StdoutTrace {
    fn write_str(&mut self, buf: &str) -> Result {
        print!("{}", buf);
        Ok(())
    }
}
