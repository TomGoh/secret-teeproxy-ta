// SPDX-License-Identifier: Apache-2.0
//! Install cancellation on the thread that actually executes Invoke, not its
//! socket reader. Only cancellation state is scoped; TA objects stay alive.
use crate::error::Error;

/// x-kernel's private current-thread cancellation scope syscall (both 64-bit ABIs).
const INVOKE_SCOPE_SYSCALL: libc::c_long = 572;

pub(crate) struct InvokeScope {
    is_supported: bool,
}

impl InvokeScope {
    pub(crate) fn enter(deadline_ns: Option<u64>) -> Result<Self, Error> {
        let result = scope_call(
            if deadline_ns.is_some() { 0 } else { 2 },
            deadline_ns.unwrap_or(0),
        );
        if result == 0 {
            return Ok(Self { is_supported: true });
        }
        // Legacy requests still run on kernels predating this private syscall.
        // Timed requests must fail rather than silently run without a deadline.
        if result == -1 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
                return if deadline_ns.is_none() {
                    Ok(Self {
                        is_supported: false,
                    })
                } else {
                    Err(Error::NotSupported)
                };
            }
            return Err(Error::Generic);
        }
        Err(Error::from(result as u32))
    }
}
impl Drop for InvokeScope {
    fn drop(&mut self) {
        if self.is_supported {
            let _ = scope_call(1, 0);
        }
    }
}

#[cfg(not(test))]
fn scope_call(operation: libc::c_ulong, deadline_ns: u64) -> libc::c_long {
    // SAFETY: scalar-only private x-kernel ABI; the kernel changes only the
    // calling thread's cancellation fields. No user pointer is passed.
    unsafe { libc::syscall(INVOKE_SCOPE_SYSCALL, operation, deadline_ns) }
}

#[cfg(test)]
thread_local! { static TEST_DEADLINE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
fn scope_call(operation: libc::c_ulong, deadline_ns: u64) -> libc::c_long {
    let _ = INVOKE_SCOPE_SYSCALL;
    TEST_DEADLINE.set(if operation == 0 {
        Some(deadline_ns)
    } else {
        None
    });
    0
}
#[cfg(test)]
pub(crate) fn installed_deadline() -> Option<u64> {
    TEST_DEADLINE.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_clears_on_return_and_does_not_cross_threads() {
        let scope = InvokeScope::enter(Some(123)).unwrap();
        assert_eq!(installed_deadline(), Some(123));
        std::thread::spawn(|| assert_eq!(installed_deadline(), None))
            .join()
            .unwrap();
        drop(scope);
        assert_eq!(installed_deadline(), None);
        let _ordinary = InvokeScope::enter(None).unwrap();
        assert_eq!(installed_deadline(), None);
    }
}
