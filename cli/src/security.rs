//! Process hardening and debugger detection.
//!
//! Applies OS-level security mitigations at process startup:
//! - Unix: `PR_SET_DUMPABLE=0` prevents `/proc/{pid}/mem` access and ptrace attach.
//! - Unix: `RLIMIT_CORE=0` disables core dump file generation on crash.
//! - Unix/Windows: Detects an attached debugger and emits a warning.

/// Apply OS-level process hardening at startup.
///
/// On Unix:
/// 1. Sets `PR_SET_DUMPABLE=0` to prevent other processes from reading
///    `/proc/{pid}/mem` and to block ptrace attach.
/// 2. Sets `RLIMIT_CORE=0` to suppress core dump files on crash,
///    preventing key material from leaking to disk.
///
/// On Windows: no-op (these concepts do not exist on Windows).
///
/// All failures are emitted as warnings to stderr; the process continues
/// regardless (REQ-013).
pub fn harden_process() {
    #[cfg(unix)]
    {
        // PR_SET_DUMPABLE=0: blocks /proc/pid/mem reads and ptrace attach.
        // nix 0.29 does not expose a prctl feature, so we call libc::prctl directly.
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) is listed in CLAUDE.md's allowed unsafe scope.
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0_usize, 0_usize, 0_usize, 0_usize) };
        if ret != 0 {
            eprintln!(
                "Warning: PR_SET_DUMPABLE failed: {}",
                std::io::Error::last_os_error()
            );
        }
        // RLIMIT_CORE=0: disables core dump files to prevent key material leakage
        use nix::sys::resource::{setrlimit, Resource};
        if let Err(e) = setrlimit(Resource::RLIMIT_CORE, 0, 0) {
            eprintln!("Warning: setrlimit(RLIMIT_CORE, 0) failed: {e}");
        }
    }
}

/// Detect an attached debugger and warn the user.
///
/// On Unix: reads `/proc/self/status` and checks the `TracerPid` field.
/// A non-zero `TracerPid` indicates an attached debugger.
///
/// On Windows: calls `IsDebuggerPresent()`. A non-zero return value
/// indicates an attached debugger.
///
/// On other platforms: no-op.
///
/// Detection only produces a warning; the process does not exit (REQ-013).
pub fn check_debugger() {
    #[cfg(unix)]
    {
        // /proc/self/status is Linux-specific; the if-let handles macOS and others safely
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let pid: u32 = line
                        .split(':')
                        .nth(1)
                        .unwrap_or("0")
                        .trim()
                        .parse()
                        .unwrap_or(0);
                    if pid != 0 {
                        eprintln!(
                            "Warning: debugger detected (TracerPid: {pid}). Key material may be exposed."
                        );
                    }
                }
            }
        }
    }
    #[cfg(windows)]
    {
        // SAFETY: IsDebuggerPresent() is a nullary Win32 API that is always safe to call.
        // It requires no parameters and returns a BOOL (i32). This falls within the
        // CLAUDE.md-permitted unsafe scope for Win32 system APIs used for security hardening.
        let attached =
            unsafe { windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() };
        if attached != 0 {
            eprintln!("Warning: debugger detected. Key material may be exposed.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TC-S9-084-01: harden_process() completes without panicking on the current platform.
    ///
    /// Verifies that the function is safe to call regardless of platform and privilege level.
    #[test]
    fn tc_s9_084_01_harden_process_does_not_panic() {
        harden_process();
    }

    /// TC-S9-084-02: check_debugger() completes without panicking in a non-debugger environment.
    ///
    /// Verifies that the function handles the no-debugger case safely.
    #[test]
    fn tc_s9_084_02_check_debugger_no_panic() {
        check_debugger();
    }

    /// TC-S9-084-03: After harden_process(), the Dumpable field in /proc/self/status is 0.
    ///
    /// Linux-only test. Skipped silently on platforms where /proc/self/status is unavailable.
    #[cfg(unix)]
    #[test]
    fn tc_s9_084_03_dumpable_set_to_zero() {
        harden_process();
        // /proc/self/status is Linux-specific; silently skip on macOS and others
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            return;
        };
        for line in status.lines() {
            if line.starts_with("Dumpable:") {
                let val: u32 = line
                    .split(':')
                    .nth(1)
                    .unwrap_or("1")
                    .trim()
                    .parse()
                    .unwrap_or(1);
                assert_eq!(val, 0, "Dumpable must be 0 after harden_process()");
                return;
            }
        }
        // Dumpable field not found in /proc/self/status — skip
    }

    /// TC-S9-084-04: After harden_process(), RLIMIT_CORE is 0 for both soft and hard limits.
    ///
    /// Unix-only test. Uses nix::sys::resource::getrlimit to read the current limits.
    #[cfg(unix)]
    #[test]
    fn tc_s9_084_04_rlimit_core_set_to_zero() {
        use nix::sys::resource::{getrlimit, Resource};
        harden_process();
        let (soft, hard) = getrlimit(Resource::RLIMIT_CORE).expect("getrlimit must succeed");
        assert_eq!(
            soft, 0,
            "RLIMIT_CORE soft limit must be 0 after harden_process()"
        );
        assert_eq!(
            hard, 0,
            "RLIMIT_CORE hard limit must be 0 after harden_process()"
        );
    }

    /// TC-S9-084-05: IsDebuggerPresent() returns 0 during normal test execution.
    ///
    /// Windows-only test. Verifies that the API is callable and returns 0 without a debugger.
    #[cfg(windows)]
    #[test]
    fn tc_s9_084_05_is_debugger_present_returns_zero() {
        // SAFETY: IsDebuggerPresent() is a nullary Win32 API, always safe to call.
        let result = unsafe { windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() };
        assert_eq!(
            result, 0,
            "IsDebuggerPresent must return 0 during normal test execution (no debugger attached)"
        );
    }
}
