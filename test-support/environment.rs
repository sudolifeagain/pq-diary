//! Environment-sensitive tests re-execute themselves before touching fixtures.
//!
//! A mutex cannot protect unrelated readers (including library and OS code).
//! Only the selected test runs in the child; mutations and even panics cannot
//! leak back into the parallel parent harness. This is exec, not a raw fork.
use std::process::{Command, Stdio};

const CHILD: &str = "PQ_DIARY_ISOLATED_TEST";

/// Return true in the parent after the exact child test succeeds.
/// Call first, before constructing fixtures or changing any environment value.
pub fn isolated() -> bool {
    let thread = std::thread::current();
    let name = thread.name().expect("named libtest thread");
    if std::env::var_os(CHILD).is_some() {
        // A dispatch mismatch is an error, never permission to recurse.
        assert_isolated();
        return false;
    }
    let output = run_isolated(name);
    assert!(
        output.status.success(),
        "isolated test {name} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "isolated test must execute exactly one non-ignored test"
    );
    true
}

/// Fail closed if an environment override is accidentally used before isolation.
pub fn assert_isolated() {
    let thread = std::thread::current();
    assert!(
        std::env::var_os(CHILD).as_deref() == thread.name().map(std::ffi::OsStr::new),
        "call isolated() before creating environment-dependent fixtures"
    );
}

fn run_isolated(name: &str) -> std::process::Output {
    assert!(
        std::env::var_os(CHILD).is_none(),
        "isolated children cannot spawn another test harness"
    );
    let home = tempfile::tempdir().expect("isolated test home");
    Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name)
        // Set these on Command, never in the parallel parent. Keep PATH for
        // fixture setup; missing-git tests clear it only inside their child.
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("APPDATA", home.path())
        .env("LOCALAPPDATA", home.path())
        .env("PQ_DIARY_HOME", home.path().join(".pq-diary"))
        .env_remove("PQ_DIARY_PASSWORD")
        .env_remove("EDITOR")
        .stdin(Stdio::null())
        .output()
        .expect("start isolated test")
}

#[test]
fn child_panic_cannot_change_parent_environment() {
    let thread = std::thread::current();
    let name = thread.name().unwrap();
    const KEYS: [&str; 3] = ["PQ_DIARY_HOME", "PQ_DIARY_PASSWORD", "PATH"];
    if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new(name)) {
        assert_isolated();
        assert!(std::env::var_os("PQ_DIARY_PASSWORD").is_none());
        let home = std::env::var_os("HOME").unwrap();
        assert_eq!(std::env::var_os("USERPROFILE").unwrap(), home);
        for key in KEYS {
            std::env::set_var(key, "synthetic child value");
        }
        panic!("intentional isolated child panic");
    }
    let before = KEYS.map(std::env::var_os);
    let output = run_isolated(name);
    assert!(
        !output.status.success(),
        "child panic must propagate as failure"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("running 1 test"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("intentional isolated child panic"));
    assert!(
        KEYS.map(std::env::var_os) == before,
        "child changed parent environment (values redacted)"
    );
}
