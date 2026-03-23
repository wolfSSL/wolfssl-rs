//! Meta-test: enforce a minimum number of tests in the conformance suite.
//!
//! This prevents silently deleting tests without anyone noticing.
//! If a legitimate change reduces the test count, update `MINIMUM_TESTS`.
//!
//! # Why a subprocess?
//!
//! Rust's built-in test harness provides no introspection API to query the
//! number of tests at runtime. `cargo test -- --list` is the only stable
//! mechanism. The cost is ~0.5s of wall-clock time (a no-build re-invocation
//! of cargo).
//!
//! The `CARGO` env var (set by Cargo during `cargo test`) is used so this
//! works regardless of PATH or cross-compilation toolchain. If a sandboxed
//! CI environment restricts subprocess spawning, this test will fail with a
//! clear "failed to run" message — not a silent false pass.
//!
//! # Self-counting
//!
//! `--list` includes this test itself in the count. We subtract 1 via
//! `saturating_sub` so the minimum applies only to "real" tests.

#[test]
fn minimum_test_count() {
    // Cargo sets `CARGO` to its own path when running tests.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let output = std::process::Command::new(&cargo)
        .args(["test", "-p", "wolfcrypt-conformance", "--", "--list"])
        .output()
        .unwrap_or_else(|e| panic!("failed to run `{cargo} test --list`: {e}"));

    assert!(
        output.status.success(),
        "`{cargo} test --list` exited with {}",
        output.status,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let test_count = stdout.lines().filter(|l| l.ends_with(": test")).count();

    // Subtract 1 for this test itself
    let other_tests = test_count.saturating_sub(1);

    // Calibrated 2026-03-21; actual count 510 with all features enabled.
    // Set conservatively (~80%) to allow for cfg-disabled algorithms.
    const MINIMUM_TESTS: usize = 400;

    assert!(
        other_tests >= MINIMUM_TESTS,
        "Expected at least {} tests, found {}. Tests may have been deleted.",
        MINIMUM_TESTS,
        other_tests
    );
}
