//! Test count enforcement: ensures the total number of tests in the
//! wolfcrypt-dpe-conformance crate never drops below a minimum threshold.

mod helpers;

#[test]
fn minimum_test_count() {
    let output = std::process::Command::new("cargo")
        .args(["test", "-p", "wolfcrypt-dpe-conformance", "--", "--list"])
        .output()
        .expect("failed to run cargo test --list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let test_count = stdout.lines().filter(|l| l.ends_with(": test")).count();
    // Subtract this test itself
    let other_tests = test_count.saturating_sub(1);
    const MINIMUM_TESTS: usize = 200;
    assert!(
        other_tests >= MINIMUM_TESTS,
        "Expected at least {} tests, found {}. Tests may have been deleted.",
        MINIMUM_TESTS,
        other_tests
    );
}
