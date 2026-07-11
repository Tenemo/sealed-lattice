use std::process::Command;

const CHILD_ALLOCATION_BYTES: &str = "SEALED_LATTICE_PROCESS_GUARD_TEST_ALLOCATION_BYTES";
const GUARD_EXECUTABLE: &str = env!("CARGO_BIN_EXE_sealed-lattice-process-memory-guard");

#[test]
fn guarded_child_exits_successfully() {
    // This test is also the small child command selected by the success case.
}

#[test]
fn guarded_child_attempts_requested_allocation() {
    let Some(allocation_bytes) = std::env::var(CHILD_ALLOCATION_BYTES)
        .ok()
        .map(|value| value.parse::<usize>().expect("allocation byte count"))
    else {
        return;
    };

    let allocated_bytes = vec![1_u8; allocation_bytes];
    std::hint::black_box(allocated_bytes);
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
fn runs_a_small_child_below_the_memory_limit() {
    let current_test_executable = std::env::current_exe().expect("current test executable");
    let status = Command::new(GUARD_EXECUTABLE)
        .args([
            "--memory-limit-bytes",
            "1073741824",
            "--",
            current_test_executable
                .to_str()
                .expect("UTF-8 test executable path"),
            "--exact",
            "guarded_child_exits_successfully",
        ])
        .status()
        .expect("guarded success command");

    assert!(status.success(), "guarded success command failed: {status}");
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
fn refuses_a_child_allocation_above_the_memory_limit() {
    let current_test_executable = std::env::current_exe().expect("current test executable");
    let status = Command::new(GUARD_EXECUTABLE)
        .args([
            "--memory-limit-bytes",
            "536870912",
            "--",
            current_test_executable
                .to_str()
                .expect("UTF-8 test executable path"),
            "--exact",
            "guarded_child_attempts_requested_allocation",
        ])
        .env(CHILD_ALLOCATION_BYTES, "1073741824")
        .status()
        .expect("guarded over-limit command");

    assert!(
        !status.success(),
        "over-limit allocation unexpectedly succeeded"
    );
}
