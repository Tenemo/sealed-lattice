use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const CHILD_ALLOCATION_BYTES: &str = "SEALED_LATTICE_PROCESS_GUARD_TEST_ALLOCATION_BYTES";
const CHILD_EXIT_CODE: &str = "SEALED_LATTICE_PROCESS_GUARD_TEST_EXIT_CODE";
const EXPECTED_ALLOCATION_REFUSAL: &str =
    "SEALED_LATTICE_PROCESS_MEMORY_GUARD_EXPECTED_ALLOCATION_REFUSAL";
const HOLD_ALLOCATION_MILLISECONDS: &str =
    "SEALED_LATTICE_PROCESS_GUARD_TEST_HOLD_ALLOCATION_MILLISECONDS";
const MAXIMUM_RESOURCE_SAMPLE_GAP_MILLISECONDS: u64 = 500;
const REQUESTED_RESOURCE_SAMPLE_INTERVAL_MILLISECONDS: u64 = 100;
const RESOURCE_SAMPLE_TEST_HOLD_MILLISECONDS: u64 = 1_200;
#[cfg(target_os = "linux")]
const SPAWN_AGGREGATE_ALLOCATION_CHILDREN: &str =
    "SEALED_LATTICE_PROCESS_GUARD_TEST_SPAWN_AGGREGATE_ALLOCATION_CHILDREN";
const GUARD_EXECUTABLE: &str = env!("CARGO_BIN_EXE_sealed-lattice-process-memory-guard");

struct TemporaryDiagnostics {
    directory_path: PathBuf,
    file_path: PathBuf,
}

impl TemporaryDiagnostics {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let directory_path = std::env::temp_dir().join(format!(
            "sealed-lattice-process-memory-guard-{}-{unique}-{label}",
            std::process::id()
        ));
        Self {
            file_path: directory_path.join("nested").join("guard.jsonl"),
            directory_path,
        }
    }

    fn read(&self) -> String {
        fs::read_to_string(&self.file_path).expect("process-memory guard diagnostics")
    }
}

impl Drop for TemporaryDiagnostics {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory_path);
    }
}

fn unsigned_json_field(line: &str, field_name: &str) -> Option<u64> {
    let marker = format!("\"{field_name}\":");
    let (_, value_and_suffix) = line.split_once(&marker)?;
    let digit_count = value_and_suffix
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count();
    if digit_count == 0 {
        return None;
    }
    value_and_suffix[..digit_count].parse::<u64>().ok()
}

fn resource_sample_elapsed_milliseconds(diagnostics: &str) -> Vec<u64> {
    diagnostics
        .lines()
        .filter(|line| line.contains("\"eventType\":\"resource-sample\""))
        .map(|line| {
            unsigned_json_field(line, "elapsedMilliseconds")
                .expect("resource sample elapsed milliseconds")
        })
        .collect()
}

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
    if let Some(milliseconds) = std::env::var(HOLD_ALLOCATION_MILLISECONDS)
        .ok()
        .map(|value| value.parse::<u64>().expect("allocation hold duration"))
    {
        thread::sleep(Duration::from_millis(milliseconds));
    }
    std::hint::black_box(allocated_bytes);
}

#[cfg(target_os = "linux")]
#[test]
fn guarded_child_spawns_allocations_that_only_exceed_the_aggregate_limit() {
    if std::env::var_os(SPAWN_AGGREGATE_ALLOCATION_CHILDREN).is_none() {
        return;
    }

    let current_test_executable = std::env::current_exe().expect("current test executable");
    let mut allocation_children = (0..2)
        .map(|_| {
            Command::new(&current_test_executable)
                .args(["--exact", "guarded_child_attempts_requested_allocation"])
                .env(CHILD_ALLOCATION_BYTES, "201326592")
                .env(HOLD_ALLOCATION_MILLISECONDS, "2000")
                .spawn()
                .expect("aggregate allocation child")
        })
        .collect::<Vec<_>>();
    let statuses = allocation_children
        .iter_mut()
        .map(|child| child.wait().expect("aggregate allocation child status"))
        .collect::<Vec<_>>();

    if statuses.iter().any(|status| !status.success()) {
        std::process::exit(86);
    }
    panic!("two individually allowed allocations exceeded the aggregate limit without refusal");
}

#[test]
fn guarded_child_exits_with_requested_status() {
    let Some(exit_code) = std::env::var(CHILD_EXIT_CODE)
        .ok()
        .map(|value| value.parse::<i32>().expect("child exit code"))
    else {
        return;
    };

    std::process::exit(exit_code);
}

#[cfg(target_os = "linux")]
#[test]
fn guarded_child_terminates_with_sigterm() {
    if std::env::var_os("SEALED_LATTICE_PROCESS_GUARD_TEST_SIGTERM").is_none() {
        return;
    }
    unsafe extern "C" {
        fn raise(signal: i32) -> i32;
    }
    // SAFETY: SIGTERM is a valid signal number and raise has no pointer
    // preconditions. This child exists solely to exercise signal propagation.
    unsafe {
        raise(15);
    }
    panic!("SIGTERM did not terminate the signal fixture");
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
fn runs_a_small_child_below_the_memory_limit() {
    let current_test_executable = std::env::current_exe().expect("current test executable");
    let diagnostics = TemporaryDiagnostics::new("success");
    let status = Command::new(GUARD_EXECUTABLE)
        .args([
            "--memory-limit-bytes",
            "1073741824",
            "--virtual-address-space-allowance-bytes",
            "8589934592",
            "--diagnostics-path",
            diagnostics
                .file_path
                .to_str()
                .expect("UTF-8 diagnostics path"),
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
    let diagnostic_text = diagnostics.read();
    assert!(diagnostic_text.contains("\"eventType\":\"guard-started\""));
    assert!(diagnostic_text.contains("\"eventType\":\"child-started\""));
    assert!(diagnostic_text.contains("\"eventType\":\"resource-sample\""));
    assert!(diagnostic_text.contains("\"processTreeResidentMemoryBytes\":"));
    assert!(!diagnostic_text.contains("\"processTreeResidentMemoryBytes\":null"));
    assert!(diagnostic_text.contains("\"eventType\":\"child-exited\""));
    assert!(diagnostic_text.contains("\"terminationClassification\":\"completed\""));
    assert!(diagnostic_text.contains("\"memoryLimitBytes\":1073741824"));
    assert!(diagnostic_text.contains("\"virtualAddressSpaceAllowanceBytes\":8589934592"));
    assert!(diagnostic_text.contains("\"resourceSampleIntervalMilliseconds\":5000"));
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
fn records_a_requested_resource_sample_interval_with_bounded_actual_gaps() {
    let current_test_executable = std::env::current_exe().expect("current test executable");
    let diagnostics = TemporaryDiagnostics::new("resource-sample-interval");
    let requested_interval = REQUESTED_RESOURCE_SAMPLE_INTERVAL_MILLISECONDS.to_string();
    let status = Command::new(GUARD_EXECUTABLE)
        .args([
            "--memory-limit-bytes",
            "1073741824",
            "--resource-sample-interval-milliseconds",
            &requested_interval,
            "--diagnostics-path",
            diagnostics
                .file_path
                .to_str()
                .expect("UTF-8 diagnostics path"),
            "--",
            current_test_executable
                .to_str()
                .expect("UTF-8 test executable path"),
            "--exact",
            "guarded_child_attempts_requested_allocation",
        ])
        .env(CHILD_ALLOCATION_BYTES, "1048576")
        .env(
            HOLD_ALLOCATION_MILLISECONDS,
            RESOURCE_SAMPLE_TEST_HOLD_MILLISECONDS.to_string(),
        )
        .status()
        .expect("guarded command with requested resource sample interval");

    assert!(
        status.success(),
        "guarded command with requested resource sample interval failed: {status}"
    );
    let diagnostic_text = diagnostics.read();
    assert!(diagnostic_text.contains("\"resourceSampleIntervalMilliseconds\":100"));
    let sample_elapsed_milliseconds = resource_sample_elapsed_milliseconds(&diagnostic_text);
    assert!(
        sample_elapsed_milliseconds.len() >= 3,
        "expected at least three resource samples, received {sample_elapsed_milliseconds:?}"
    );
    for sample_pair in sample_elapsed_milliseconds.windows(2) {
        let [previous, current] = sample_pair else {
            unreachable!("windows of two always contain two samples");
        };
        let gap = current
            .checked_sub(*previous)
            .expect("resource sample elapsed time must be nondecreasing");
        assert!(
            gap <= MAXIMUM_RESOURCE_SAMPLE_GAP_MILLISECONDS,
            "resource sampling gap {gap} ms exceeded the Windows-safe {} ms bound: {sample_elapsed_milliseconds:?}",
            MAXIMUM_RESOURCE_SAMPLE_GAP_MILLISECONDS
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
fn refuses_a_child_allocation_above_the_memory_limit() {
    let current_test_executable = std::env::current_exe().expect("current test executable");
    let diagnostics = TemporaryDiagnostics::new("expected-allocation-refusal");
    let status = Command::new(GUARD_EXECUTABLE)
        .args([
            "--memory-limit-bytes",
            "536870912",
            "--virtual-address-space-allowance-bytes",
            "8589934592",
            "--diagnostics-path",
            diagnostics
                .file_path
                .to_str()
                .expect("UTF-8 diagnostics path"),
            "--",
            current_test_executable
                .to_str()
                .expect("UTF-8 test executable path"),
            "--exact",
            "guarded_child_attempts_requested_allocation",
        ])
        .env(CHILD_ALLOCATION_BYTES, "1073741824")
        .env(EXPECTED_ALLOCATION_REFUSAL, "1")
        .status()
        .expect("guarded over-limit command");

    assert!(
        !status.success(),
        "over-limit allocation unexpectedly succeeded"
    );
    let diagnostic_text = diagnostics.read();
    assert!(diagnostic_text.contains("\"expectedDiagnostic\":\"controlled-allocation-refusal\""));
    assert!(diagnostic_text.contains("\"eventType\":\"child-exited\""));
    assert!(diagnostic_text.contains("\"memoryEvidence\":"));
}

#[cfg(target_os = "linux")]
#[test]
fn refuses_individually_allowed_allocations_above_the_aggregate_limit() {
    let current_test_executable = std::env::current_exe().expect("current test executable");
    let diagnostics = TemporaryDiagnostics::new("aggregate-allocation-refusal");
    let status = Command::new(GUARD_EXECUTABLE)
        .args([
            "--memory-limit-bytes",
            "268435456",
            "--virtual-address-space-allowance-bytes",
            "8589934592",
            "--diagnostics-path",
            diagnostics
                .file_path
                .to_str()
                .expect("UTF-8 diagnostics path"),
            "--",
            current_test_executable
                .to_str()
                .expect("UTF-8 test executable path"),
            "--exact",
            "guarded_child_spawns_allocations_that_only_exceed_the_aggregate_limit",
        ])
        .env(SPAWN_AGGREGATE_ALLOCATION_CHILDREN, "1")
        .env(EXPECTED_ALLOCATION_REFUSAL, "1")
        .status()
        .expect("guarded aggregate allocation command");

    assert_eq!(status.code(), Some(86));
    let diagnostic_text = diagnostics.read();
    assert!(
        diagnostic_text.contains(
            "\"containmentBackend\":\"linux-cgroup-v2-memory-max-plus-rlimit-data-and-as\""
        )
    );
    assert!(diagnostic_text.contains("\"aggregateProcessTreeMemoryLimit\":true"));
    assert!(diagnostic_text.contains("\"confirmedMemoryLimitViolation\":true"));
    assert!(diagnostic_text.contains("\"memoryEvidence\":\"confirmed\""));
    assert!(diagnostic_text.contains("\"terminationClassification\":\"memory-limit-confirmed\""));
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
fn preserves_a_nonzero_child_exit_code_and_records_its_raw_status() {
    let current_test_executable = std::env::current_exe().expect("current test executable");
    let diagnostics = TemporaryDiagnostics::new("exit-code");
    let status = Command::new(GUARD_EXECUTABLE)
        .args([
            "--memory-limit-bytes",
            "1073741824",
            "--diagnostics-path",
            diagnostics
                .file_path
                .to_str()
                .expect("UTF-8 diagnostics path"),
            "--",
            current_test_executable
                .to_str()
                .expect("UTF-8 test executable path"),
            "--exact",
            "guarded_child_exits_with_requested_status",
        ])
        .env(CHILD_EXIT_CODE, "37")
        .status()
        .expect("guarded nonzero command");

    assert_eq!(status.code(), Some(37));
    let diagnostic_text = diagnostics.read();
    assert!(diagnostic_text.contains("\"exitCode\":37"));
    assert!(diagnostic_text.contains("\"rawStatusHex\":"));
    assert!(diagnostic_text.contains("\"memoryEvidence\":\"unknown\""));
}

#[cfg(target_os = "linux")]
#[test]
fn propagates_a_child_signal_instead_of_collapsing_it_to_exit_one() {
    use std::os::unix::process::ExitStatusExt;

    let current_test_executable = std::env::current_exe().expect("current test executable");
    let diagnostics = TemporaryDiagnostics::new("sigterm");
    let status = Command::new(GUARD_EXECUTABLE)
        .args([
            "--memory-limit-bytes",
            "1073741824",
            "--diagnostics-path",
            diagnostics
                .file_path
                .to_str()
                .expect("UTF-8 diagnostics path"),
            "--",
            current_test_executable
                .to_str()
                .expect("UTF-8 test executable path"),
            "--exact",
            "guarded_child_terminates_with_sigterm",
        ])
        .env("SEALED_LATTICE_PROCESS_GUARD_TEST_SIGTERM", "1")
        .status()
        .expect("guarded signal command");

    assert_eq!(status.signal(), Some(15));
    let diagnostic_text = diagnostics.read();
    assert!(diagnostic_text.contains("\"signalName\":\"SIGTERM\""));
    assert!(diagnostic_text.contains("\"signalNumber\":15"));
    assert!(diagnostic_text.contains("\"memoryEvidence\":\"unknown\""));
}
