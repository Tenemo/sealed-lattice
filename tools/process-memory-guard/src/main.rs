#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsString;
use std::process::Command;

const MEMORY_LIMIT_ARGUMENT: &str = "--memory-limit-bytes";
const COMMAND_SEPARATOR: &str = "--";

#[derive(Debug, Eq, PartialEq)]
struct GuardedCommand {
    memory_limit_bytes: u64,
    program: OsString,
    arguments: Vec<OsString>,
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<GuardedCommand, String> {
    let mut arguments = arguments.into_iter();
    let memory_limit_argument = arguments
        .next()
        .ok_or_else(|| usage("missing memory-limit argument"))?;
    if memory_limit_argument != MEMORY_LIMIT_ARGUMENT {
        return Err(usage(&format!(
            "expected {MEMORY_LIMIT_ARGUMENT}, received {}",
            memory_limit_argument.to_string_lossy()
        )));
    }

    let memory_limit_value = arguments
        .next()
        .ok_or_else(|| usage("missing memory-limit value"))?;
    let memory_limit_bytes = memory_limit_value
        .to_str()
        .ok_or_else(|| usage("memory-limit value must be UTF-8"))?
        .parse::<u64>()
        .map_err(|_| usage("memory-limit value must be a positive integer"))?;
    if memory_limit_bytes == 0 {
        return Err(usage("memory-limit value must be greater than zero"));
    }

    let separator = arguments
        .next()
        .ok_or_else(|| usage("missing command separator"))?;
    if separator != COMMAND_SEPARATOR {
        return Err(usage(&format!(
            "expected {COMMAND_SEPARATOR} before the guarded command"
        )));
    }

    let program = arguments
        .next()
        .ok_or_else(|| usage("missing guarded command"))?;

    Ok(GuardedCommand {
        memory_limit_bytes,
        program,
        arguments: arguments.collect(),
    })
}

fn usage(reason: &str) -> String {
    format!(
        "{reason}. Usage: sealed-lattice-process-memory-guard {MEMORY_LIMIT_ARGUMENT} <bytes> {COMMAND_SEPARATOR} <command> [arguments...]"
    )
}

fn run_guarded_command(command: GuardedCommand) -> Result<i32, String> {
    platform::apply_memory_limit(command.memory_limit_bytes)?;
    let status = Command::new(&command.program)
        .args(&command.arguments)
        .status()
        .map_err(|error| {
            format!(
                "failed to start guarded command {}: {error}",
                command.program.to_string_lossy()
            )
        })?;

    Ok(status.code().unwrap_or(1))
}

fn main() {
    let guarded_command = match parse_arguments(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("Process memory guard refused to start: {error}");
            std::process::exit(1);
        }
    };

    match run_guarded_command(guarded_command) {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            eprintln!("Process memory guard failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use std::ffi::c_void;
    use std::io;
    use std::mem::{forget, size_of};
    use std::ptr;

    type Handle = *mut c_void;

    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
    const JOB_OBJECT_LIMIT_JOB_MEMORY: u32 = 0x0000_0200;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

    #[repr(C)]
    #[derive(Default)]
    struct JobObjectBasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation,
        io_information: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    unsafe extern "system" {
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn CloseHandle(object: Handle) -> i32;
        fn CreateJobObjectW(job_attributes: *const c_void, name: *const u16) -> Handle;
        fn GetCurrentProcess() -> Handle;
        fn SetInformationJobObject(
            job: Handle,
            information_class: i32,
            information: *const c_void,
            information_length: u32,
        ) -> i32;
    }

    struct OwnedJobHandle(Handle);

    impl Drop for OwnedJobHandle {
        fn drop(&mut self) {
            // SAFETY: CreateJobObjectW returned this non-null owned handle and
            // this wrapper closes it at most once before it is deliberately
            // transferred to process-lifetime ownership.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub(super) fn apply_memory_limit(memory_limit_bytes: u64) -> Result<(), String> {
        let job_memory_limit = usize::try_from(memory_limit_bytes).map_err(|_| {
            format!(
                "memory limit {memory_limit_bytes} cannot be represented on this Windows target"
            )
        })?;
        let information_length = u32::try_from(size_of::<JobObjectExtendedLimitInformation>())
            .map_err(|_| "Windows job information structure is unexpectedly large".to_owned())?;

        // SAFETY: Null attributes and name request an unnamed job with the
        // current process's default security descriptor. The returned handle
        // is checked before it is wrapped as owned.
        let raw_job_handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if raw_job_handle.is_null() {
            return Err(format!(
                "CreateJobObjectW failed: {}",
                io::Error::last_os_error()
            ));
        }
        let job_handle = OwnedJobHandle(raw_job_handle);

        let mut limit_information = JobObjectExtendedLimitInformation::default();
        limit_information.basic_limit_information.limit_flags =
            JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        limit_information.job_memory_limit = job_memory_limit;

        // SAFETY: The information pointer addresses a repr(C) structure of the
        // exact size supplied for JobObjectExtendedLimitInformation, and the
        // job handle remains valid for the call.
        let limit_was_set = unsafe {
            SetInformationJobObject(
                job_handle.0,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                ptr::from_ref(&limit_information).cast(),
                information_length,
            )
        };
        if limit_was_set == 0 {
            return Err(format!(
                "SetInformationJobObject failed: {}",
                io::Error::last_os_error()
            ));
        }

        // Assign the launcher before it creates the guarded command. Windows
        // associates every child with the same job by default, eliminating the
        // race in which cargo could create a test process before assignment.
        // SAFETY: GetCurrentProcess returns a valid pseudo-handle with the
        // access required to assign the current process to this valid job.
        let process_was_assigned =
            unsafe { AssignProcessToJobObject(job_handle.0, GetCurrentProcess()) };
        if process_was_assigned == 0 {
            return Err(format!(
                "AssignProcessToJobObject failed: {}",
                io::Error::last_os_error()
            ));
        }

        // Keep the only job handle open for the launcher's lifetime. Windows
        // closes it if the launcher exits for any reason; KILL_ON_JOB_CLOSE then
        // terminates cargo and every remaining descendant in the job.
        forget(job_handle);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::c_int;
    use std::io;

    const RESOURCE_LIMIT_ADDRESS_SPACE: c_int = 9;

    #[repr(C)]
    struct ResourceLimit {
        current: usize,
        maximum: usize,
    }

    unsafe extern "C" {
        fn setrlimit(resource: c_int, limits: *const ResourceLimit) -> c_int;
    }

    pub(super) fn apply_memory_limit(memory_limit_bytes: u64) -> Result<(), String> {
        let memory_limit = usize::try_from(memory_limit_bytes).map_err(|_| {
            format!("memory limit {memory_limit_bytes} cannot be represented on this Linux target")
        })?;
        let limits = ResourceLimit {
            current: memory_limit,
            maximum: memory_limit,
        };

        // SAFETY: The pointer addresses a repr(C) rlimit-compatible structure
        // for Linux, and it remains valid for the duration of setrlimit.
        let result = unsafe { setrlimit(RESOURCE_LIMIT_ADDRESS_SPACE, &limits) };
        if result != 0 {
            return Err(format!(
                "setrlimit(RLIMIT_AS) failed: {}",
                io::Error::last_os_error()
            ));
        }

        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod platform {
    pub(super) fn apply_memory_limit(_memory_limit_bytes: u64) -> Result<(), String> {
        Err(format!(
            "hard memory containment is unsupported on {}",
            std::env::consts::OS
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned_arguments(arguments: &[&str]) -> Vec<OsString> {
        arguments.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_a_guarded_command_without_interpreting_its_arguments() {
        let parsed = parse_arguments(owned_arguments(&[
            MEMORY_LIMIT_ARGUMENT,
            "34359738368",
            COMMAND_SEPARATOR,
            "cargo",
            "test",
            COMMAND_SEPARATOR,
            "--test-threads",
            "1",
        ]))
        .expect("guarded command arguments");

        assert_eq!(
            parsed,
            GuardedCommand {
                memory_limit_bytes: 34_359_738_368,
                program: OsString::from("cargo"),
                arguments: owned_arguments(&["test", COMMAND_SEPARATOR, "--test-threads", "1"]),
            }
        );
    }

    #[test]
    fn refuses_missing_or_invalid_memory_limits() {
        for arguments in [
            vec![],
            owned_arguments(&[MEMORY_LIMIT_ARGUMENT]),
            owned_arguments(&[MEMORY_LIMIT_ARGUMENT, "0", COMMAND_SEPARATOR, "cargo"]),
            owned_arguments(&[
                MEMORY_LIMIT_ARGUMENT,
                "not-a-number",
                COMMAND_SEPARATOR,
                "cargo",
            ]),
        ] {
            assert!(parse_arguments(arguments).is_err());
        }
    }

    #[test]
    fn refuses_a_missing_separator_or_command() {
        assert!(
            parse_arguments(owned_arguments(&[MEMORY_LIMIT_ARGUMENT, "1024", "cargo"])).is_err()
        );
        assert!(
            parse_arguments(owned_arguments(&[
                MEMORY_LIMIT_ARGUMENT,
                "1024",
                COMMAND_SEPARATOR,
            ]))
            .is_err()
        );
    }
}
