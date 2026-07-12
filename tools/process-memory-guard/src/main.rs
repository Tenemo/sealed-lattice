#![deny(unsafe_op_in_unsafe_fn)]

mod diagnostics;
mod platform;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use diagnostics::{
    DiagnosticsWriter, GuardStartedDetails, MemoryEvidence, ResourcePeaks,
    expected_diagnostic_label,
};

const MEMORY_LIMIT_ARGUMENT: &str = "--memory-limit-bytes";
const DIAGNOSTICS_PATH_ARGUMENT: &str = "--diagnostics-path";
const VIRTUAL_ADDRESS_SPACE_ALLOWANCE_ARGUMENT: &str = "--virtual-address-space-allowance-bytes";
const COMMAND_SEPARATOR: &str = "--";
const RESOURCE_SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
const CHILD_STATUS_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Eq, PartialEq)]
struct GuardedCommand {
    memory_limit_bytes: u64,
    virtual_address_space_allowance_bytes: u64,
    diagnostics_path: Option<PathBuf>,
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

    let mut diagnostics_path = None;
    let mut virtual_address_space_allowance_bytes = 0;
    let mut virtual_address_space_allowance_was_set = false;
    loop {
        let option = arguments
            .next()
            .ok_or_else(|| usage("missing command separator"))?;
        if option == COMMAND_SEPARATOR {
            break;
        }
        if option == DIAGNOSTICS_PATH_ARGUMENT {
            if diagnostics_path.is_some() {
                return Err(usage("diagnostics path was supplied more than once"));
            }
            let path = arguments
                .next()
                .ok_or_else(|| usage("missing diagnostics path"))?;
            if path.is_empty() {
                return Err(usage("diagnostics path must not be empty"));
            }
            diagnostics_path = Some(PathBuf::from(path));
            continue;
        }
        if option == VIRTUAL_ADDRESS_SPACE_ALLOWANCE_ARGUMENT {
            if virtual_address_space_allowance_was_set {
                return Err(usage(
                    "virtual address-space allowance was supplied more than once",
                ));
            }
            let value = arguments
                .next()
                .ok_or_else(|| usage("missing virtual address-space allowance value"))?;
            virtual_address_space_allowance_bytes = value
                .to_str()
                .ok_or_else(|| usage("virtual address-space allowance must be UTF-8"))?
                .parse::<u64>()
                .map_err(|_| {
                    usage("virtual address-space allowance must be a non-negative integer")
                })?;
            virtual_address_space_allowance_was_set = true;
            continue;
        }
        return Err(usage(&format!(
            "unexpected process-memory guard option {}",
            option.to_string_lossy()
        )));
    }

    let program = arguments
        .next()
        .ok_or_else(|| usage("missing guarded command"))?;

    Ok(GuardedCommand {
        memory_limit_bytes,
        virtual_address_space_allowance_bytes,
        diagnostics_path,
        program,
        arguments: arguments.collect(),
    })
}

fn usage(reason: &str) -> String {
    format!(
        "{reason}. Usage: sealed-lattice-process-memory-guard {MEMORY_LIMIT_ARGUMENT} <bytes> [{VIRTUAL_ADDRESS_SPACE_ALLOWANCE_ARGUMENT} <bytes>] [{DIAGNOSTICS_PATH_ARGUMENT} <path>] {COMMAND_SEPARATOR} <command> [arguments...]"
    )
}

struct GuardRunResult {
    _containment: platform::MemoryContainment,
    diagnostics_error: Option<String>,
    exit_status: ExitStatus,
}

fn run_guarded_command(command: GuardedCommand) -> Result<GuardRunResult, String> {
    let mut diagnostics = command
        .diagnostics_path
        .as_deref()
        .map(DiagnosticsWriter::create)
        .transpose()?;
    let guard_started_at = Instant::now();
    let expected_diagnostic = expected_diagnostic_label();

    if let Some(writer) = diagnostics.as_mut() {
        writer.write_guard_started(GuardStartedDetails {
            aggregate_process_tree_limit: platform::AGGREGATE_PROCESS_TREE_LIMIT,
            containment_backend: platform::CONTAINMENT_BACKEND,
            containment_scope: platform::CONTAINMENT_SCOPE,
            expected_diagnostic,
            memory_limit_bytes: command.memory_limit_bytes,
            sample_interval: RESOURCE_SAMPLE_INTERVAL,
            virtual_address_space_allowance_bytes: command.virtual_address_space_allowance_bytes,
        })?;
    }

    let containment = match platform::MemoryContainment::apply(
        command.memory_limit_bytes,
        command.virtual_address_space_allowance_bytes,
    ) {
        Ok(containment) => containment,
        Err(error) => {
            if let Some(writer) = diagnostics.as_mut() {
                writer.write_guard_error("containment-setup", &error)?;
            }
            return Err(error);
        }
    };

    let mut child = match Command::new(&command.program)
        .args(&command.arguments)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let message = format!(
                "failed to start guarded command {}: {error}",
                command.program.to_string_lossy()
            );
            if let Some(writer) = diagnostics.as_mut() {
                writer.write_guard_error("child-spawn", &message)?;
            }
            return Err(message);
        }
    };

    if let Some(writer) = diagnostics.as_mut() {
        writer.write_child_started(child.id())?;
    }

    let mut peaks = ResourcePeaks::default();
    let mut confirmed_limit_violation = false;
    let mut diagnostics_error = None;
    let exit_status = if diagnostics.is_some() {
        let mut next_sample_at = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => {
                    let message = format!("failed to wait for guarded command: {error}");
                    if let Some(writer) = diagnostics.as_mut() {
                        writer.write_guard_error("child-wait", &message)?;
                    }
                    return Err(message);
                }
            }

            let now = Instant::now();
            if now >= next_sample_at {
                let snapshot = containment.sample(std::process::id());
                peaks.observe(&snapshot);
                confirmed_limit_violation |= snapshot.confirmed_memory_limit_violation;
                if let Some(writer) = diagnostics.as_mut()
                    && let Err(error) = writer.write_resource_sample(&snapshot, &peaks)
                {
                    eprintln!("Process memory guard diagnostics failed: {error}");
                    diagnostics_error = Some(error);
                    diagnostics = None;
                }
                next_sample_at = now + RESOURCE_SAMPLE_INTERVAL;
            }
            thread::sleep(CHILD_STATUS_POLL_INTERVAL);
        }
    } else {
        child
            .wait()
            .map_err(|error| format!("failed to wait for guarded command: {error}"))?
    };

    if let Some(writer) = diagnostics.as_mut() {
        let final_snapshot = containment.sample(std::process::id());
        peaks.observe(&final_snapshot);
        confirmed_limit_violation |= final_snapshot.confirmed_memory_limit_violation;
        if let Err(error) = writer.write_resource_sample(&final_snapshot, &peaks) {
            eprintln!("Process memory guard diagnostics failed: {error}");
            diagnostics_error = Some(error);
            diagnostics = None;
        }
    }

    let termination = platform::termination_details(exit_status);
    let memory_evidence = MemoryEvidence::from_observations(
        command.memory_limit_bytes,
        command.virtual_address_space_allowance_bytes,
        &peaks,
        confirmed_limit_violation,
        termination.was_successful(),
    );
    if let Some(writer) = diagnostics.as_mut()
        && let Err(error) = writer.write_child_exited(
            guard_started_at.elapsed(),
            &termination,
            &peaks,
            memory_evidence,
            expected_diagnostic,
        )
    {
        eprintln!("Process memory guard diagnostics failed: {error}");
        diagnostics_error = Some(error);
    }

    Ok(GuardRunResult {
        _containment: containment,
        diagnostics_error,
        exit_status,
    })
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
        Ok(result) => {
            if let Some(error) = result.diagnostics_error {
                eprintln!(
                    "Process memory guard failed because requested diagnostics could not be completed: {error}"
                );
                std::process::exit(1);
            }
            platform::exit_like_child(result.exit_status);
        }
        Err(error) => {
            eprintln!("Process memory guard failed: {error}");
            std::process::exit(1);
        }
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
                virtual_address_space_allowance_bytes: 0,
                diagnostics_path: None,
                program: OsString::from("cargo"),
                arguments: owned_arguments(&["test", COMMAND_SEPARATOR, "--test-threads", "1"]),
            }
        );
    }

    #[test]
    fn parses_an_optional_diagnostics_path_before_the_command_separator() {
        let parsed = parse_arguments(owned_arguments(&[
            MEMORY_LIMIT_ARGUMENT,
            "4096",
            DIAGNOSTICS_PATH_ARGUMENT,
            "logs/run/resources/guard.jsonl",
            COMMAND_SEPARATOR,
            "node",
            "test.js",
        ]))
        .expect("guarded command with diagnostics");

        assert_eq!(
            parsed,
            GuardedCommand {
                memory_limit_bytes: 4096,
                virtual_address_space_allowance_bytes: 0,
                diagnostics_path: Some(PathBuf::from("logs/run/resources/guard.jsonl")),
                program: OsString::from("node"),
                arguments: owned_arguments(&["test.js"]),
            }
        );
    }

    #[test]
    fn parses_virtual_address_space_allowance_and_diagnostics_in_either_order() {
        for optional_arguments in [
            [
                VIRTUAL_ADDRESS_SPACE_ALLOWANCE_ARGUMENT,
                "8589934592",
                DIAGNOSTICS_PATH_ARGUMENT,
                "guard.jsonl",
            ],
            [
                DIAGNOSTICS_PATH_ARGUMENT,
                "guard.jsonl",
                VIRTUAL_ADDRESS_SPACE_ALLOWANCE_ARGUMENT,
                "8589934592",
            ],
        ] {
            let mut arguments = owned_arguments(&[MEMORY_LIMIT_ARGUMENT, "1073741824"]);
            arguments.extend(owned_arguments(&optional_arguments));
            arguments.extend(owned_arguments(&[COMMAND_SEPARATOR, "node"]));
            let parsed = parse_arguments(arguments).expect("optional guard arguments");

            assert_eq!(parsed.memory_limit_bytes, 1_073_741_824);
            assert_eq!(parsed.virtual_address_space_allowance_bytes, 8_589_934_592);
            assert_eq!(parsed.diagnostics_path, Some(PathBuf::from("guard.jsonl")));
        }
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
    fn refuses_a_missing_separator_command_or_diagnostics_path() {
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
        assert!(
            parse_arguments(owned_arguments(&[
                MEMORY_LIMIT_ARGUMENT,
                "1024",
                DIAGNOSTICS_PATH_ARGUMENT,
            ]))
            .is_err()
        );
    }
}
