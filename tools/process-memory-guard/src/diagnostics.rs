use std::env;
use std::fs::{File, create_dir_all};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const EXPECTED_ALLOCATION_REFUSAL_ENVIRONMENT_VARIABLE: &str =
    "SEALED_LATTICE_PROCESS_MEMORY_GUARD_EXPECTED_ALLOCATION_REFUSAL";

#[derive(Debug, Default)]
pub(crate) struct ResourceSnapshot {
    pub(crate) active_process_count: Option<u64>,
    pub(crate) backend_current_memory_bytes: Option<u64>,
    pub(crate) backend_peak_job_memory_bytes: Option<u64>,
    pub(crate) backend_peak_process_memory_bytes: Option<u64>,
    pub(crate) confirmed_memory_limit_violation: bool,
    pub(crate) cpu_kernel_time_units: Option<u64>,
    pub(crate) cpu_time_unit: Option<&'static str>,
    pub(crate) cpu_user_time_units: Option<u64>,
    pub(crate) host_available_commit_bytes: Option<u64>,
    pub(crate) host_available_physical_memory_bytes: Option<u64>,
    pub(crate) host_available_swap_bytes: Option<u64>,
    pub(crate) io_read_bytes: Option<u64>,
    pub(crate) io_write_bytes: Option<u64>,
    pub(crate) maximum_process_virtual_memory_bytes: Option<u64>,
    pub(crate) process_tree_resident_memory_bytes: Option<u64>,
    pub(crate) process_tree_virtual_memory_bytes: Option<u64>,
    pub(crate) sample_error: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct ResourcePeaks {
    backend_current_memory_bytes: Option<u64>,
    backend_peak_job_memory_bytes: Option<u64>,
    backend_peak_process_memory_bytes: Option<u64>,
    maximum_process_virtual_memory_bytes: Option<u64>,
    process_tree_resident_memory_bytes: Option<u64>,
    process_tree_virtual_memory_bytes: Option<u64>,
}

impl ResourcePeaks {
    pub(crate) fn observe(&mut self, snapshot: &ResourceSnapshot) {
        update_maximum(
            &mut self.backend_current_memory_bytes,
            snapshot.backend_current_memory_bytes,
        );
        update_maximum(
            &mut self.backend_peak_job_memory_bytes,
            snapshot.backend_peak_job_memory_bytes,
        );
        update_maximum(
            &mut self.backend_peak_process_memory_bytes,
            snapshot.backend_peak_process_memory_bytes,
        );
        update_maximum(
            &mut self.maximum_process_virtual_memory_bytes,
            snapshot.maximum_process_virtual_memory_bytes,
        );
        update_maximum(
            &mut self.process_tree_resident_memory_bytes,
            snapshot.process_tree_resident_memory_bytes,
        );
        update_maximum(
            &mut self.process_tree_virtual_memory_bytes,
            snapshot.process_tree_virtual_memory_bytes,
        );
    }

    fn highest_allocation_observation(&self) -> Option<u64> {
        [
            self.backend_current_memory_bytes,
            self.backend_peak_job_memory_bytes,
            self.backend_peak_process_memory_bytes,
            self.process_tree_resident_memory_bytes,
        ]
        .into_iter()
        .flatten()
        .max()
    }
}

fn update_maximum(target: &mut Option<u64>, value: Option<u64>) {
    if let Some(value) = value {
        *target = Some(target.map_or(value, |current| current.max(value)));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemoryEvidence {
    Completed,
    Confirmed,
    Suspected,
    Unknown,
}

impl MemoryEvidence {
    pub(crate) fn from_observations(
        memory_limit_bytes: u64,
        virtual_address_space_allowance_bytes: u64,
        peaks: &ResourcePeaks,
        confirmed_limit_violation: bool,
        child_was_successful: bool,
    ) -> Self {
        if child_was_successful {
            return Self::Completed;
        }
        if confirmed_limit_violation {
            return Self::Confirmed;
        }

        let near_limit_threshold = memory_limit_bytes.saturating_mul(9) / 10;
        let allocation_was_near_limit = peaks
            .highest_allocation_observation()
            .is_some_and(|observation| observation >= near_limit_threshold);
        let virtual_address_space_limit =
            memory_limit_bytes.saturating_add(virtual_address_space_allowance_bytes);
        let virtual_address_space_was_near_limit = peaks
            .maximum_process_virtual_memory_bytes
            .is_some_and(|observation| {
                observation >= virtual_address_space_limit.saturating_mul(9) / 10
            });
        if allocation_was_near_limit || virtual_address_space_was_near_limit {
            return Self::Suspected;
        }

        Self::Unknown
    }

    fn label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Confirmed => "confirmed",
            Self::Suspected => "suspected",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug)]
pub(crate) struct TerminationDetails {
    pub(crate) core_dumped: Option<bool>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) raw_status_signed: Option<i64>,
    pub(crate) raw_status_unsigned: Option<u64>,
    pub(crate) signal_name: Option<&'static str>,
    pub(crate) signal_number: Option<i32>,
}

impl TerminationDetails {
    pub(crate) fn was_successful(&self) -> bool {
        self.exit_code == Some(0) && self.signal_number.is_none()
    }

    fn classification(&self, memory_evidence: MemoryEvidence) -> &'static str {
        match memory_evidence {
            MemoryEvidence::Completed => "completed",
            MemoryEvidence::Confirmed => "memory-limit-confirmed",
            MemoryEvidence::Suspected => "memory-exhaustion-suspected",
            MemoryEvidence::Unknown if self.signal_number.is_some() => "external-signal",
            MemoryEvidence::Unknown if self.exit_code.is_some() => "nonzero-exit",
            MemoryEvidence::Unknown => "abnormal-termination-unknown",
        }
    }
}

pub(crate) fn expected_diagnostic_label() -> Option<&'static str> {
    match env::var(EXPECTED_ALLOCATION_REFUSAL_ENVIRONMENT_VARIABLE) {
        Ok(value) if value == "1" => Some("controlled-allocation-refusal"),
        _ => None,
    }
}

pub(crate) struct DiagnosticsWriter {
    elapsed_start: Instant,
    output: BufWriter<File>,
    path: PathBuf,
    sequence: u64,
}

pub(crate) struct GuardStartedDetails<'a> {
    pub(crate) aggregate_process_tree_limit: bool,
    pub(crate) containment_backend: &'a str,
    pub(crate) containment_scope: &'a str,
    pub(crate) expected_diagnostic: Option<&'a str>,
    pub(crate) memory_limit_bytes: u64,
    pub(crate) sample_interval: Duration,
    pub(crate) virtual_address_space_allowance_bytes: u64,
}

impl DiagnosticsWriter {
    pub(crate) fn create(requested_path: &Path) -> Result<Self, String> {
        let path = if requested_path.is_absolute() {
            requested_path.to_path_buf()
        } else {
            env::current_dir()
                .map_err(|error| {
                    format!("failed to resolve process-memory diagnostics path: {error}")
                })?
                .join(requested_path)
        };
        let parent = path.parent().ok_or_else(|| {
            format!(
                "process-memory diagnostics path has no parent: {}",
                path.display()
            )
        })?;
        create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create process-memory diagnostics directory {}: {error}",
                parent.display()
            )
        })?;
        let file = File::create(&path).map_err(|error| {
            format!(
                "failed to create process-memory diagnostics file {}: {error}",
                path.display()
            )
        })?;

        Ok(Self {
            elapsed_start: Instant::now(),
            output: BufWriter::new(file),
            path,
            sequence: 0,
        })
    }

    pub(crate) fn write_guard_started(
        &mut self,
        details: GuardStartedDetails<'_>,
    ) -> Result<(), String> {
        let path = self.path.display().to_string();
        self.write_event("guard-started", |record| {
            record.string("diagnosticsPath", &path);
            record.unsigned("guardProcessId", u64::from(std::process::id()));
            record.unsigned("memoryLimitBytes", details.memory_limit_bytes);
            record.unsigned(
                "virtualAddressSpaceAllowanceBytes",
                details.virtual_address_space_allowance_bytes,
            );
            record.string("containmentBackend", details.containment_backend);
            record.string("containmentScope", details.containment_scope);
            record.boolean(
                "aggregateProcessTreeMemoryLimit",
                details.aggregate_process_tree_limit,
            );
            record.unsigned(
                "resourceSampleIntervalMilliseconds",
                duration_milliseconds(details.sample_interval),
            );
            record.optional_string("expectedDiagnostic", details.expected_diagnostic);
        })
    }

    pub(crate) fn write_child_started(&mut self, child_process_id: u32) -> Result<(), String> {
        self.write_event("child-started", |record| {
            record.unsigned("guardProcessId", u64::from(std::process::id()));
            record.unsigned("childProcessId", u64::from(child_process_id));
        })
    }

    pub(crate) fn write_resource_sample(
        &mut self,
        snapshot: &ResourceSnapshot,
        peaks: &ResourcePeaks,
    ) -> Result<(), String> {
        self.write_event("resource-sample", |record| {
            record.optional_unsigned("activeProcessCount", snapshot.active_process_count);
            record.optional_unsigned(
                "backendCurrentMemoryBytes",
                snapshot.backend_current_memory_bytes,
            );
            record.optional_unsigned(
                "backendPeakJobMemoryBytes",
                snapshot.backend_peak_job_memory_bytes,
            );
            record.optional_unsigned(
                "backendPeakProcessMemoryBytes",
                snapshot.backend_peak_process_memory_bytes,
            );
            record.boolean(
                "confirmedMemoryLimitViolation",
                snapshot.confirmed_memory_limit_violation,
            );
            record.optional_unsigned("cpuKernelTimeUnits", snapshot.cpu_kernel_time_units);
            record.optional_string("cpuTimeUnit", snapshot.cpu_time_unit);
            record.optional_unsigned("cpuUserTimeUnits", snapshot.cpu_user_time_units);
            record.optional_unsigned(
                "hostAvailableCommitBytes",
                snapshot.host_available_commit_bytes,
            );
            record.optional_unsigned(
                "hostAvailablePhysicalMemoryBytes",
                snapshot.host_available_physical_memory_bytes,
            );
            record.optional_unsigned("hostAvailableSwapBytes", snapshot.host_available_swap_bytes);
            record.optional_unsigned("ioReadBytes", snapshot.io_read_bytes);
            record.optional_unsigned("ioWriteBytes", snapshot.io_write_bytes);
            record.optional_unsigned(
                "maximumProcessVirtualMemoryBytes",
                snapshot.maximum_process_virtual_memory_bytes,
            );
            record.optional_unsigned(
                "processTreeResidentMemoryBytes",
                snapshot.process_tree_resident_memory_bytes,
            );
            record.optional_unsigned(
                "processTreeVirtualMemoryBytes",
                snapshot.process_tree_virtual_memory_bytes,
            );
            record.optional_string("sampleError", snapshot.sample_error.as_deref());
            write_peak_fields(record, peaks);
        })
    }

    pub(crate) fn write_child_exited(
        &mut self,
        duration: Duration,
        termination: &TerminationDetails,
        peaks: &ResourcePeaks,
        memory_evidence: MemoryEvidence,
        expected_diagnostic: Option<&str>,
    ) -> Result<(), String> {
        self.write_event("child-exited", |record| {
            record.unsigned("durationMilliseconds", duration_milliseconds(duration));
            record.optional_signed("exitCode", termination.exit_code.map(i64::from));
            record.optional_signed("rawStatusSigned", termination.raw_status_signed);
            record.optional_unsigned("rawStatusUnsigned", termination.raw_status_unsigned);
            if let Some(raw_status) = termination.raw_status_unsigned {
                record.string("rawStatusHex", &format!("0x{raw_status:08X}"));
            } else {
                record.null("rawStatusHex");
            }
            record.optional_signed("signalNumber", termination.signal_number.map(i64::from));
            record.optional_string("signalName", termination.signal_name);
            record.optional_boolean("coreDumped", termination.core_dumped);
            record.string("memoryEvidence", memory_evidence.label());
            record.string(
                "terminationClassification",
                termination.classification(memory_evidence),
            );
            record.optional_string("expectedDiagnostic", expected_diagnostic);
            write_peak_fields(record, peaks);
        })?;
        self.output.get_ref().sync_data().map_err(|error| {
            format!(
                "failed to sync process-memory diagnostics file {}: {error}",
                self.path.display()
            )
        })
    }

    pub(crate) fn write_guard_error(&mut self, phase: &str, error: &str) -> Result<(), String> {
        self.write_event("guard-error", |record| {
            record.string("phase", phase);
            record.string("error", error);
        })?;
        self.output.get_ref().sync_data().map_err(|sync_error| {
            format!(
                "failed to sync process-memory diagnostics file {} after {phase} error: {sync_error}",
                self.path.display()
            )
        })
    }

    fn write_event(
        &mut self,
        event_type: &str,
        add_fields: impl FnOnce(&mut JsonObject),
    ) -> Result<(), String> {
        let mut record = JsonObject::default();
        record.string("eventType", event_type);
        record.unsigned("sequence", self.sequence);
        let (timestamp_iso, timestamp_unix_milliseconds) = current_timestamp();
        record.string("recordedAtIso", &timestamp_iso);
        record.unsigned("recordedAtUnixMilliseconds", timestamp_unix_milliseconds);
        record.unsigned(
            "elapsedMilliseconds",
            duration_milliseconds(self.elapsed_start.elapsed()),
        );
        add_fields(&mut record);

        self.output
            .write_all(format!("{}\n", record.finish()).as_bytes())
            .and_then(|()| self.output.flush())
            .map_err(|error| {
                format!(
                    "failed to append process-memory diagnostics file {}: {error}",
                    self.path.display()
                )
            })?;
        self.sequence = self.sequence.saturating_add(1);
        Ok(())
    }
}

fn write_peak_fields(record: &mut JsonObject, peaks: &ResourcePeaks) {
    record.optional_unsigned(
        "observedPeakBackendCurrentMemoryBytes",
        peaks.backend_current_memory_bytes,
    );
    record.optional_unsigned(
        "observedPeakBackendJobMemoryBytes",
        peaks.backend_peak_job_memory_bytes,
    );
    record.optional_unsigned(
        "observedPeakBackendProcessMemoryBytes",
        peaks.backend_peak_process_memory_bytes,
    );
    record.optional_unsigned(
        "observedMaximumProcessVirtualMemoryBytes",
        peaks.maximum_process_virtual_memory_bytes,
    );
    record.optional_unsigned(
        "observedPeakProcessTreeResidentMemoryBytes",
        peaks.process_tree_resident_memory_bytes,
    );
    record.optional_unsigned(
        "observedPeakProcessTreeVirtualMemoryBytes",
        peaks.process_tree_virtual_memory_bytes,
    );
}

fn duration_milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Default)]
struct JsonObject {
    fields: Vec<String>,
}

impl JsonObject {
    fn boolean(&mut self, name: &str, value: bool) {
        self.push(name, if value { "true" } else { "false" }.to_owned());
    }

    fn null(&mut self, name: &str) {
        self.push(name, "null".to_owned());
    }

    fn optional_boolean(&mut self, name: &str, value: Option<bool>) {
        match value {
            Some(value) => self.boolean(name, value),
            None => self.null(name),
        }
    }

    fn optional_signed(&mut self, name: &str, value: Option<i64>) {
        match value {
            Some(value) => self.signed(name, value),
            None => self.null(name),
        }
    }

    fn optional_string(&mut self, name: &str, value: Option<&str>) {
        match value {
            Some(value) => self.string(name, value),
            None => self.null(name),
        }
    }

    fn optional_unsigned(&mut self, name: &str, value: Option<u64>) {
        match value {
            Some(value) => self.unsigned(name, value),
            None => self.null(name),
        }
    }

    fn signed(&mut self, name: &str, value: i64) {
        self.push(name, value.to_string());
    }

    fn string(&mut self, name: &str, value: &str) {
        self.push(name, format!("\"{}\"", escape_json_string(value)));
    }

    fn unsigned(&mut self, name: &str, value: u64) {
        self.push(name, value.to_string());
    }

    fn push(&mut self, name: &str, encoded_value: String) {
        self.fields.push(format!(
            "\"{}\":{}",
            escape_json_string(name),
            encoded_value
        ));
    }

    fn finish(self) -> String {
        format!("{{{}}}", self.fields.join(","))
    }
}

fn escape_json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0C}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character <= '\u{1F}' => {
                escaped.push_str(&format!("\\u{:04X}", u32::from(character)));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn current_timestamp() -> (String, u64) {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let milliseconds = u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX);
    (format_unix_milliseconds(milliseconds), milliseconds)
}

fn format_unix_milliseconds(milliseconds: u64) -> String {
    let total_seconds = milliseconds / 1_000;
    let milliseconds_within_second = milliseconds % 1_000;
    let days_since_epoch = i64::try_from(total_seconds / 86_400).unwrap_or(i64::MAX);
    let seconds_within_day = total_seconds % 86_400;
    let hour = seconds_within_day / 3_600;
    let minute = (seconds_within_day % 3_600) / 60;
    let second = seconds_within_day % 60;
    let (year, month, day) = civil_date_from_days_since_epoch(days_since_epoch);

    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds_within_second:03}Z"
    )
}

// This is Howard Hinnant's civil-from-days conversion, specialized to dates
// after the Unix epoch. It avoids pulling a date-time dependency into the
// small containment executable solely to format diagnostic timestamps.
fn civil_date_from_days_since_epoch(days_since_epoch: i64) -> (i64, i64, i64) {
    let shifted_days = days_since_epoch + 719_468;
    let era = shifted_days / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_epoch_and_leap_day_timestamps_as_utc_iso() {
        assert_eq!(format_unix_milliseconds(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            format_unix_milliseconds(1_709_164_800_123),
            "2024-02-29T00:00:00.123Z"
        );
    }

    #[test]
    fn escapes_every_json_control_character_used_by_paths_and_errors() {
        assert_eq!(
            escape_json_string("C:\\logs\n\"failure\"\u{01}"),
            "C:\\\\logs\\n\\\"failure\\\"\\u0001"
        );
    }

    #[test]
    fn does_not_treat_a_nonzero_exit_or_signal_as_confirmed_memory_exhaustion() {
        assert_eq!(
            MemoryEvidence::from_observations(1_000, 0, &ResourcePeaks::default(), false, false,),
            MemoryEvidence::Unknown
        );
    }

    #[test]
    fn distinguishes_confirmed_and_near_limit_memory_evidence() {
        let peaks = ResourcePeaks {
            maximum_process_virtual_memory_bytes: Some(950),
            ..ResourcePeaks::default()
        };
        assert_eq!(
            MemoryEvidence::from_observations(1_000, 0, &peaks, false, false),
            MemoryEvidence::Suspected
        );
        assert_eq!(
            MemoryEvidence::from_observations(1_000, 0, &peaks, true, false),
            MemoryEvidence::Confirmed
        );
        assert_eq!(
            MemoryEvidence::from_observations(1_000, 0, &peaks, true, true),
            MemoryEvidence::Completed
        );
    }

    #[test]
    fn does_not_treat_an_allowed_virtual_reservation_as_memory_pressure() {
        let peaks = ResourcePeaks {
            maximum_process_virtual_memory_bytes: Some(8_500),
            ..ResourcePeaks::default()
        };

        assert_eq!(
            MemoryEvidence::from_observations(1_000, 9_000, &peaks, false, false),
            MemoryEvidence::Unknown
        );
    }
}
