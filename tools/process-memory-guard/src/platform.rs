use std::process::ExitStatus;

use crate::diagnostics::{ResourceSnapshot, TerminationDetails};

#[cfg(target_os = "windows")]
mod implementation {
    use std::ffi::c_void;
    use std::io;
    use std::mem::size_of;
    use std::ptr;

    use super::*;

    type Handle = *mut c_void;

    const JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS: i32 = 1;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
    const JOB_OBJECT_LIMIT_VIOLATION_INFORMATION_2_CLASS: i32 = 34;
    const JOB_OBJECT_LIMIT_JOB_MEMORY: u32 = 0x0000_0200;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

    pub(crate) const CONTAINMENT_BACKEND: &str = "windows-job-object-job-memory";
    pub(crate) const CONTAINMENT_SCOPE: &str = "guard-and-descendant-process-tree";
    pub(crate) const AGGREGATE_PROCESS_TREE_LIMIT: bool = true;

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

    #[repr(C)]
    #[derive(Default)]
    struct JobObjectBasicAccountingInformation {
        total_user_time: i64,
        total_kernel_time: i64,
        this_period_total_user_time: i64,
        this_period_total_kernel_time: i64,
        total_page_fault_count: u32,
        total_processes: u32,
        active_processes: u32,
        total_terminated_processes: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct JobObjectLimitViolationInformation2 {
        limit_flags: u32,
        violation_limit_flags: u32,
        io_read_bytes: u64,
        io_read_bytes_limit: u64,
        io_write_bytes: u64,
        io_write_bytes_limit: u64,
        per_job_user_time: i64,
        per_job_user_time_limit: i64,
        job_memory: u64,
        job_memory_limit: u64,
        rate_control_tolerance: i32,
        rate_control_tolerance_limit: i32,
        job_low_memory_limit: u64,
        io_rate_control_tolerance: i32,
        io_rate_control_tolerance_limit: i32,
        net_rate_control_tolerance: i32,
        net_rate_control_tolerance_limit: i32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct MemoryStatusExtended {
        structure_length: u32,
        memory_load_percent: u32,
        total_physical_bytes: u64,
        available_physical_bytes: u64,
        total_page_file_bytes: u64,
        available_page_file_bytes: u64,
        total_virtual_bytes: u64,
        available_virtual_bytes: u64,
        available_extended_virtual_bytes: u64,
    }

    unsafe extern "system" {
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn CloseHandle(object: Handle) -> i32;
        fn CreateJobObjectW(job_attributes: *const c_void, name: *const u16) -> Handle;
        fn GetCurrentProcess() -> Handle;
        fn GlobalMemoryStatusEx(memory_status: *mut MemoryStatusExtended) -> i32;
        fn QueryInformationJobObject(
            job: Handle,
            information_class: i32,
            information: *mut c_void,
            information_length: u32,
            return_length: *mut u32,
        ) -> i32;
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
            // this wrapper closes it at most once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub(crate) struct MemoryContainment {
        job_handle: OwnedJobHandle,
    }

    impl MemoryContainment {
        pub(crate) fn apply(
            memory_limit_bytes: u64,
            _virtual_address_space_allowance_bytes: u64,
        ) -> Result<Self, String> {
            let job_memory_limit = usize::try_from(memory_limit_bytes).map_err(|_| {
                format!(
                    "memory limit {memory_limit_bytes} cannot be represented on this Windows target"
                )
            })?;
            let information_length = structure_length::<JobObjectExtendedLimitInformation>()?;

            // SAFETY: Null attributes and name request an unnamed job with the
            // current process's default security descriptor. The returned
            // handle is checked before being wrapped as owned.
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

            // SAFETY: The pointer addresses a repr(C) structure of the exact
            // supplied size, and the job handle remains valid for the call.
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

            // Assign the launcher before it creates the guarded command.
            // Windows associates children with the same job by default, which
            // avoids a race between spawn and child assignment.
            // SAFETY: GetCurrentProcess returns a valid pseudo-handle with the
            // access required to assign this process to the valid job.
            let process_was_assigned =
                unsafe { AssignProcessToJobObject(job_handle.0, GetCurrentProcess()) };
            if process_was_assigned == 0 {
                return Err(format!(
                    "AssignProcessToJobObject failed: {}",
                    io::Error::last_os_error()
                ));
            }

            Ok(Self { job_handle })
        }

        pub(crate) fn sample(&self, _guard_process_id: u32) -> ResourceSnapshot {
            let mut snapshot = ResourceSnapshot::default();
            let mut sample_errors = Vec::new();

            match query_job_information::<JobObjectExtendedLimitInformation>(
                self.job_handle.0,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ) {
                Ok(information) => {
                    snapshot.backend_peak_process_memory_bytes =
                        u64::try_from(information.peak_process_memory_used).ok();
                    snapshot.backend_peak_job_memory_bytes =
                        u64::try_from(information.peak_job_memory_used).ok();
                    snapshot.io_read_bytes = Some(information.io_information.read_transfer_count);
                    snapshot.io_write_bytes = Some(information.io_information.write_transfer_count);
                }
                Err(error) => sample_errors.push(error),
            }

            match query_job_information::<JobObjectBasicAccountingInformation>(
                self.job_handle.0,
                JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS,
            ) {
                Ok(information) => {
                    snapshot.active_process_count = Some(u64::from(information.active_processes));
                    snapshot.cpu_user_time_units = u64::try_from(information.total_user_time).ok();
                    snapshot.cpu_kernel_time_units =
                        u64::try_from(information.total_kernel_time).ok();
                    snapshot.cpu_time_unit = Some("100-nanosecond-intervals");
                }
                Err(error) => sample_errors.push(error),
            }

            match query_job_information::<JobObjectLimitViolationInformation2>(
                self.job_handle.0,
                JOB_OBJECT_LIMIT_VIOLATION_INFORMATION_2_CLASS,
            ) {
                Ok(information) => {
                    snapshot.backend_current_memory_bytes = Some(information.job_memory);
                    snapshot.confirmed_memory_limit_violation =
                        information.violation_limit_flags & JOB_OBJECT_LIMIT_JOB_MEMORY != 0;
                }
                Err(error) => sample_errors.push(error),
            }

            match query_host_memory() {
                Ok(information) => {
                    snapshot.host_available_physical_memory_bytes =
                        Some(information.available_physical_bytes);
                    // Windows reports page-file/commit availability rather
                    // than a portable swap-only value, so keep it distinctly
                    // labelled instead of presenting it as swap.
                    snapshot.host_available_commit_bytes =
                        Some(information.available_page_file_bytes);
                }
                Err(error) => sample_errors.push(error),
            }

            if !sample_errors.is_empty() {
                snapshot.sample_error = Some(sample_errors.join("; "));
            }
            snapshot
        }
    }

    fn structure_length<T>() -> Result<u32, String> {
        u32::try_from(size_of::<T>())
            .map_err(|_| "Windows job information structure is unexpectedly large".to_owned())
    }

    fn query_job_information<T: Default>(
        job_handle: Handle,
        information_class: i32,
    ) -> Result<T, String> {
        let mut information = T::default();
        let information_length = structure_length::<T>()?;
        // SAFETY: The output pointer addresses a writable value of the exact
        // repr(C) structure selected by information_class. The handle remains
        // valid for the call and no return-length pointer is needed.
        let succeeded = unsafe {
            QueryInformationJobObject(
                job_handle,
                information_class,
                ptr::from_mut(&mut information).cast(),
                information_length,
                ptr::null_mut(),
            )
        };
        if succeeded == 0 {
            return Err(format!(
                "QueryInformationJobObject class {information_class} failed: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(information)
    }

    fn query_host_memory() -> Result<MemoryStatusExtended, String> {
        let mut information = MemoryStatusExtended {
            structure_length: structure_length::<MemoryStatusExtended>()?,
            ..MemoryStatusExtended::default()
        };
        // SAFETY: information points to a writable MEMORYSTATUSEX-compatible
        // repr(C) value whose dwLength field has been initialized correctly.
        let succeeded = unsafe { GlobalMemoryStatusEx(&mut information) };
        if succeeded == 0 {
            return Err(format!(
                "GlobalMemoryStatusEx failed: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(information)
    }

    pub(crate) fn termination_details(status: ExitStatus) -> TerminationDetails {
        let exit_code = status.code();
        let raw_status_unsigned = exit_code.map(|code| u64::from(code as u32));
        TerminationDetails {
            core_dumped: None,
            exit_code,
            raw_status_signed: exit_code.map(i64::from),
            raw_status_unsigned,
            signal_name: None,
            signal_number: None,
        }
    }

    pub(crate) fn exit_like_child(status: ExitStatus) -> ! {
        std::process::exit(status.code().unwrap_or(1));
    }
}

#[cfg(target_os = "linux")]
mod implementation {
    use std::collections::{HashMap, HashSet};
    use std::ffi::c_int;
    use std::fs;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;

    use super::*;

    const RESOURCE_LIMIT_DATA: c_int = 2;
    const RESOURCE_LIMIT_ADDRESS_SPACE: c_int = 9;
    const SYSTEM_CONFIGURATION_PAGE_SIZE: c_int = 30;

    pub(crate) const CONTAINMENT_BACKEND: &str = "linux-rlimit-data-and-as";
    pub(crate) const CONTAINMENT_SCOPE: &str = "inherited-per-process-data-and-virtual-address-space-limits; RLIMIT_DATA uses the memory limit and RLIMIT_AS adds the configured inaccessible-reservation allowance";
    pub(crate) const AGGREGATE_PROCESS_TREE_LIMIT: bool = false;

    #[repr(C)]
    struct ResourceLimit {
        current: usize,
        maximum: usize,
    }

    unsafe extern "C" {
        fn raise(signal: c_int) -> c_int;
        fn setrlimit(resource: c_int, limits: *const ResourceLimit) -> c_int;
        fn signal(
            signal: c_int,
            handler: Option<unsafe extern "C" fn(c_int)>,
        ) -> Option<unsafe extern "C" fn(c_int)>;
        fn sysconf(name: c_int) -> isize;
    }

    pub(crate) struct MemoryContainment {
        page_size_bytes: Option<u64>,
    }

    impl MemoryContainment {
        pub(crate) fn apply(
            memory_limit_bytes: u64,
            virtual_address_space_allowance_bytes: u64,
        ) -> Result<Self, String> {
            let data_memory_limit = usize::try_from(memory_limit_bytes).map_err(|_| {
                format!(
                    "memory limit {memory_limit_bytes} cannot be represented on this Linux target"
                )
            })?;
            let virtual_address_space_limit_bytes = memory_limit_bytes
                .checked_add(virtual_address_space_allowance_bytes)
                .ok_or_else(|| {
                    format!(
                        "memory limit {memory_limit_bytes} plus virtual address-space allowance {virtual_address_space_allowance_bytes} overflows u64"
                    )
                })?;
            let virtual_address_space_limit = usize::try_from(
                virtual_address_space_limit_bytes,
            )
            .map_err(|_| {
                format!(
                    "virtual address-space limit {virtual_address_space_limit_bytes} cannot be represented on this Linux target"
                )
            })?;
            let data_limits = ResourceLimit {
                current: data_memory_limit,
                maximum: data_memory_limit,
            };

            // SAFETY: The pointer addresses a repr(C) rlimit-compatible
            // structure for Linux and remains valid for this call.
            let data_result = unsafe { setrlimit(RESOURCE_LIMIT_DATA, &data_limits) };
            if data_result != 0 {
                return Err(format!(
                    "setrlimit(RLIMIT_DATA) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let address_space_limits = ResourceLimit {
                current: virtual_address_space_limit,
                maximum: virtual_address_space_limit,
            };
            // SAFETY: The pointer addresses a repr(C) rlimit-compatible
            // structure for Linux and remains valid for this call.
            let address_space_result =
                unsafe { setrlimit(RESOURCE_LIMIT_ADDRESS_SPACE, &address_space_limits) };
            if address_space_result != 0 {
                return Err(format!(
                    "setrlimit(RLIMIT_AS) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // SAFETY: sysconf has no pointer preconditions and _SC_PAGESIZE is
            // a valid Linux configuration selector.
            let page_size = unsafe { sysconf(SYSTEM_CONFIGURATION_PAGE_SIZE) };
            let page_size_bytes = u64::try_from(page_size).ok().filter(|size| *size > 0);
            Ok(Self { page_size_bytes })
        }

        pub(crate) fn sample(&self, guard_process_id: u32) -> ResourceSnapshot {
            let mut snapshot = ResourceSnapshot::default();
            let mut errors = Vec::new();

            match sample_descendants(guard_process_id, self.page_size_bytes) {
                Ok(process_sample) => {
                    snapshot.active_process_count = Some(process_sample.process_count);
                    snapshot.process_tree_resident_memory_bytes =
                        Some(process_sample.resident_memory_bytes);
                    snapshot.process_tree_virtual_memory_bytes =
                        Some(process_sample.virtual_memory_bytes);
                    snapshot.maximum_process_virtual_memory_bytes =
                        Some(process_sample.maximum_process_virtual_memory_bytes);
                    snapshot.cpu_user_time_units = Some(process_sample.user_cpu_clock_ticks);
                    snapshot.cpu_kernel_time_units = Some(process_sample.kernel_cpu_clock_ticks);
                    snapshot.cpu_time_unit = Some("clock-ticks");
                    snapshot.io_read_bytes = Some(process_sample.io_read_bytes);
                    snapshot.io_write_bytes = Some(process_sample.io_write_bytes);
                }
                Err(error) => errors.push(error),
            }

            match read_linux_host_memory() {
                Ok(host_memory) => {
                    snapshot.host_available_physical_memory_bytes =
                        host_memory.available_physical_memory_bytes;
                    snapshot.host_available_swap_bytes = host_memory.available_swap_bytes;
                }
                Err(error) => errors.push(error),
            }

            if self.page_size_bytes.is_none() {
                errors.push("sysconf(_SC_PAGESIZE) did not return a positive page size".to_owned());
            }
            if !errors.is_empty() {
                snapshot.sample_error = Some(errors.join("; "));
            }
            snapshot
        }
    }

    #[derive(Debug)]
    struct ProcessInformation {
        kernel_cpu_clock_ticks: u64,
        parent_process_id: u32,
        process_id: u32,
        resident_memory_pages: u64,
        user_cpu_clock_ticks: u64,
        virtual_memory_bytes: u64,
    }

    #[derive(Debug, Default)]
    struct ProcessTreeSample {
        io_read_bytes: u64,
        io_write_bytes: u64,
        kernel_cpu_clock_ticks: u64,
        maximum_process_virtual_memory_bytes: u64,
        process_count: u64,
        resident_memory_bytes: u64,
        user_cpu_clock_ticks: u64,
        virtual_memory_bytes: u64,
    }

    fn sample_descendants(
        guard_process_id: u32,
        page_size_bytes: Option<u64>,
    ) -> Result<ProcessTreeSample, String> {
        let directory_entries =
            fs::read_dir("/proc").map_err(|error| format!("failed to enumerate /proc: {error}"))?;
        let mut processes = HashMap::new();
        for entry in directory_entries.flatten() {
            let Some(process_id) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if let Ok(information) = read_process_information(process_id) {
                processes.insert(process_id, information);
            }
        }

        let mut selected_process_ids = HashSet::from([guard_process_id]);
        loop {
            let previous_count = selected_process_ids.len();
            for process in processes.values() {
                if selected_process_ids.contains(&process.parent_process_id) {
                    selected_process_ids.insert(process.process_id);
                }
            }
            if selected_process_ids.len() == previous_count {
                break;
            }
        }

        let mut sample = ProcessTreeSample::default();
        for process_id in selected_process_ids {
            let Some(process) = processes.get(&process_id) else {
                continue;
            };
            sample.process_count = sample.process_count.saturating_add(1);
            sample.virtual_memory_bytes = sample
                .virtual_memory_bytes
                .saturating_add(process.virtual_memory_bytes);
            sample.maximum_process_virtual_memory_bytes = sample
                .maximum_process_virtual_memory_bytes
                .max(process.virtual_memory_bytes);
            sample.user_cpu_clock_ticks = sample
                .user_cpu_clock_ticks
                .saturating_add(process.user_cpu_clock_ticks);
            sample.kernel_cpu_clock_ticks = sample
                .kernel_cpu_clock_ticks
                .saturating_add(process.kernel_cpu_clock_ticks);
            if let Some(page_size_bytes) = page_size_bytes {
                sample.resident_memory_bytes = sample.resident_memory_bytes.saturating_add(
                    process
                        .resident_memory_pages
                        .saturating_mul(page_size_bytes),
                );
            }
            if let Ok((read_bytes, write_bytes)) = read_process_io(process_id) {
                sample.io_read_bytes = sample.io_read_bytes.saturating_add(read_bytes);
                sample.io_write_bytes = sample.io_write_bytes.saturating_add(write_bytes);
            }
        }
        Ok(sample)
    }

    fn read_process_information(process_id: u32) -> Result<ProcessInformation, String> {
        let path = format!("/proc/{process_id}/stat");
        let text =
            fs::read_to_string(&path).map_err(|error| format!("failed to read {path}: {error}"))?;
        let closing_name_parenthesis = text
            .rfind(')')
            .ok_or_else(|| format!("{path} omitted the process-name terminator"))?;
        let fields = text[(closing_name_parenthesis + 1)..]
            .split_whitespace()
            .collect::<Vec<_>>();
        if fields.len() <= 21 {
            return Err(format!("{path} contained too few fields"));
        }
        let parse_field = |field_index: usize, field_name: &str| -> Result<u64, String> {
            fields[field_index]
                .parse::<u64>()
                .map_err(|error| format!("failed to parse {field_name} in {path}: {error}"))
        };

        Ok(ProcessInformation {
            kernel_cpu_clock_ticks: parse_field(12, "kernel CPU time")?,
            parent_process_id: u32::try_from(parse_field(1, "parent process identifier")?)
                .map_err(|_| format!("parent process identifier in {path} exceeded u32"))?,
            process_id,
            resident_memory_pages: parse_field(21, "resident memory")?,
            user_cpu_clock_ticks: parse_field(11, "user CPU time")?,
            virtual_memory_bytes: parse_field(20, "virtual memory")?,
        })
    }

    fn read_process_io(process_id: u32) -> Result<(u64, u64), String> {
        let path = format!("/proc/{process_id}/io");
        let values = read_colon_separated_kib_or_byte_values(Path::new(&path), 1)?;
        Ok((
            values.get("read_bytes").copied().unwrap_or(0),
            values.get("write_bytes").copied().unwrap_or(0),
        ))
    }

    #[derive(Debug)]
    struct LinuxHostMemory {
        available_physical_memory_bytes: Option<u64>,
        available_swap_bytes: Option<u64>,
    }

    fn read_linux_host_memory() -> Result<LinuxHostMemory, String> {
        let values = read_colon_separated_kib_or_byte_values(Path::new("/proc/meminfo"), 1024)?;
        Ok(LinuxHostMemory {
            available_physical_memory_bytes: values.get("MemAvailable").copied(),
            available_swap_bytes: values.get("SwapFree").copied(),
        })
    }

    fn read_colon_separated_kib_or_byte_values(
        path: &Path,
        multiplier: u64,
    ) -> Result<HashMap<String, u64>, String> {
        let text = fs::read_to_string(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let mut values = HashMap::new();
        for line in text.lines() {
            let Some((name, raw_value)) = line.split_once(':') else {
                continue;
            };
            let Some(value) = raw_value.split_whitespace().next() else {
                continue;
            };
            if let Ok(value) = value.parse::<u64>() {
                values.insert(name.to_owned(), value.saturating_mul(multiplier));
            }
        }
        Ok(values)
    }

    pub(crate) fn termination_details(status: ExitStatus) -> TerminationDetails {
        let signal_number = status.signal();
        let core_dumped = status.core_dumped();
        let exit_code = status.code();
        let raw_status = status.into_raw();
        TerminationDetails {
            core_dumped: Some(core_dumped),
            exit_code,
            raw_status_signed: Some(i64::from(raw_status)),
            raw_status_unsigned: Some(u64::from(raw_status as u32)),
            signal_name: signal_number.map(signal_name),
            signal_number,
        }
    }

    pub(crate) fn exit_like_child(status: ExitStatus) -> ! {
        if let Some(signal_number) = status.signal() {
            // SAFETY: Restoring the default handler and raising the same valid
            // signal reproduces the child's observable signal termination in
            // the guard. Neither call dereferences pointers.
            unsafe {
                signal(signal_number, None);
                raise(signal_number);
            }
            // A blocked signal can remain pending after raise returns. The
            // conventional 128+signal fallback still preserves the signal
            // number without invoking undefined behavior.
            std::process::exit(128_i32.saturating_add(signal_number));
        }
        std::process::exit(status.code().unwrap_or(1));
    }

    fn signal_name(signal_number: i32) -> &'static str {
        match signal_number {
            1 => "SIGHUP",
            2 => "SIGINT",
            3 => "SIGQUIT",
            4 => "SIGILL",
            6 => "SIGABRT",
            7 => "SIGBUS",
            8 => "SIGFPE",
            9 => "SIGKILL",
            11 => "SIGSEGV",
            13 => "SIGPIPE",
            14 => "SIGALRM",
            15 => "SIGTERM",
            _ => "unknown-signal",
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod implementation {
    use super::*;

    pub(crate) const CONTAINMENT_BACKEND: &str = "unsupported";
    pub(crate) const CONTAINMENT_SCOPE: &str = "none";
    pub(crate) const AGGREGATE_PROCESS_TREE_LIMIT: bool = false;

    pub(crate) struct MemoryContainment;

    impl MemoryContainment {
        pub(crate) fn apply(
            _memory_limit_bytes: u64,
            _virtual_address_space_allowance_bytes: u64,
        ) -> Result<Self, String> {
            Err(format!(
                "hard memory containment is unsupported on {}",
                std::env::consts::OS
            ))
        }

        pub(crate) fn sample(&self, _guard_process_id: u32) -> ResourceSnapshot {
            ResourceSnapshot {
                sample_error: Some("hard memory containment is unsupported".to_owned()),
                ..ResourceSnapshot::default()
            }
        }
    }

    pub(crate) fn termination_details(status: ExitStatus) -> TerminationDetails {
        TerminationDetails {
            core_dumped: None,
            exit_code: status.code(),
            raw_status_signed: status.code().map(i64::from),
            raw_status_unsigned: status.code().map(|code| u64::from(code as u32)),
            signal_name: None,
            signal_number: None,
        }
    }

    pub(crate) fn exit_like_child(status: ExitStatus) -> ! {
        std::process::exit(status.code().unwrap_or(1));
    }
}

pub(crate) use implementation::*;
