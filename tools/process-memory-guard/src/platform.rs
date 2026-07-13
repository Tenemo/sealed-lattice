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

        pub(crate) fn cleanup(&mut self) -> Result<(), String> {
            Ok(())
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
    use std::collections::HashMap;
    use std::ffi::c_int;
    use std::fs;
    use std::io::{self, Write};
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Component, Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::*;

    const CONTROL_GROUP_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
    const CONTROL_GROUP_EMPTY_POLL_INTERVAL: Duration = Duration::from_millis(10);
    const RESOURCE_LIMIT_DATA: c_int = 2;
    const RESOURCE_LIMIT_ADDRESS_SPACE: c_int = 9;
    const SYSTEM_CONFIGURATION_PAGE_SIZE: c_int = 30;

    pub(crate) const CONTAINMENT_BACKEND: &str =
        "linux-cgroup-v2-memory-max-plus-rlimit-data-and-as";
    pub(crate) const CONTAINMENT_SCOPE: &str = "cgroup-v2 aggregate guard-and-descendant memory.max with swap disabled; inherited RLIMIT_DATA uses the memory limit and RLIMIT_AS adds the configured inaccessible-reservation allowance";
    pub(crate) const AGGREGATE_PROCESS_TREE_LIMIT: bool = true;

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
        control_group: LinuxControlGroup,
        page_size_bytes: Option<u64>,
    }

    impl MemoryContainment {
        pub(crate) fn apply(
            memory_limit_bytes: u64,
            virtual_address_space_allowance_bytes: u64,
        ) -> Result<Self, String> {
            let control_group = LinuxControlGroup::create(memory_limit_bytes)?;
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
            Ok(Self {
                control_group,
                page_size_bytes,
            })
        }

        pub(crate) fn sample(&self, _guard_process_id: u32) -> ResourceSnapshot {
            let mut snapshot = ResourceSnapshot::default();
            let mut errors = Vec::new();

            match sample_control_group_processes(&self.control_group.path, self.page_size_bytes) {
                Ok(process_sample) => {
                    errors.extend(process_sample.errors.iter().cloned());
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

            match read_control_group_unsigned(&self.control_group.path.join("memory.current")) {
                Ok(current_memory_bytes) => {
                    snapshot.backend_current_memory_bytes = Some(current_memory_bytes);
                }
                Err(error) => errors.push(error),
            }
            let peak_memory_path = self.control_group.path.join("memory.peak");
            if peak_memory_path.exists() {
                match read_control_group_unsigned(&peak_memory_path) {
                    Ok(peak_memory_bytes) => {
                        snapshot.backend_peak_job_memory_bytes = Some(peak_memory_bytes);
                    }
                    Err(error) => errors.push(error),
                }
            }
            match read_control_group_events(&self.control_group.path.join("memory.events")) {
                Ok(events) => {
                    snapshot.confirmed_memory_limit_violation = events.maximum > 0
                        || events.out_of_memory > 0
                        || events.out_of_memory_kill > 0;
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

        pub(crate) fn cleanup(&mut self) -> Result<(), String> {
            self.control_group.cleanup_inner()
        }
    }

    struct LinuxControlGroup {
        cleaned: bool,
        original_path: PathBuf,
        path: PathBuf,
    }

    impl LinuxControlGroup {
        fn create(memory_limit_bytes: u64) -> Result<Self, String> {
            let mount_information = fs::read_to_string("/proc/self/mountinfo")
                .map_err(|error| format!("failed to read /proc/self/mountinfo: {error}"))?;
            let mount_path = find_cgroup_v2_mount_path(&mount_information)?;
            let original_path = current_cgroup_path(&mount_path)?;
            require_memory_controller_for_children(&mount_path)?;

            let unique_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos();
            let path = mount_path.join(format!(
                "sealed-lattice-memory-guard-{}-{unique_time}",
                std::process::id()
            ));
            create_control_group_directory(&path)?;
            let mut control_group = Self {
                cleaned: false,
                original_path,
                path,
            };

            let setup_result = (|| {
                write_control_group_value(
                    &control_group.path.join("memory.max"),
                    &memory_limit_bytes.to_string(),
                )?;
                write_control_group_value(&control_group.path.join("memory.swap.max"), "0")?;
                write_control_group_value(
                    &control_group.path.join("cgroup.procs"),
                    &std::process::id().to_string(),
                )?;
                Ok(())
            })();
            if let Err(setup_error) = setup_result {
                return match control_group.cleanup_inner() {
                    Ok(()) => Err(setup_error),
                    Err(cleanup_error) => Err(format!(
                        "{setup_error}; additionally failed to clean up the incomplete cgroup: {cleanup_error}"
                    )),
                };
            }
            Ok(control_group)
        }

        fn cleanup_inner(&mut self) -> Result<(), String> {
            if self.cleaned {
                return Ok(());
            }

            write_control_group_value(
                &self.original_path.join("cgroup.procs"),
                &std::process::id().to_string(),
            )?;
            self.terminate_remaining_processes()?;
            wait_for_empty_control_group(&self.path)?;
            remove_control_group_directory(&self.path)?;
            self.cleaned = true;
            Ok(())
        }

        fn terminate_remaining_processes(&self) -> Result<(), String> {
            if read_control_group_process_ids(&self.path)?.is_empty() {
                return Ok(());
            }
            let kill_path = self.path.join("cgroup.kill");
            if !kill_path.exists() {
                return Err(format!(
                    "{} still contains processes but this cgroup-v2 kernel does not expose cgroup.kill",
                    self.path.display()
                ));
            }
            write_control_group_value(&kill_path, "1")
        }
    }

    impl Drop for LinuxControlGroup {
        fn drop(&mut self) {
            if !self.cleaned {
                let _ = self.cleanup_inner();
            }
        }
    }

    fn find_cgroup_v2_mount_path(mount_information: &str) -> Result<PathBuf, String> {
        for line in mount_information.lines() {
            let Some((mount_fields, filesystem_fields)) = line.split_once(" - ") else {
                continue;
            };
            if filesystem_fields.split_whitespace().next() != Some("cgroup2") {
                continue;
            }
            let encoded_mount_path = mount_fields
                .split_whitespace()
                .nth(4)
                .ok_or_else(|| "cgroup-v2 mount information omitted its mount path".to_owned())?;
            return Ok(PathBuf::from(decode_mount_information_path(
                encoded_mount_path,
            )));
        }
        Err("Linux cgroup v2 is not mounted; an aggregate process-tree memory limit cannot be enforced".to_owned())
    }

    fn decode_mount_information_path(encoded_path: &str) -> String {
        encoded_path
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\")
    }

    fn current_cgroup_path(mount_path: &Path) -> Result<PathBuf, String> {
        let membership = fs::read_to_string("/proc/self/cgroup")
            .map_err(|error| format!("failed to read /proc/self/cgroup: {error}"))?;
        let relative_path = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or_else(|| {
                "/proc/self/cgroup did not contain the unified cgroup-v2 membership".to_owned()
            })?;
        append_kernel_absolute_path(mount_path, relative_path)
    }

    fn append_kernel_absolute_path(base: &Path, kernel_path: &str) -> Result<PathBuf, String> {
        let mut resolved = base.to_path_buf();
        for component in Path::new(kernel_path).components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => resolved.push(name),
                _ => {
                    return Err(format!(
                        "kernel cgroup path contained an unsupported component: {kernel_path}"
                    ));
                }
            }
        }
        Ok(resolved)
    }

    fn require_memory_controller_for_children(parent_path: &Path) -> Result<(), String> {
        let subtree_control_path = parent_path.join("cgroup.subtree_control");
        let enabled_controllers = fs::read_to_string(&subtree_control_path).map_err(|error| {
            format!("failed to read {}: {error}", subtree_control_path.display())
        })?;
        if enabled_controllers
            .split_whitespace()
            .any(|controller| controller == "memory")
        {
            return Ok(());
        }
        Err(format!(
            "the cgroup-v2 memory controller is not enabled for child cgroups at {}; refusing to claim an aggregate process-tree memory limit",
            parent_path.display()
        ))
    }

    fn create_control_group_directory(path: &Path) -> Result<(), String> {
        match fs::create_dir(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                run_sudo_path_command("mkdir", path)
            }
            Err(error) => Err(format!(
                "failed to create cgroup {}: {error}",
                path.display()
            )),
        }
    }

    fn remove_control_group_directory(path: &Path) -> Result<(), String> {
        match fs::remove_dir(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                run_sudo_path_command("rmdir", path)
            }
            Err(error) => Err(format!(
                "failed to remove cgroup {}: {error}",
                path.display()
            )),
        }
    }

    fn run_sudo_path_command(program: &str, path: &Path) -> Result<(), String> {
        let output = Command::new("sudo")
            .args(["--non-interactive", program, "--"])
            .arg(path)
            .output()
            .map_err(|error| {
                format!(
                    "failed to start sudo {program} for cgroup {}: {error}",
                    path.display()
                )
            })?;
        if output.status.success() {
            return Ok(());
        }
        Err(format!(
            "sudo {program} failed for cgroup {} with {}: {}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }

    fn write_control_group_value(path: &Path, value: &str) -> Result<(), String> {
        match fs::write(path, value) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                write_control_group_value_with_sudo(path, value)
            }
            Err(error) => Err(format!(
                "failed to write cgroup control {}: {error}",
                path.display()
            )),
        }
    }

    fn write_control_group_value_with_sudo(path: &Path, value: &str) -> Result<(), String> {
        let mut child = Command::new("sudo")
            .args(["--non-interactive", "tee", "--"])
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                format!(
                    "failed to start sudo tee for cgroup control {}: {error}",
                    path.display()
                )
            })?;
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| "sudo tee did not provide a standard-input pipe".to_owned())
            .and_then(|mut input| {
                input.write_all(value.as_bytes()).map_err(|error| {
                    format!(
                        "failed to pass a value to sudo tee for {}: {error}",
                        path.display()
                    )
                })
            });
        let output = child.wait_with_output().map_err(|error| {
            format!(
                "failed to wait for sudo tee writing {}: {error}",
                path.display()
            )
        })?;
        write_result?;
        if output.status.success() {
            return Ok(());
        }
        Err(format!(
            "sudo tee failed for cgroup control {} with {}: {}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }

    fn wait_for_empty_control_group(path: &Path) -> Result<(), String> {
        let deadline = Instant::now() + CONTROL_GROUP_CLEANUP_TIMEOUT;
        loop {
            if read_control_group_process_ids(path)?.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "cgroup {} still contained processes after {} milliseconds",
                    path.display(),
                    CONTROL_GROUP_CLEANUP_TIMEOUT.as_millis()
                ));
            }
            thread::sleep(CONTROL_GROUP_EMPTY_POLL_INTERVAL);
        }
    }

    fn read_control_group_process_ids(path: &Path) -> Result<Vec<u32>, String> {
        let process_path = path.join("cgroup.procs");
        let text = fs::read_to_string(&process_path)
            .map_err(|error| format!("failed to read {}: {error}", process_path.display()))?;
        text.lines()
            .map(|line| {
                line.parse::<u32>().map_err(|error| {
                    format!(
                        "failed to parse process identifier in {}: {error}",
                        process_path.display()
                    )
                })
            })
            .collect()
    }

    #[derive(Debug, Default, Eq, PartialEq)]
    struct ControlGroupMemoryEvents {
        maximum: u64,
        out_of_memory: u64,
        out_of_memory_kill: u64,
    }

    fn read_control_group_events(path: &Path) -> Result<ControlGroupMemoryEvents, String> {
        let text = fs::read_to_string(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        parse_control_group_events(&text, path)
    }

    fn parse_control_group_events(
        text: &str,
        path: &Path,
    ) -> Result<ControlGroupMemoryEvents, String> {
        let mut values = HashMap::new();
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let Some(name) = fields.next() else {
                continue;
            };
            let Some(value) = fields.next() else {
                continue;
            };
            let value = value.parse::<u64>().map_err(|error| {
                format!(
                    "failed to parse {name} in cgroup event file {}: {error}",
                    path.display()
                )
            })?;
            values.insert(name, value);
        }
        Ok(ControlGroupMemoryEvents {
            maximum: values.get("max").copied().unwrap_or(0),
            out_of_memory: values.get("oom").copied().unwrap_or(0),
            out_of_memory_kill: values.get("oom_kill").copied().unwrap_or(0),
        })
    }

    fn read_control_group_unsigned(path: &Path) -> Result<u64, String> {
        let text = fs::read_to_string(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        text.trim().parse::<u64>().map_err(|error| {
            format!(
                "failed to parse the unsigned value in {}: {error}",
                path.display()
            )
        })
    }

    #[derive(Debug)]
    struct ProcessInformation {
        kernel_cpu_clock_ticks: u64,
        resident_memory_pages: u64,
        user_cpu_clock_ticks: u64,
        virtual_memory_bytes: u64,
    }

    #[derive(Debug, Default)]
    struct ProcessTreeSample {
        errors: Vec<String>,
        io_read_bytes: u64,
        io_write_bytes: u64,
        kernel_cpu_clock_ticks: u64,
        maximum_process_virtual_memory_bytes: u64,
        process_count: u64,
        resident_memory_bytes: u64,
        user_cpu_clock_ticks: u64,
        virtual_memory_bytes: u64,
    }

    fn sample_control_group_processes(
        control_group_path: &Path,
        page_size_bytes: Option<u64>,
    ) -> Result<ProcessTreeSample, String> {
        let process_ids = read_control_group_process_ids(control_group_path)?;
        let mut sample = ProcessTreeSample::default();
        for process_id in process_ids {
            let process = match read_process_information(process_id) {
                Ok(process) => process,
                Err(ProcessReadError::Exited) => continue,
                Err(ProcessReadError::Failed(error)) => {
                    sample.errors.push(error);
                    continue;
                }
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
            match read_process_io(process_id) {
                Ok((read_bytes, write_bytes)) => {
                    sample.io_read_bytes = sample.io_read_bytes.saturating_add(read_bytes);
                    sample.io_write_bytes = sample.io_write_bytes.saturating_add(write_bytes);
                }
                Err(ProcessReadError::Exited) => {}
                Err(ProcessReadError::Failed(error)) => sample.errors.push(error),
            }
        }
        Ok(sample)
    }

    enum ProcessReadError {
        Exited,
        Failed(String),
    }

    fn read_process_text(path: &str) -> Result<String, ProcessReadError> {
        fs::read_to_string(path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                ProcessReadError::Exited
            } else {
                ProcessReadError::Failed(format!("failed to read {path}: {error}"))
            }
        })
    }

    fn read_process_information(process_id: u32) -> Result<ProcessInformation, ProcessReadError> {
        let path = format!("/proc/{process_id}/stat");
        let text = read_process_text(&path)?;
        let closing_name_parenthesis = text
            .rfind(')')
            .ok_or_else(|| {
                ProcessReadError::Failed(format!("{path} omitted the process-name terminator"))
            })?;
        let fields = text[(closing_name_parenthesis + 1)..]
            .split_whitespace()
            .collect::<Vec<_>>();
        if fields.len() <= 21 {
            return Err(ProcessReadError::Failed(format!(
                "{path} contained too few fields"
            )));
        }
        let parse_field = |field_index: usize, field_name: &str| {
            fields[field_index].parse::<u64>().map_err(|error| {
                ProcessReadError::Failed(format!(
                    "failed to parse {field_name} in {path}: {error}"
                ))
            })
        };

        Ok(ProcessInformation {
            kernel_cpu_clock_ticks: parse_field(12, "kernel CPU time")?,
            resident_memory_pages: parse_field(21, "resident memory")?,
            user_cpu_clock_ticks: parse_field(11, "user CPU time")?,
            virtual_memory_bytes: parse_field(20, "virtual memory")?,
        })
    }

    fn read_process_io(process_id: u32) -> Result<(u64, u64), ProcessReadError> {
        let path = format!("/proc/{process_id}/io");
        let text = read_process_text(&path)?;
        let values = parse_selected_colon_separated_values(
            &text,
            Path::new(&path),
            1,
            &["read_bytes", "write_bytes"],
        )
        .map_err(ProcessReadError::Failed)?;
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
        let path = Path::new("/proc/meminfo");
        let text = fs::read_to_string(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let values = parse_selected_colon_separated_values(
            &text,
            path,
            1024,
            &["MemAvailable", "SwapFree"],
        )?;
        Ok(LinuxHostMemory {
            available_physical_memory_bytes: values.get("MemAvailable").copied(),
            available_swap_bytes: values.get("SwapFree").copied(),
        })
    }

    fn parse_selected_colon_separated_values(
        text: &str,
        path: &Path,
        multiplier: u64,
        selected_names: &[&str],
    ) -> Result<HashMap<String, u64>, String> {
        let mut values = HashMap::new();
        for line in text.lines() {
            let Some((name, raw_value)) = line.split_once(':') else {
                continue;
            };
            if !selected_names.contains(&name) {
                continue;
            }
            let value = raw_value.split_whitespace().next().ok_or_else(|| {
                format!("{name} in {} omitted its value", path.display())
            })?;
            let value = value.parse::<u64>().map_err(|error| {
                format!("failed to parse {name} in {}: {error}", path.display())
            })?;
            values.insert(name.to_owned(), value.saturating_mul(multiplier));
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn finds_and_decodes_the_cgroup_v2_mount_path() {
            let mount_information = "29 23 0:26 / /sys/fs/cgroup\\040root rw - cgroup2 cgroup rw\n";

            assert_eq!(
                find_cgroup_v2_mount_path(mount_information),
                Ok(PathBuf::from("/sys/fs/cgroup root"))
            );
        }

        #[test]
        fn rejects_mount_information_without_cgroup_v2() {
            assert!(
                find_cgroup_v2_mount_path("29 23 0:26 / /sys/fs/cgroup rw - tmpfs tmpfs rw")
                    .is_err()
            );
        }

        #[test]
        fn parses_the_memory_limit_event_counters() {
            let events = parse_control_group_events(
                "low 0\nhigh 2\nmax 3\noom 1\noom_kill 1\noom_group_kill 0\n",
                Path::new("memory.events"),
            )
            .expect("cgroup memory events");

            assert_eq!(
                events,
                ControlGroupMemoryEvents {
                    maximum: 3,
                    out_of_memory: 1,
                    out_of_memory_kill: 1,
                }
            );
        }

        #[test]
        fn confines_kernel_membership_paths_below_the_mount() {
            assert_eq!(
                append_kernel_absolute_path(Path::new("/sys/fs/cgroup"), "/runner/job"),
                Ok(PathBuf::from("/sys/fs/cgroup/runner/job"))
            );
            assert!(
                append_kernel_absolute_path(Path::new("/sys/fs/cgroup"), "/runner/../escape")
                    .is_err()
            );
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

        pub(crate) fn cleanup(&mut self) -> Result<(), String> {
            Ok(())
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
