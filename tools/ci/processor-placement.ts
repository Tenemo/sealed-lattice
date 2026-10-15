import os from 'node:os';

import type { CommandInvocation } from '#tools/ci/command-runner.js';

// The Windows priority classes a placement may select, by option name.
const priorityClasses = {
    'below-normal': 0x4000,
    normal: 0x20,
    'above-normal': 0x8000,
} as const;

type ProcessorPriority = keyof typeof priorityClasses;

export type ProcessorPlacement = Readonly<{
    affinityMask: bigint;
    priority: ProcessorPriority;
}>;

// One outer job accounts for the monitor and workload, while each command
// retains its own nested job for process-tree cleanup.
export type ProcessorAccountingJob = Readonly<{ name: string; create?: true }>;

// One affinity mask addresses one Windows processor group of at most 64
// logical processors.
const processorGroupSize = 64;

// Parses `<hexadecimal affinity mask>:<priority>`, such as
// `0xAAAA:above-normal`. A placement holds every process of a command in a
// Windows job object, so another platform refuses it instead of running the
// command unplaced.
export const parseProcessorPlacement = (
    value: string,
    host: Readonly<{
        logicalProcessorCount: number;
        platform: NodeJS.Platform;
    }> = {
        logicalProcessorCount: os.cpus().length,
        platform: process.platform,
    },
): ProcessorPlacement => {
    if (host.platform !== 'win32')
        throw new Error(
            'Processor placement holds a command in a Windows job object, which this platform lacks; run without a placement option.',
        );
    const match =
        /^(?:0x)?([0-9a-f]{1,16}):(below-normal|normal|above-normal)$/iu.exec(
            value,
        );
    if (match === null)
        throw new Error(
            `A processor placement is <hexadecimal affinity mask>:<below-normal|normal|above-normal>, not ${value}.`,
        );
    if (host.logicalProcessorCount > processorGroupSize)
        throw new Error(
            `This host's ${String(host.logicalProcessorCount)} logical processors span processor groups, which one affinity mask cannot address.`,
        );
    const affinityMask = BigInt('0x' + match[1]);
    if (
        affinityMask === 0n ||
        affinityMask >> BigInt(host.logicalProcessorCount) !== 0n
    )
        throw new Error(
            `The affinity mask 0x${match[1]} selects no logical processor or one beyond this host's ${String(host.logicalProcessorCount)}.`,
        );
    return {
        affinityMask,
        priority: match[2].toLowerCase() as ProcessorPriority,
    };
};

export const describeProcessorPlacement = (placement: ProcessorPlacement) => ({
    affinityMask: '0x' + placement.affinityMask.toString(16).toUpperCase(),
    priority: placement.priority,
});

// Quotes one argument so that the Microsoft C runtime's command-line parser,
// which Node and most Windows programs use, reads it back unchanged:
// backslashes are literal except before a quotation mark, where each one is
// doubled and the mark escaped.
export const quoteWindowsCommandLineArgument = (argument: string): string => {
    let quoted = '"';
    let backslashes = 0;
    for (const character of argument) {
        if (character === '\\') {
            backslashes += 1;
            continue;
        }
        quoted +=
            character === '"'
                ? '\\'.repeat(2 * backslashes + 1) + '"'
                : '\\'.repeat(backslashes) + character;
        backslashes = 0;
    }
    return quoted + '\\'.repeat(2 * backslashes) + '"';
};

// Creates a job object whose processes run on the mask's logical processors
// at the priority class, with no breakaway, and moves the calling process
// into it, so every process it starts inherits the job. The job ends every
// process it holds when its last handle closes with the calling process.
export const processorJobSource = String.raw`
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

public static class ProcessorPlacementJob {
    [StructLayout(LayoutKind.Sequential)]
    struct BasicLimits {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct InputOutputCounters {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ExtendedLimits {
        public BasicLimits Basic;
        public InputOutputCounters InputOutput;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct Accounting {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long PeriodUserTime;
        public long PeriodKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    const int ExtendedLimitInformation = 9;
    const uint LimitAffinity = 0x10;
    const uint LimitPriorityClass = 0x20;
    const uint LimitKillOnJobClose = 0x2000;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenJobObject(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int informationClass, ref ExtendedLimits information, int length);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool QueryInformationJobObject(IntPtr job, int informationClass, out Accounting information, int length, IntPtr returnedLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetSystemTimes(out long idle, out long kernel, out long user);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    static IntPtr job;
    static IntPtr accountingJob;

    static IntPtr Create(ulong affinity, uint priorityClass, string name) {
        IntPtr created = CreateJobObject(IntPtr.Zero, name);
        if (created == IntPtr.Zero) throw new Win32Exception();
        if (Marshal.GetLastWin32Error() == 183) {
            CloseHandle(created);
            throw new InvalidOperationException("The accounting job already exists.");
        }
        ExtendedLimits limits = new ExtendedLimits();
        limits.Basic.LimitFlags = LimitAffinity | LimitPriorityClass | LimitKillOnJobClose;
        limits.Basic.Affinity = new UIntPtr(affinity);
        limits.Basic.PriorityClass = priorityClass;
        if (!SetInformationJobObject(created, ExtendedLimitInformation, ref limits, Marshal.SizeOf(typeof(ExtendedLimits))))
            throw new Win32Exception();
        return created;
    }

    public static void Enter(ulong affinity, uint priorityClass, string accountingName, bool createAccounting) {
        if (!String.IsNullOrEmpty(accountingName)) {
            accountingJob = createAccounting ? Create(affinity, priorityClass, accountingName) : OpenJobObject(1, false, accountingName);
            if (accountingJob == IntPtr.Zero) throw new Win32Exception();
            if (!AssignProcessToJobObject(accountingJob, GetCurrentProcess())) throw new Win32Exception();
        }
        job = Create(affinity, priorityClass, null);
        if (!AssignProcessToJobObject(job, GetCurrentProcess())) throw new Win32Exception();
    }

    public static string CpuTimes(string name) {
        IntPtr handle = OpenJobObject(4, false, name);
        if (handle == IntPtr.Zero) throw new Win32Exception();
        try {
            Accounting information;
            if (!QueryInformationJobObject(handle, 1, out information, Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero)) throw new Win32Exception();
            long idle, kernel, user;
            if (!GetSystemTimes(out idle, out kernel, out user)) throw new Win32Exception();
            double at = 1000.0 * Stopwatch.GetTimestamp() / Stopwatch.Frequency;
            double busy = (kernel + user - idle) / 1e7;
            double own = (information.TotalUserTime + information.TotalKernelTime) / 1e7;
            return String.Format(CultureInfo.InvariantCulture, "{0:R}|{1:R}|{2:R}", at, busy, own);
        } finally { CloseHandle(handle); }
    }
}
`;

// The Windows PowerShell script that enters a placement's job and runs the
// command in it with the inherited standard streams, returning its exit
// status. The command travels as Base64 JSON, so no value is ever parsed as
// script.
export const placedCommandScript = (
    invocation: CommandInvocation,
    placement: ProcessorPlacement,
    accountingJob?: ProcessorAccountingJob,
): string => {
    const payload = Buffer.from(
        JSON.stringify({
            arguments: invocation.args
                .map(quoteWindowsCommandLineArgument)
                .join(' '),
            command: invocation.command,
            workingDirectory: invocation.workingDirectoryPath ?? process.cwd(),
            ...(accountingJob === undefined ? {} : { accountingJob }),
        }),
        'utf8',
    ).toString('base64');
    return [
        "$ErrorActionPreference = 'Stop'",
        "$ProgressPreference = 'SilentlyContinue'",
        "$source = @'",
        processorJobSource,
        "'@",
        'try {',
        `    $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}')) | ConvertFrom-Json`,
        '    Add-Type -TypeDefinition $source',
        `    [ProcessorPlacementJob]::Enter([UInt64]::Parse('${placement.affinityMask.toString()}'), [UInt32]::Parse('${String(priorityClasses[placement.priority])}'), [string]$payload.accountingJob.name, [bool]$payload.accountingJob.create)`,
        '} catch {',
        "    [Console]::Error.WriteLine('The processor placement failed: ' + $_.Exception.Message)",
        '    exit 1',
        '}',
        'try {',
        '    $start = New-Object System.Diagnostics.ProcessStartInfo',
        '    $start.FileName = $payload.command',
        '    $start.Arguments = $payload.arguments',
        '    $start.WorkingDirectory = $payload.workingDirectory',
        '    $start.UseShellExecute = $false',
        '    $process = [System.Diagnostics.Process]::Start($start)',
        '} catch {',
        "    [Console]::Error.WriteLine('The placed command did not start: ' + $_.Exception.Message)",
        '    exit 1',
        '}',
        '$process.WaitForExit()',
        'exit $process.ExitCode',
    ].join('\n');
};

// The command that runs the invocation inside the placement's job, under the
// same description, environment and working directory.
export const placeCommand = (
    invocation: CommandInvocation,
    placement: ProcessorPlacement,
    accountingJob?: ProcessorAccountingJob,
): CommandInvocation => ({
    ...invocation,
    args: [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-EncodedCommand',
        Buffer.from(
            placedCommandScript(invocation, placement, accountingJob),
            'utf16le',
        ).toString('base64'),
    ],
    command: 'powershell.exe',
});
