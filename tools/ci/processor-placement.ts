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
const processorJobSource = String.raw`
using System;
using System.ComponentModel;
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

    const int ExtendedLimitInformation = 9;
    const uint LimitAffinity = 0x10;
    const uint LimitPriorityClass = 0x20;
    const uint LimitKillOnJobClose = 0x2000;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int informationClass, ref ExtendedLimits information, int length);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    static IntPtr job;

    public static void Enter(ulong affinity, uint priorityClass) {
        job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new Win32Exception();
        ExtendedLimits limits = new ExtendedLimits();
        limits.Basic.LimitFlags = LimitAffinity | LimitPriorityClass | LimitKillOnJobClose;
        limits.Basic.Affinity = new UIntPtr(affinity);
        limits.Basic.PriorityClass = priorityClass;
        if (!SetInformationJobObject(job, ExtendedLimitInformation, ref limits, Marshal.SizeOf(typeof(ExtendedLimits))))
            throw new Win32Exception();
        if (!AssignProcessToJobObject(job, GetCurrentProcess())) throw new Win32Exception();
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
): string => {
    const payload = Buffer.from(
        JSON.stringify({
            arguments: invocation.args
                .map(quoteWindowsCommandLineArgument)
                .join(' '),
            command: invocation.command,
            workingDirectory: invocation.workingDirectoryPath ?? process.cwd(),
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
        '    Add-Type -TypeDefinition $source',
        `    [ProcessorPlacementJob]::Enter([UInt64]::Parse('${placement.affinityMask.toString()}'), [UInt32]::Parse('${String(priorityClasses[placement.priority])}'))`,
        '} catch {',
        "    [Console]::Error.WriteLine('The processor placement failed: ' + $_.Exception.Message)",
        '    exit 1',
        '}',
        'try {',
        `    $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}')) | ConvertFrom-Json`,
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
): CommandInvocation => ({
    ...invocation,
    args: [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-EncodedCommand',
        Buffer.from(
            placedCommandScript(invocation, placement),
            'utf16le',
        ).toString('base64'),
    ],
    command: 'powershell.exe',
});
