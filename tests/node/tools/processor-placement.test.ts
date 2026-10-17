import { execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import os from 'node:os';

import { describe, expect, it } from 'vitest';

import { runCommandAndCaptureOutput } from '#tools/ci/command-runner.js';
import { readCpuTimes } from '#tools/ci/monitor-host-contention.js';
import {
    describeProcessorPlacement,
    parseProcessorPlacement,
    placeCommand,
    placedCommandScript,
    quoteWindowsCommandLineArgument,
} from '#tools/ci/processor-placement.js';

const windowsHost = { logicalProcessorCount: 32, platform: 'win32' } as const;

// An independent reading of a command line by the Microsoft C runtime's
// rules: whitespace separates arguments outside quotation marks, a run of
// backslashes before a quotation mark halves and escapes it when odd, and
// backslashes elsewhere are literal.
const parseWindowsCommandLine = (commandLine: string): string[] => {
    const parsed: string[] = [];
    let index = 0;
    while (index < commandLine.length) {
        while (commandLine[index] === ' ' || commandLine[index] === '\t')
            index += 1;
        if (index >= commandLine.length) break;
        let argument = '';
        let quoted = false;
        while (index < commandLine.length) {
            const character = commandLine[index];
            if ((character === ' ' || character === '\t') && !quoted) break;
            if (character === '\\') {
                let end = index;
                while (commandLine[end] === '\\') end += 1;
                const count = end - index;
                if (commandLine[end] === '"') {
                    argument += '\\'.repeat(Math.floor(count / 2));
                    if (count % 2 === 1) {
                        argument += '"';
                        index = end + 1;
                    } else index = end;
                } else {
                    argument += '\\'.repeat(count);
                    index = end;
                }
                continue;
            }
            if (character === '"') {
                quoted = !quoted;
                index += 1;
                continue;
            }
            argument += character;
            index += 1;
        }
        parsed.push(argument);
    }
    return parsed;
};

// On Windows, runs a probe in a job on the lowest logical processor this
// process may use, so the job nests inside any job that already holds the
// test, and reports what the probe saw; elsewhere, reports whether the
// placement was refused for the platform.
const observePlacedProbe = async () => {
    if (process.platform !== 'win32') {
        try {
            parseProcessorPlacement('0x1:normal');
        } catch (error) {
            return {
                refusedForPlatform: (error as Error).message.includes(
                    'which this platform lacks',
                ),
            };
        }
        return { refusedForPlatform: false };
    }
    const affinity = BigInt(
        execFileSync(
            'powershell.exe',
            [
                '-NoProfile',
                '-Command',
                `(Get-Process -Id ${String(process.pid)}).ProcessorAffinity.ToInt64()`,
            ],
            { encoding: 'utf8', windowsHide: true },
        ).trim(),
    );
    const result = await runCommandAndCaptureOutput(
        placeCommand(
            {
                args: [
                    '-e',
                    "process.stdout.write(JSON.stringify({ argv: process.argv.slice(1), parallelism: require('node:os').availableParallelism(), priority: require('node:os').getPriority() })); process.exit(3)",
                    'a b',
                    'c"d',
                    '',
                    'trailing\\',
                ],
                command: process.execPath,
                description: 'Placed probe',
                workingDirectoryPath: os.tmpdir(),
            },
            parseProcessorPlacement(
                `0x${(affinity & -affinity).toString(16)}:below-normal`,
            ),
        ),
    );
    return {
        exitCode: result.exitCode,
        output: JSON.parse(result.stdout) as unknown,
    };
};

const observeRetiredWorkload = async () => {
    if (process.platform !== 'win32') return { supported: false };
    const affinity = BigInt(
        execFileSync(
            'powershell.exe',
            [
                '-NoProfile',
                '-Command',
                `(Get-Process -Id ${String(process.pid)}).ProcessorAffinity.ToInt64()`,
            ],
            { encoding: 'utf8', windowsHide: true },
        ).trim(),
    );
    const placement = parseProcessorPlacement(
        `0x${(affinity & -affinity).toString(16)}:normal`,
    );
    const job = { name: 'Local\\sealed-lattice-cpu-test-' + randomUUID() };
    const invocation = placeCommand(
        {
            command: process.execPath,
            args: [
                '-e',
                "process.stdout.write('ready\\n'); process.stdin.resume();",
            ],
            description: 'Keep accounting job alive',
        },
        placement,
        { ...job, create: true },
    );
    const keeper = spawn(invocation.command, [...invocation.args], {
        stdio: 'pipe',
        windowsHide: true,
    });
    const closed = new Promise<void>((resolve, reject) => {
        keeper.once('error', reject);
        keeper.once('close', () => resolve());
    });
    let output = '',
        errors = '';
    keeper.stderr.on('data', (chunk: Buffer) => {
        errors += chunk.toString();
    });
    try {
        await new Promise<void>((resolve, reject) => {
            const timeout = setTimeout(
                () => reject(new Error('The accounting keeper did not start.')),
                15000,
            );
            keeper.stdout.on('data', (chunk: Buffer) => {
                output += chunk.toString();
                if (output.includes('ready\n')) {
                    clearTimeout(timeout);
                    resolve();
                }
            });
            keeper.once('error', (error) => {
                clearTimeout(timeout);
                reject(error);
            });
            keeper.once('close', () => {
                clearTimeout(timeout);
                reject(new Error('The accounting keeper ended: ' + errors));
            });
        });
        const before = await readCpuTimes(job.name);
        const child =
            'const started = process.cpuUsage(); let cpu; do { for (let i=0;i<100000;i++) Math.sqrt(i); cpu=process.cpuUsage(started); } while(cpu.user+cpu.system<300000); process.stdout.write(String((cpu.user+cpu.system)/1e6));';
        const code = `const {execFileSync}=require('node:child_process'); let seconds=0; for(let index=0;index<3;index++) seconds+=Number(execFileSync(process.execPath,['-e',${JSON.stringify(child)}],{encoding:'utf8',windowsHide:true})); process.stdout.write(String(seconds));`;
        const workload = await runCommandAndCaptureOutput(
            placeCommand(
                {
                    command: process.execPath,
                    args: ['-e', code],
                    description: 'Short-lived accounting descendants',
                },
                placement,
                job,
            ),
        );
        if (workload.exitCode !== 0) throw new Error(workload.stderr);
        const reportedCpu = Number(workload.stdout);
        if (!Number.isFinite(reportedCpu) || reportedCpu <= 0)
            throw new Error('The short-lived children reported no CPU work.');
        // The workload, its nested job, and every child have exited here.
        const after = await readCpuTimes(job.name);
        return {
            supported: true,
            retiredCpuAccounted:
                after.ownSeconds - before.ownSeconds >= reportedCpu,
            hostAdvanced: after.busySeconds > before.busySeconds,
            timeAdvanced: after.at > before.at,
        };
    } finally {
        keeper.kill();
        await closed;
    }
};

describe('processor placement', () => {
    it('keeps CPU totals after a separately launched workload and its descendants exit', async () => {
        expect(await observeRetiredWorkload()).toEqual(
            process.platform === 'win32'
                ? {
                      supported: true,
                      retiredCpuAccounted: true,
                      hostAdvanced: true,
                      timeAdvanced: true,
                  }
                : { supported: false },
        );
    });
    it('refuses a placement where no Windows job object exists', () => {
        for (const platform of ['linux', 'darwin'] as const)
            expect(() =>
                parseProcessorPlacement('0xAAAA:above-normal', {
                    logicalProcessorCount: 32,
                    platform,
                }),
            ).toThrow('Windows job object, which this platform lacks');
    });

    it('parses a mask within the host and a priority option', () => {
        expect(
            parseProcessorPlacement('0xAAAA:above-normal', windowsHost),
        ).toEqual({ affinityMask: 0xaaaan, priority: 'above-normal' });
        const efficiency = parseProcessorPlacement(
            'ffff0000:below-normal',
            windowsHost,
        );
        expect(describeProcessorPlacement(efficiency)).toEqual({
            affinityMask: '0xFFFF0000',
            priority: 'below-normal',
        });
        expect(
            parseProcessorPlacement('0x80000000:normal', windowsHost)
                .affinityMask,
        ).toBe(0x80000000n);
    });

    it('refuses empty, oversized and malformed placements', () => {
        for (const value of [
            '0xAAAA',
            'AAAA:',
            '0xAAAA:high',
            '0xAAAA:realtime',
            '0xGG:normal',
            ' 0xAAAA:normal',
            '0x10000000000000000:normal',
        ])
            expect(() => parseProcessorPlacement(value, windowsHost)).toThrow(
                'A processor placement is',
            );
        for (const value of ['0x0:normal', '0x100000000:normal'])
            expect(() => parseProcessorPlacement(value, windowsHost)).toThrow(
                'selects no logical processor or one beyond',
            );
        expect(() =>
            parseProcessorPlacement('0x1:normal', {
                logicalProcessorCount: 96,
                platform: 'win32',
            }),
        ).toThrow('span processor groups');
    });

    it('quotes arguments that the runtime reads back unchanged', () => {
        const values = [
            '',
            'plain',
            'with space',
            'tab\there',
            'quote"inside',
            '"',
            '\\"',
            'trailing\\',
            'trailing\\\\',
            'back\\\\"slashes',
            '\\\\server\\share',
            'C:\\path with space\\',
            '--foreign-poll=logs/2026-10-12/run',
            'ünïcode',
        ];
        expect(
            parseWindowsCommandLine(
                values.map(quoteWindowsCommandLineArgument).join(' '),
            ),
        ).toEqual(values);
    });

    it('encodes the command as data inside the job script', () => {
        const invocation = {
            args: ['-e', 'process.exit(0)', 'a b'],
            command: 'C:\\node\\node.exe',
            description: 'Placed command',
            workingDirectoryPath: 'C:\\checkout',
        };
        const placement = parseProcessorPlacement(
            '0xAAAA:above-normal',
            windowsHost,
        );
        const placed = placeCommand(invocation, placement);
        expect(placed.command).toBe('powershell.exe');
        expect(placed.description).toBe('Placed command');
        expect(placed.workingDirectoryPath).toBe('C:\\checkout');
        const script = Buffer.from(
            placed.args[placed.args.length - 1],
            'base64',
        ).toString('utf16le');
        expect(script).toBe(placedCommandScript(invocation, placement));
        expect(script).toContain(
            "[ProcessorPlacementJob]::Enter([UInt64]::Parse('43690'), [UInt32]::Parse('32768'), [string]$payload.accountingJob.name, [bool]$payload.accountingJob.create)",
        );
        const payload = /FromBase64String\('([A-Za-z0-9+/=]+)'\)/u.exec(
            script,
        )?.[1];
        expect(
            JSON.parse(Buffer.from(payload ?? '', 'base64').toString('utf8')),
        ).toEqual({
            arguments: '"-e" "process.exit(0)" "a b"',
            command: 'C:\\node\\node.exe',
            workingDirectory: 'C:\\checkout',
        });
    });

    it('runs a placed command in its job on Windows and refuses placement elsewhere', async () => {
        expect(await observePlacedProbe()).toEqual(
            process.platform === 'win32'
                ? {
                      exitCode: 3,
                      output: {
                          argv: ['a b', 'c"d', '', 'trailing\\'],
                          parallelism: 1,
                          priority: os.constants.priority.PRIORITY_BELOW_NORMAL,
                      },
                  }
                : { refusedForPlatform: true },
        );
    });
});
