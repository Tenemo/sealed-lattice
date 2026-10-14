import { execFileSync } from 'node:child_process';
import os from 'node:os';

import { describe, expect, it } from 'vitest';

import { runCommandAndCaptureOutput } from '#tools/ci/command-runner.js';
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

describe('processor placement', () => {
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
            "[ProcessorPlacementJob]::Enter([UInt64]::Parse('43690'), [UInt32]::Parse('32768'))",
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
