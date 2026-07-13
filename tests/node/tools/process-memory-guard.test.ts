import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { addProcessMemoryGuardDiagnostics } from '#tools/ci/process-memory-guard';
import type { CommandInvocation } from '#tools/ci/run-command';

const guardedCommand = (
    guardArguments: readonly string[] = [],
): CommandInvocation => ({
    args: [
        '--memory-limit-bytes',
        '1073741824',
        ...guardArguments,
        '--',
        'cargo',
        'test',
    ],
    command: path.resolve('target', 'process-memory-guard', 'guard.exe'),
    description: 'guarded cargo test',
});

describe('Process-memory guard diagnostics arguments', () => {
    it('adds diagnostics without disturbing guard or child arguments', () => {
        const diagnosticsPath = path.resolve('logs', 'guard.jsonl');

        expect(
            addProcessMemoryGuardDiagnostics(
                guardedCommand([
                    '--virtual-address-space-allowance-bytes',
                    '8589934592',
                ]),
                diagnosticsPath,
            ).args,
        ).toEqual([
            '--memory-limit-bytes',
            '1073741824',
            '--virtual-address-space-allowance-bytes',
            '8589934592',
            '--diagnostics-path',
            diagnosticsPath,
            '--',
            'cargo',
            'test',
        ]);
    });

    it.each([
        {
            command: guardedCommand(),
            diagnosticsPath: 'logs/guard.jsonl',
            expectedMessage: 'must be absolute',
        },
        {
            command: {
                ...guardedCommand(),
                args: ['--memory-limit-bytes', 'invalid', '--', 'cargo'],
            },
            diagnosticsPath: path.resolve('logs', 'guard.jsonl'),
            expectedMessage: 'only be attached to a guarded command',
        },
        {
            command: guardedCommand([
                '--diagnostics-path',
                path.resolve('logs', 'first.jsonl'),
            ]),
            diagnosticsPath: path.resolve('logs', 'second.jsonl'),
            expectedMessage: 'unrecognized guard option',
        },
    ])(
        'rejects hostile guard arguments: $expectedMessage',
        ({ command, diagnosticsPath, expectedMessage }) => {
            expect(() =>
                addProcessMemoryGuardDiagnostics(command, diagnosticsPath),
            ).toThrow(expectedMessage);
        },
    );
});
