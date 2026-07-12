import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    addProcessMemoryGuardDiagnostics,
    buildProcessMemoryGuardVerificationCommand,
} from '#tools/ci/process-memory-guard';
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
    it('serializes the verification tests so wall-clock runtimes are attributable', () => {
        const command = buildProcessMemoryGuardVerificationCommand();

        expect(command.args.slice(-4)).toEqual([
            '--',
            '--test-threads',
            '1',
            '--show-output',
        ]);
        expect(command.env?.RUST_BACKTRACE).toBe('1');
    });

    it('inserts one absolute diagnostics path before the guarded command', () => {
        const diagnosticsPath = path.resolve(
            'logs',
            'run',
            'resources',
            'guard.jsonl',
        );

        expect(
            addProcessMemoryGuardDiagnostics(guardedCommand(), diagnosticsPath)
                .args,
        ).toEqual([
            '--memory-limit-bytes',
            '1073741824',
            '--diagnostics-path',
            diagnosticsPath,
            '--',
            'cargo',
            'test',
        ]);
    });

    it('preserves the Linux virtual-address allowance before diagnostics', () => {
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

    it('rejects relative paths, malformed wrappers, and duplicate diagnostics', () => {
        expect(() =>
            addProcessMemoryGuardDiagnostics(
                guardedCommand(),
                'logs/guard.jsonl',
            ),
        ).toThrow('must be absolute');
        expect(() =>
            addProcessMemoryGuardDiagnostics(
                {
                    ...guardedCommand(),
                    args: ['--memory-limit-bytes', 'invalid', '--', 'cargo'],
                },
                path.resolve('logs', 'guard.jsonl'),
            ),
        ).toThrow('only be attached to a guarded command');
        expect(() =>
            addProcessMemoryGuardDiagnostics(
                guardedCommand([
                    '--diagnostics-path',
                    path.resolve('logs', 'first.jsonl'),
                ]),
                path.resolve('logs', 'second.jsonl'),
            ),
        ).toThrow('unrecognized guard option');
    });
});
