import { describe, expect, it } from 'vitest';

import type { PackageManagerRunner } from '#tools/ci/package-manager-runner';
import {
    buildNodeTestCommands,
    buildNodeTestExtraGateCommands,
    parseRequestedNodeTestLanes,
} from '#tools/ci/run-node-tests';

const packageManagerRunner: PackageManagerRunner = {
    command: 'node',
    commandArgumentsPrefix: ['pnpm-entry.js'],
    kind: 'pnpm',
};

describe('Node test runner arguments', () => {
    it('keeps the heavy kernel lane out of the default Node aggregate', () => {
        expect(parseRequestedNodeTestLanes([])).toEqual([
            'fast',
            'protocol',
            'kernel-fast',
        ]);
    });

    it('accepts a single bare lane', () => {
        expect(parseRequestedNodeTestLanes(['kernel-fast'])).toEqual([
            'kernel-fast',
        ]);
    });

    it('expands the kernel aggregate lane', () => {
        expect(parseRequestedNodeTestLanes(['kernel'])).toEqual([
            'kernel-fast',
            'kernel-heavy',
        ]);
    });

    it('accepts comma-separated and space-separated lane lists', () => {
        expect(
            parseRequestedNodeTestLanes(['fast,protocol', 'kernel-fast']),
        ).toEqual(['fast', 'protocol', 'kernel-fast']);
    });

    it('rejects empty and unsupported lane names', () => {
        expect(() => parseRequestedNodeTestLanes([''])).toThrow(
            'At least one Node test lane is required.',
        );
        expect(() => parseRequestedNodeTestLanes(['unsupported'])).toThrow(
            'Unsupported Node test lane: unsupported',
        );
        expect(() => parseRequestedNodeTestLanes(['--unsupported'])).toThrow(
            'Unsupported Node test lane: --unsupported',
        );
    });

    it('rejects duplicate lanes before command or containment selection', () => {
        expect(() =>
            parseRequestedNodeTestLanes(['kernel-fast,kernel-fast']),
        ).toThrow('Node test lane requested more than once: kernel-fast');
        expect(() =>
            parseRequestedNodeTestLanes(['kernel', 'kernel-heavy']),
        ).toThrow('Node test lane requested more than once: kernel-heavy');
        expect(() =>
            buildNodeTestCommands({
                lanes: ['kernel-fast', 'kernel-fast'],
                packageManagerRunner,
            }),
        ).toThrow('Node test commands require distinct lanes.');
    });

    it('wraps heavy Node kernel commands in the process-memory guard', () => {
        const [heavyCommand] = buildNodeTestCommands({
            lanes: ['kernel-heavy'],
            packageManagerRunner,
        });

        expect(heavyCommand?.command).toContain(
            'sealed-lattice-process-memory-guard',
        );
        expect(heavyCommand?.args.slice(0, 5)).toEqual([
            '--memory-limit-bytes',
            expect.stringMatching(/^[1-9][0-9]*$/u),
            '--virtual-address-space-allowance-bytes',
            String(8 * 1024 ** 3),
            '--',
        ]);
        expect(heavyCommand?.args.slice(5)).toEqual([
            'node',
            'pnpm-entry.js',
            'exec',
            'vitest',
            '--project',
            'node-kernel-heavy',
            '--run',
        ]);

        const commands = buildNodeTestCommands({
            lanes: ['kernel-fast', 'kernel-heavy'],
            packageManagerRunner,
        });
        expect(commands).toHaveLength(1);
        expect(commands[0]?.command).toContain(
            'sealed-lattice-process-memory-guard',
        );
        expect(commands[0]?.args).toContain('node-kernel-fast');
        expect(commands[0]?.args).toContain('node-kernel-heavy');
    });

    it('keeps non-heavy Node commands unguarded', () => {
        const commands = buildNodeTestCommands({
            lanes: ['fast', 'protocol', 'kernel-fast'],
            packageManagerRunner,
        });

        expect(commands).toHaveLength(3);
        expect(commands.every((command) => command.command === 'node')).toBe(
            true,
        );
    });

    it('verifies the guard only for a heavy Node lane', () => {
        const heavyGateCommands = buildNodeTestExtraGateCommands({
            lanes: ['kernel-heavy'],
        });
        expect(heavyGateCommands).toHaveLength(1);
        expect(heavyGateCommands[0]?.command).toBe('cargo');
        expect(heavyGateCommands[0]?.args).toContain(
            'sealed-lattice-process-memory-guard',
        );

        const fastGateCommands = buildNodeTestExtraGateCommands({
            lanes: ['kernel-fast'],
        });
        expect(fastGateCommands).toEqual([]);
    });
});
