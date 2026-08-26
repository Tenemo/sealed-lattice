import { describe, expect, it } from 'vitest';

import {
    buildRustKernelHeavyProcessMemoryGuardVerificationCommand,
    buildRustKernelHeavyTestCommand,
    parseRustKernelHeavyArguments,
} from '#tools/ci/run-rust-kernel-heavy-tests';
import { cargoTestArgumentsForRustKernelHeavy } from '#tools/ci/rust-kernel-test-arguments';

describe('Rust kernel heavy runner', () => {
    it('requires an exact active heavy-test filter before inventory compilation', () => {
        const activeTestFilter = 'heavy_rust_kernel_expensive_relation';
        expect(() => parseRustKernelHeavyArguments([])).toThrow(
            'require an exact active test filter',
        );
        expect(() => parseRustKernelHeavyArguments(['ordinary_test'])).toThrow(
            'must start with heavy_rust_kernel_',
        );
        expect(() => parseRustKernelHeavyArguments([activeTestFilter])).toThrow(
            'not in the source-controlled active registry',
        );
        const parsed = parseRustKernelHeavyArguments(
            [activeTestFilter],
            [activeTestFilter],
        );
        const arguments_ = cargoTestArgumentsForRustKernelHeavy(
            parsed.testFilter,
        );
        expect(arguments_).toContain('heavy_rust_kernel_expensive_relation');
        expect(arguments_).toContain('--ignored');
        expect(arguments_).toContain('--nocapture');
        expect(arguments_).not.toContain('--show-output');
        expect(arguments_).toContain('--test-threads');
        expect(arguments_).not.toContain('--skip');
    });

    it('normalizes a focused heavy filter', () => {
        expect(
            parseRustKernelHeavyArguments(
                ['heavy_rust_kernel_expensive_relation.rs'],
                ['heavy_rust_kernel_expensive_relation'],
            ),
        ).toEqual({
            testFilter: 'heavy_rust_kernel_expensive_relation',
        });
    });

    it('refuses unsupported checkpoint arguments', () => {
        expect(() =>
            parseRustKernelHeavyArguments(['--resume-checkpoints']),
        ).toThrow(/Unknown argument/u);
    });

    it('serializes heavy tests behind the verified process-memory guard', () => {
        const command = buildRustKernelHeavyTestCommand({
            testFilter: 'heavy_rust_kernel_expensive_relation',
        });
        expect(command.command).toContain(
            'sealed-lattice-process-memory-guard',
        );
        expect(Number(command.args[1])).toBeGreaterThan(0);
        expect(command.args).toContain('cargo');
        expect(command.env).toMatchObject({
            CARGO_BUILD_JOBS: '1',
            CARGO_INCREMENTAL: '0',
            RAYON_NUM_THREADS: '1',
        });
        expect(
            buildRustKernelHeavyProcessMemoryGuardVerificationCommand().args,
        ).toContain('sealed-lattice-process-memory-guard');
    });
});
