import { describe, expect, it } from 'vitest';

import {
    buildRustKernelHeavyProcessMemoryGuardVerificationCommand,
    buildRustKernelHeavyTestCommand,
    parseRustKernelHeavyArguments,
    rustKernelHeavyCheckpointResumeEnvironmentVariable,
} from '#tools/ci/run-rust-kernel-heavy-tests';
import {
    cargoTestArgumentsForRustKernelHeavy,
    heavyRustKernelTestNamePrefix,
} from '#tools/ci/rust-kernel-test-arguments';

describe('Rust kernel heavy runner', () => {
    it('owns only ignored tests under the heavy prefix by default', () => {
        const parsed = parseRustKernelHeavyArguments([]);
        expect(parsed.testFilter).toBe(heavyRustKernelTestNamePrefix);
        expect(parsed.resumeCheckpoints).toBe(false);

        const arguments_ = cargoTestArgumentsForRustKernelHeavy(
            parsed.testFilter,
        );
        expect(arguments_).toContain(heavyRustKernelTestNamePrefix);
        expect(arguments_).toContain('--ignored');
        expect(arguments_).toContain('--nocapture');
        expect(arguments_).not.toContain('--show-output');
        expect(arguments_).toContain('--test-threads');
    });

    it('normalizes a focused heavy filter', () => {
        expect(
            parseRustKernelHeavyArguments([
                'heavy_rust_kernel_expensive_relation.rs',
            ]),
        ).toEqual({
            resumeCheckpoints: false,
            testFilter: 'heavy_rust_kernel_expensive_relation',
        });
    });

    it('owns explicit checkpoint resume independently of filter position', () => {
        expect(
            parseRustKernelHeavyArguments([
                '--resume-checkpoints',
                '--',
                'heavy_rust_kernel_expensive_relation.rs',
            ]),
        ).toEqual({
            resumeCheckpoints: true,
            testFilter: 'heavy_rust_kernel_expensive_relation',
        });
        expect(
            parseRustKernelHeavyArguments([
                'heavy_rust_kernel_expensive_relation',
                '--resume-checkpoints',
            ]),
        ).toEqual({
            resumeCheckpoints: true,
            testFilter: 'heavy_rust_kernel_expensive_relation',
        });
        expect(() =>
            parseRustKernelHeavyArguments([
                '--resume-checkpoints',
                '--resume-checkpoints',
            ]),
        ).toThrow(/Duplicate --resume-checkpoints/u);
    });

    it('serializes heavy tests behind the verified process-memory guard', () => {
        const command = buildRustKernelHeavyTestCommand({
            resumeCheckpoints: true,
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
            [rustKernelHeavyCheckpointResumeEnvironmentVariable]: '1',
            SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE: '1',
        });
        expect(
            buildRustKernelHeavyTestCommand({
                resumeCheckpoints: false,
                testFilter: 'heavy_rust_kernel_expensive_relation',
            }).env?.[rustKernelHeavyCheckpointResumeEnvironmentVariable],
        ).toBe('0');
        expect(
            buildRustKernelHeavyProcessMemoryGuardVerificationCommand().args,
        ).toContain('sealed-lattice-process-memory-guard');
    });
});
