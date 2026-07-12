import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { createDeterministicCargoEnvironment } from '#tools/ci/build-wasm-kernel';

const encodedRustflagSeparator = '\x1f';

describe('WASM kernel build environment', () => {
    it('sets the complete deterministic Rust flag list and target directory', () => {
        const projectRoot = path.resolve('C:\\repo\\sealed-lattice');
        const cargoHome = path.resolve('C:\\cargo-home');
        const targetDirectory = path.resolve(projectRoot, 'target');
        const environment = createDeterministicCargoEnvironment(
            { PATH: 'toolchain' },
            { cargoHome, projectRoot, targetDirectory },
        );
        const rustflags = environment.CARGO_ENCODED_RUSTFLAGS?.split(
            encodedRustflagSeparator,
        );

        expect(rustflags).toEqual([
            '--remap-path-prefix',
            `${projectRoot}=/workspace`,
            '--remap-path-prefix',
            `${cargoHome}=/cargo`,
            '-C',
            expect.stringMatching(/^link-arg=--max-memory=\d+$/u),
        ]);
        expect(environment.CARGO_TARGET_DIR).toBe(targetDirectory);
        expect(environment.CARGO_INCREMENTAL).toBe('0');
        expect(environment.PATH).toBe('toolchain');
        expect(environment.SOURCE_DATE_EPOCH).toBe('0');
    });

    it('refuses inherited encoded Rust flags instead of producing environment-dependent bytes', () => {
        expect(() =>
            createDeterministicCargoEnvironment({
                CARGO_ENCODED_RUSTFLAGS: '-C\x1ftarget-cpu=native',
            }),
        ).toThrow(
            'CARGO_ENCODED_RUSTFLAGS must be unset for the deterministic WASM build.',
        );
    });

    it('accepts an explicitly empty inherited flag value', () => {
        expect(
            createDeterministicCargoEnvironment({
                CARGO_ENCODED_RUSTFLAGS: '',
            }).CARGO_ENCODED_RUSTFLAGS,
        ).toContain('--remap-path-prefix');
    });
});
