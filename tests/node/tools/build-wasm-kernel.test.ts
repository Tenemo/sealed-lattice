import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    assertDeterministicWasmStackLayout,
    createDeterministicCargoEnvironment,
    createWasmCargoBuildArguments,
    resolveWasmCargoExecutable,
    wasmStackByteLength,
} from '#tools/ci/build-wasm-kernel';

const encodedRustflagSeparator = '\x1f';

describe('WASM kernel build environment', () => {
    it('uses an explicit Cargo executable without changing the deterministic environment', () => {
        expect(resolveWasmCargoExecutable({})).toBe('cargo');
        expect(
            resolveWasmCargoExecutable({
                SEALED_LATTICE_CARGO_EXECUTABLE:
                    'C:\\toolchains\\cargo\\cargo.exe',
            }),
        ).toBe('C:\\toolchains\\cargo\\cargo.exe');
        expect(() =>
            resolveWasmCargoExecutable({
                SEALED_LATTICE_CARGO_EXECUTABLE: '   ',
            }),
        ).toThrow(/nonempty Cargo executable/u);
    });

    it('keeps the ordinary cargo build arguments feature-free', () => {
        expect(createWasmCargoBuildArguments()).toEqual([
            'build',
            '--locked',
            '--package',
            'sealed-lattice-kernel',
            '--lib',
            '--target',
            'wasm32-unknown-unknown',
            '--release',
        ]);
        expect(
            createWasmCargoBuildArguments(['primitive-measurement-evidence']),
        ).toEqual([
            'build',
            '--locked',
            '--package',
            'sealed-lattice-kernel',
            '--lib',
            '--target',
            'wasm32-unknown-unknown',
            '--release',
            '--features',
            'primitive-measurement-evidence',
        ]);
    });

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
            '-C',
            'link-arg=-z',
            '-C',
            `link-arg=stack-size=${wasmStackByteLength}`,
            '-C',
            'link-arg=--stack-first',
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

    it('requires one build-owned mutable stack global', () => {
        const moduleWithStack = Uint8Array.from([
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x06, 0x13, 0x03,
            0x7f, 0x01, 0x41, 0x80, 0x80, 0xc0, 0x00, 0x0b, 0x7f, 0x00, 0x41,
            0x01, 0x0b, 0x7f, 0x00, 0x41, 0x02, 0x0b,
        ]);

        expect(() =>
            assertDeterministicWasmStackLayout(moduleWithStack),
        ).not.toThrow();

        const moduleWithWrongStack = moduleWithStack.slice();
        moduleWithWrongStack[15] = 0x81;
        expect(() =>
            assertDeterministicWasmStackLayout(moduleWithWrongStack),
        ).toThrow(`initialized to ${wasmStackByteLength}`);
    });
});
