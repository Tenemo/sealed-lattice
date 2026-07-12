// This file is one targeted part of the split test suite.
import { describe, expect, it } from 'vitest';

import { textDecoder, textEncoder, wasmHeader } from './shared.js';

import {
    canonicalJson,
    deriveCanonicalObjectHash,
} from '#packages/crypto/src/index';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import {
    normalizeTranscriptCoreKernelBytesForHash,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/transcript-core-bridge';

type SetupCommitmentOpeningComputation = Readonly<{
    readonly commitment: Record<string, unknown>;
    readonly commitmentRoot: string;
}>;

type SetupCommitmentKernel = Readonly<{
    readonly exportedFunctionNames: readonly string[];
    readonly computeSetupCommitmentFromOpening: (input: {
        readonly publicMatrixSeedHash: string;
        readonly sourceRnsLimbIndex: number;
        readonly sourceMessageModulus: number;
        readonly shamirCoefficientIndex: number;
        readonly messageCoefficients: readonly number[];
        readonly randomnessByColumn: readonly (readonly number[])[];
        readonly ringDegree: number;
    }) => SetupCommitmentOpeningComputation;
}>;

describe('transcript-core kernel in Node', () => {
    it('normalizes host-specific Rust source paths before hashing', () => {
        const windowsBytes = textEncoder.encode(
            [
                'prefix',
                'C:\\Users\\Piotr\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\serde_json-1.0.149\\src\\error.rs',
                'crates\\sealed-lattice-kernel\\src\\lib.rs',
                'suffix',
            ].join('\0'),
        );
        const linuxBytes = textEncoder.encode(
            [
                'prefix',
                '/home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.149/src/error.rs',
                'crates/sealed-lattice-kernel/src/lib.rs',
                'suffix',
            ].join('\0'),
        );

        const normalizedWindowsBytes =
            normalizeTranscriptCoreKernelBytesForHash(windowsBytes);
        const normalizedLinuxBytes =
            normalizeTranscriptCoreKernelBytesForHash(linuxBytes);

        expect(Array.from(normalizedWindowsBytes)).toEqual(
            Array.from(normalizedLinuxBytes),
        );
        expect(textDecoder.decode(normalizedWindowsBytes)).toBe(
            [
                'prefix',
                '/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.149/src/error.rs',
                'crates/sealed-lattice-kernel/src/lib.rs',
                'suffix',
            ].join('\0'),
        );
    });

    it('ignores WASM custom sections before hashing', () => {
        const leftCustomSection = Uint8Array.from([0, 4, 3, 111, 110, 101]);
        const rightCustomSection = Uint8Array.from([0, 4, 3, 116, 119, 111]);
        const emptyTypeSection = Uint8Array.from([1, 1, 0]);

        const leftBytes = Uint8Array.from([
            ...wasmHeader,
            ...leftCustomSection,
            ...emptyTypeSection,
        ]);
        const rightBytes = Uint8Array.from([
            ...wasmHeader,
            ...rightCustomSection,
            ...emptyTypeSection,
        ]);

        expect(
            Array.from(normalizeTranscriptCoreKernelBytesForHash(leftBytes)),
        ).toEqual(
            Array.from(normalizeTranscriptCoreKernelBytesForHash(rightBytes)),
        );
        expect(
            Array.from(normalizeTranscriptCoreKernelBytesForHash(leftBytes)),
        ).toEqual(
            Array.from(Uint8Array.from([...wasmHeader, ...emptyTypeSection])),
        );
    });

    it('rejects malformed WASM sections before hashing', () => {
        const invalidLengthBytes = Uint8Array.from([
            ...wasmHeader,
            1,
            0x80,
            0x80,
            0x80,
            0x80,
            0x80,
        ]);
        const overflowingLengthBytes = Uint8Array.from([
            ...wasmHeader,
            1,
            0x80,
            0x80,
            0x80,
            0x80,
            0x10,
        ]);
        const truncatedLengthBytes = Uint8Array.from([...wasmHeader, 1, 0x80]);
        const truncatedSectionBytes = Uint8Array.from([...wasmHeader, 1, 2, 0]);

        expect(() =>
            normalizeTranscriptCoreKernelBytesForHash(invalidLengthBytes),
        ).toThrow(
            'The transcript-core kernel contains an invalid WASM section length.',
        );
        expect(() =>
            normalizeTranscriptCoreKernelBytesForHash(overflowingLengthBytes),
        ).toThrow(
            'The transcript-core kernel contains an invalid WASM section length.',
        );
        expect(() =>
            normalizeTranscriptCoreKernelBytesForHash(truncatedLengthBytes),
        ).toThrow(
            'The transcript-core kernel contains a truncated WASM section length.',
        );
        expect(() =>
            normalizeTranscriptCoreKernelBytesForHash(truncatedSectionBytes),
        ).toThrow(
            'The transcript-core kernel contains a truncated WASM section.',
        );
    });

    it('loads the transcript-core module and exposes command exports', async () => {
        const kernel =
            (await loadTranscriptCoreKernel()) as SetupCommitmentKernel;

        expect(kernel.exportedFunctionNames).toEqual(
            expect.arrayContaining([
                'memory',
                'sealed_lattice_allocate',
                'sealed_lattice_deallocate',
                'sealed_lattice_transcript_core_command_with_length',
                'sealed_lattice_roundtrip',
            ]),
        );
    });

    it('computes Shamir interpolation and plaintext comparison through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.interpolateShamirConstantTerm({
                sharePoints: [
                    { rosterPosition: 1, value: 15 },
                    { rosterPosition: 2, value: 25 },
                ],
            }),
        ).toBe(5);
        expect(
            kernel.evaluatePlaintextComparison({
                leftTotalScore: 41,
                rightTotalScore: 40,
                rosterSize: 5,
            }),
        ).toEqual({
            greaterThan: 1,
            equal: 0,
            scoreDifference: 1,
        });
    });

    it('keeps canonical JSON aligned for ASCII and sends Unicode through the Rust path', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const asciiValue = {
            objectType: 'CanonicalJsonParityProbe',
            controls: '\u0000then\u0009then\u001b',
            flags: [true, false, null],
            nested: { first: 'Cafe', second: 'supplementary key' },
            numbers: [Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER],
        };

        expect(kernel.deriveCanonicalObjectHash({ value: asciiValue })).toBe(
            deriveCanonicalObjectHash(asciiValue),
        );

        const rustUnicodeValues: readonly Record<string, unknown>[] = [
            {
                objectType: 'CanonicalJsonParityProbe',
                flags: [true, false, null],
                nested: {
                    a: 'Cafe\u0301',
                    ['\u{10000}']: 'supplementary key',
                    ['\uE000']: 'private-use key',
                },
                numbers: [Number.MIN_SAFE_INTEGER, 0, Number.MAX_SAFE_INTEGER],
            },
            {
                ['receiver\u0301']: {
                    ballot: ['\u0065\u0301', '\u00E9'],
                    rosterPosition: 20,
                },
                shareVectorWidth: 220,
                objectType: 'CanonicalJsonParityProbe',
            },
            {
                // Key order across the surrogate boundary: UTF-16 code-unit
                // sorting and Unicode code-point sorting disagree on whether
                // U+FFFF precedes U+10000.
                objectType: 'CanonicalJsonParityProbe',
                [String.fromCodePoint(0xff_ff)]: 'basic-plane boundary key',
                [String.fromCodePoint(0x1_00_00)]:
                    'supplementary-plane boundary key',
                [String.fromCodePoint(0xfb_00)]: 'compatibility ligature key',
            },
            {
                objectType: 'CanonicalJsonParityProbe',
                separators: [0x20_28, 0x20_29]
                    .map((codePoint) => String.fromCodePoint(codePoint))
                    .join('separates'),
                controls: [0x00_00, 0x00_09, 0x00_1b]
                    .map((codePoint) => String.fromCodePoint(codePoint))
                    .join('then'),
                emptyContainers: [{}, []],
                deep: [[[['edge']]]],
            },
        ];

        for (const value of rustUnicodeValues) {
            const firstHash = kernel.deriveCanonicalObjectHash({ value });

            expect(firstHash).toMatch(/^[a-f0-9]{128}$/u);
            expect(kernel.deriveCanonicalObjectHash({ value })).toBe(firstHash);
            expect(() => deriveCanonicalObjectHash(value)).toThrow(
                'only ASCII characters',
            );
        }
        expect(
            kernel.deriveCanonicalObjectHash({
                value: {
                    objectType: 'CanonicalJsonParityProbe',
                    text: 'Cafe\u0301',
                },
            }),
        ).toBe(
            kernel.deriveCanonicalObjectHash({
                value: {
                    objectType: 'CanonicalJsonParityProbe',
                    text: 'Caf\u00e9',
                },
            }),
        );

        // Negative zero collapses to zero on both sides of the boundary.
        expect(
            kernel.deriveCanonicalObjectHash({
                value: { objectType: 'CanonicalJsonParityProbe', zero: -0 },
            }),
        ).toBe(
            deriveCanonicalObjectHash({
                objectType: 'CanonicalJsonParityProbe',
                zero: 0,
            }),
        );

        const rejectedValues: readonly {
            readonly value: Record<string, unknown>;
            readonly expectedKernelCode: string;
        }[] = [
            {
                value: {
                    objectType: 'CanonicalJsonParityProbe',
                    ['e\u0301']: 1,
                    ['\u00E9']: 2,
                },
                expectedKernelCode: 'DuplicateField',
            },
            {
                value: {
                    objectType: 'CanonicalJsonParityProbe',
                    unsafeInteger: Number.MAX_SAFE_INTEGER + 1,
                },
                expectedKernelCode: 'InvalidProtocolObject',
            },
            {
                value: {
                    objectType: 'CanonicalJsonParityProbe',
                    fractional: 1.5,
                },
                expectedKernelCode: 'InvalidFixture',
            },
        ];

        for (const { value, expectedKernelCode } of rejectedValues) {
            expect(() => canonicalJson(value)).toThrow(TypeError);

            let canonicalObjectHashError: unknown;
            try {
                kernel.deriveCanonicalObjectHash({ value });
            } catch (error) {
                canonicalObjectHashError = error;
            }
            expect(canonicalObjectHashError).toBeInstanceOf(
                TranscriptCoreKernelCommandError,
            );
            expect(
                (canonicalObjectHashError as TranscriptCoreKernelCommandError)
                    .code,
            ).toBe(expectedKernelCode);
        }
    });

    it('computes setup commitments from openings through WASM', async () => {
        const kernel =
            (await loadTranscriptCoreKernel()) as SetupCommitmentKernel;
        const firstAcceptedDataPrime = 140_737_487_306_753;
        const ringDegree = 8;
        const messageCoefficients = [0, 1, 2, 3, 5, 8, 13, 21];
        const randomnessByColumn = Array.from(
            { length: 5 },
            (_unused, columnIndex) =>
                Array.from({ length: ringDegree }, (_unusedAgain, index) => {
                    const residue = (columnIndex + index) % 3;

                    return residue === 0 ? -1 : residue === 1 ? 0 : 1;
                }),
        );

        const computation: SetupCommitmentOpeningComputation =
            kernel.computeSetupCommitmentFromOpening({
                publicMatrixSeedHash: 'a'.repeat(128),
                sourceRnsLimbIndex: 0,
                sourceMessageModulus: firstAcceptedDataPrime,
                shamirCoefficientIndex: 1,
                messageCoefficients,
                randomnessByColumn,
                ringDegree,
            });

        expect(computation.commitmentRoot).toHaveLength(128);
        expect(computation.commitment).toMatchObject({
            objectType: 'SetupCommitment',
            sourceRnsLimbIndex: 0,
            sourceMessageModulus: firstAcceptedDataPrime,
            shamirCoefficientIndex: 1,
            ringDegree,
        });

        expect(() =>
            kernel.computeSetupCommitmentFromOpening({
                publicMatrixSeedHash: 'a'.repeat(128),
                sourceRnsLimbIndex: 0,
                sourceMessageModulus: firstAcceptedDataPrime + 1,
                shamirCoefficientIndex: 1,
                messageCoefficients,
                randomnessByColumn,
                ringDegree,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('keeps byte round-trip as an allocation smoke path', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.roundTripBytes(Uint8Array.from([9, 8, 7, 6, 5]))).toEqual(
            Uint8Array.from([9, 8, 7, 6, 5]),
        );
    });

    it('computes internal hash smoke outputs through the command bridge', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.hashRaw('00')).toMatch(/^[a-f0-9]{128}$/u);
        expect(kernel.listCanonicalErrorCodes()).toContain('InvalidEnum');
    });
});
