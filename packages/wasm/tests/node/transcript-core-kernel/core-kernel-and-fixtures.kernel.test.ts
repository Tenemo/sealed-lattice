// This file is one targeted part of the split test suite.
import { describe, expect, it } from 'vitest';

import {
    fullyVerifiedActiveFixture,
    fullyVerifiedPassiveMhePrototypeFixture,
    invalidEnumFixture,
    textDecoder,
    textEncoder,
    wasmHeader,
} from './shared.js';

import { canonicalJson, deriveProtocolHash } from '#packages/crypto/src/index';
import {
    loadTranscriptCoreKernel,
    roundTripBytesThroughKernel,
    verifyTranscriptCoreFixture,
} from '#packages/wasm/src/index';
import {
    normalizeTranscriptCoreKernelBytesForHash,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/transcript-core-bridge';

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
        const kernel = await loadTranscriptCoreKernel();

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

    it('analyzes golden transcript-core fixtures through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();

        const fullyVerifiedPassiveMhePrototypeAnalysis =
            kernel.analyzeCanonicalObject({
                canonicalBytesHex:
                    fullyVerifiedPassiveMhePrototypeFixture.canonicalBytesHex,
                chunkSize: fullyVerifiedPassiveMhePrototypeFixture.chunkSize,
            });
        const fullyVerifiedActiveAnalysis = kernel.analyzeCanonicalObject({
            canonicalBytesHex: fullyVerifiedActiveFixture.canonicalBytesHex,
            chunkSize: fullyVerifiedActiveFixture.chunkSize,
        });

        expect(fullyVerifiedPassiveMhePrototypeAnalysis.baseClaimProfile).toBe(
            'FullyVerifiedResult',
        );
        expect(fullyVerifiedActiveAnalysis.mheSecurityClosure).toBe(
            'ActiveMalicious',
        );
        expect(fullyVerifiedPassiveMhePrototypeAnalysis.objectHash512).not.toBe(
            fullyVerifiedActiveAnalysis.objectHash512,
        );
    });

    it('derives claim-bearing Hashes and field results through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.deriveProtocolHash({
                namespace: 'PollSpecHash',
                value: { poll: 'main' },
            }),
        ).toBe(
            '43b28c9a3dcb3e34d75c9936a9930b68fb9f2010b87d43a6a61cbaa85d343d9fd0be2b312a90f404367b9c68793b0dcf02c4dae7351f6e96ded894b92f898cb4',
        );
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
        expect(() =>
            kernel.deriveProtocolHash({
                namespace: 'UnreservedHash',
                value: {},
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('keeps TypeScript and Rust canonical JSON behavior aligned for protocol Hashes', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const acceptedValues: readonly unknown[] = [
            {
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
            },
        ];

        for (const value of acceptedValues) {
            expect(
                kernel.deriveProtocolHash({
                    namespace: 'PollSpecHash',
                    value,
                }),
            ).toBe(deriveProtocolHash('PollSpecHash', value));
        }

        const rejectedValues: readonly {
            readonly value: unknown;
            readonly expectedKernelCode: string;
        }[] = [
            {
                value: { ['e\u0301']: 1, ['\u00E9']: 2 },
                expectedKernelCode: 'DuplicateField',
            },
            {
                value: { unsafeInteger: Number.MAX_SAFE_INTEGER + 1 },
                expectedKernelCode: 'InvalidFixture',
            },
            {
                value: { fractional: 1.5 },
                expectedKernelCode: 'InvalidFixture',
            },
        ];

        for (const { value, expectedKernelCode } of rejectedValues) {
            expect(() => canonicalJson(value)).toThrow(TypeError);

            let protocolHashError: unknown;
            try {
                kernel.deriveProtocolHash({
                    namespace: 'PollSpecHash',
                    value,
                });
            } catch (error) {
                protocolHashError = error;
            }
            expect(protocolHashError).toBeInstanceOf(
                TranscriptCoreKernelCommandError,
            );
            expect(
                (protocolHashError as TranscriptCoreKernelCommandError).code,
            ).toBe(expectedKernelCode);
        }
    });

    it('verifies golden and malformed fixtures with stable outputs', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.verifyFixture(fullyVerifiedPassiveMhePrototypeFixture),
        ).toEqual({
            verified: true,
            caseName: 'fully-verified-passive-mhe-prototype-transcript-core',
            objectHash512:
                fullyVerifiedPassiveMhePrototypeFixture.expectedObjectHash512,
            chunkRoot:
                fullyVerifiedPassiveMhePrototypeFixture.expectedChunkRoot,
            statusLabels:
                fullyVerifiedPassiveMhePrototypeFixture.expectedStatusLabels,
        });
        expect(kernel.verifyFixture(invalidEnumFixture)).toEqual({
            verified: true,
            caseName: 'invalid-enum',
            expectedErrorCode: 'InvalidEnum',
        });
    });

    it('maps canonical rejection errors from command responses', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() =>
            kernel.analyzeCanonicalObject({
                canonicalBytesHex: invalidEnumFixture.canonicalBytesHex,
                chunkSize: 8,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

        let invalidEnumError: unknown;
        try {
            kernel.analyzeCanonicalObject({
                canonicalBytesHex: invalidEnumFixture.canonicalBytesHex,
                chunkSize: 8,
            });
        } catch (error) {
            invalidEnumError = error;
        }
        expect(invalidEnumError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (invalidEnumError as TranscriptCoreKernelCommandError).code,
        ).toBe('InvalidEnum');
    });

    it('keeps byte round-trip as an allocation smoke path', async () => {
        await expect(
            roundTripBytesThroughKernel(Uint8Array.from([9, 8, 7, 6, 5])),
        ).resolves.toEqual(Uint8Array.from([9, 8, 7, 6, 5]));
    });

    it('verifies fixtures through the public WASM wrapper', async () => {
        await expect(
            verifyTranscriptCoreFixture(
                fullyVerifiedPassiveMhePrototypeFixture,
            ),
        ).resolves.toEqual({
            verified: true,
            caseName: 'fully-verified-passive-mhe-prototype-transcript-core',
            objectHash512:
                fullyVerifiedPassiveMhePrototypeFixture.expectedObjectHash512,
            chunkRoot:
                fullyVerifiedPassiveMhePrototypeFixture.expectedChunkRoot,
            statusLabels:
                fullyVerifiedPassiveMhePrototypeFixture.expectedStatusLabels,
        });
    });

    it('computes internal hash smoke outputs through the command bridge', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.hashRaw('00')).toMatch(/^[a-f0-9]{128}$/u);
        expect(kernel.listCanonicalErrorCodes()).toContain('InvalidEnum');
        expect(kernel.listReservedRootNamespaces()).toContain(
            'sealed-lattice-root/poll-spec-hash-v1',
        );
        expect(kernel.listReservedRootNamespaces()).toContain(
            'sealed-lattice-root/proof-bytes-hash-v1',
        );
    });
});
