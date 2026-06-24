// This file is one targeted part of the split test suite.
import { describe, expect, it } from 'vitest';

import {
    foundationTranscriptCoreFixture,
    textDecoder,
    textEncoder,
    wasmHeader,
} from './shared.js';

import {
    canonicalJson,
    deriveProtocolHash,
    setupProofMaterialFullObjectHashHex,
} from '#packages/crypto/src/index';
import {
    setupProofChunkManifestRoot,
    setupProofMaterialChunkHash,
    setupProofTransportChunkSizeBytes,
} from '#packages/protocol/src/setup/setup-proof-material-transport';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import {
    normalizeTranscriptCoreKernelBytesForHash,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/transcript-core-bridge';

type SetupCommitmentOpeningComputation = Readonly<{
    readonly operation: 'computeSetupCommitmentFromOpening';
    readonly commitment: Record<string, unknown>;
    readonly commitmentRoot: string;
    readonly commitmentChunkRoot: string;
    readonly coefficientVectorHash512: string;
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

type ThresholdShareTransportStreamKernel = Readonly<{
    readonly describeCollectiveBgvSetupProfile: () => {
        readonly setupProfileHash: string;
        readonly qShareHash: string;
        readonly carryAwareVssShareRelationProfileHash: string;
        readonly commitmentProfileHash: string;
    };
    readonly beginThresholdShareCommitmentsFromTransportStream: (input: {
        readonly derivationId: string;
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: string;
        readonly transportedVssCoefficientCommitmentMaterial: unknown;
    }) => {
        readonly operation: 'beginThresholdShareCommitmentsFromTransportStream';
        readonly derivationId: string;
    };
    readonly finishThresholdShareCommitmentsFromTransportStream: (input: {
        readonly derivationId: string;
        readonly vssCoefficientCommitmentRoot: string;
        readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
    }) => unknown;
}>;

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

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

    it('analyzes the foundation transcript-core fixture through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();

        const foundationAnalysis = kernel.analyzeCanonicalObject({
            canonicalBytesHex:
                foundationTranscriptCoreFixture.canonicalBytesHex,
            chunkSize: foundationTranscriptCoreFixture.chunkSize,
        });

        expect(foundationAnalysis.tags).toContain('direct-route');
        expect(foundationAnalysis.title).toBe('Foundation transcript roots');
        expect(foundationAnalysis.sequence).toBe(10);
    });

    it('derives protocol Hashes and field results through WASM', async () => {
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

        expect(computation.operation).toBe('computeSetupCommitmentFromOpening');
        expect(computation.commitmentRoot).toHaveLength(128);
        expect(computation.commitmentChunkRoot).toHaveLength(128);
        expect(computation.coefficientVectorHash512).toHaveLength(128);
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

    it('exposes chunk-fed VSS threshold derivation stream commands through WASM', async () => {
        const kernel =
            (await loadTranscriptCoreKernel()) as ThresholdShareTransportStreamKernel;
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const setupContext = {
            ceremonyId: 'ceremony-main',
            manifestHash: 'a'.repeat(128),
            rosterHash: 'b'.repeat(128),
            setupProfileHash: profile.setupProfileHash,
            qShareHash: profile.qShareHash,
            carryAwareVssShareRelationProfileHash:
                profile.carryAwareVssShareRelationProfileHash,
            commitmentProfileHash: profile.commitmentProfileHash,
            setupEpoch: 'setup-epoch-1',
        };
        const derivationId = 'wasm-vss-stream-smoke';

        const beginResult =
            kernel.beginThresholdShareCommitmentsFromTransportStream({
                derivationId,
                setupContext,
                publicMatrixSeedHash: 'c'.repeat(128),
                transportedVssCoefficientCommitmentMaterial: {
                    objectType:
                        'SetupTransportedVssCoefficientCommitmentMaterial',
                    objectVersion: 1,
                    binaryFormat:
                        'sealed-lattice-vss-coefficient-commitment-material-binary-v1',
                    chunkSizeBytes: 1_048_576,
                    chunkCount: 1,
                    totalByteLength: 8,
                },
            });

        expect(beginResult).toMatchObject({
            operation: 'beginThresholdShareCommitmentsFromTransportStream',
            derivationId,
        });
        expect(() =>
            kernel.finishThresholdShareCommitmentsFromTransportStream({
                derivationId,
                vssCoefficientCommitmentRoot: 'd'.repeat(128),
                sourceTrusteeCoefficientCommitmentRecords: [],
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('exposes chunk-fed setup proof material stream commands through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const proofFamily = 'same-secret-linkage-anchor';
        const proofChunk = textEncoder.encode('setup proof material stream');
        const proofChunks = [proofChunk] as const;
        const fullObjectHash = setupProofMaterialFullObjectHashHex(
            proofFamily,
            proofChunk.byteLength,
            proofChunks,
        );
        const chunkHashes = [
            setupProofMaterialChunkHash(
                proofFamily,
                fullObjectHash,
                0,
                proofChunk,
            ),
        ];
        const chunkRoot = setupProofChunkManifestRoot(
            proofFamily,
            chunkHashes,
            fullObjectHash,
            proofChunk.byteLength,
        );
        const proofMaterialRoot = fullObjectHash;
        const verificationId = 'wasm-setup-proof-material-stream-smoke';

        const beginResult = kernel.beginSetupProofMaterialTransportStream({
            verificationId,
            transportedSetupProofMaterial: {
                objectType: 'SetupTransportedSameSecretProofMaterial',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId: 'SealedLattice-SetupProof-v1',
                proofFamily,
                proofMaterialRoot,
                chunkSizeBytes: setupProofTransportChunkSizeBytes,
                chunkCount: 1,
                totalByteLength: proofChunk.byteLength,
                fullObjectHash,
                chunkRoot,
                chunkHashes,
            },
        });

        expect(beginResult).toMatchObject({
            operation: 'beginSetupProofMaterialTransportStream',
            verificationId,
            proofFamily,
            proofMaterialRoot,
        });

        const absorbResult =
            kernel.absorbSetupProofMaterialTransportStreamChunk({
                verificationId,
                chunkIndex: 0,
                bytesHex: bytesToHex(proofChunk),
            });

        expect(absorbResult).toMatchObject({
            operation: 'absorbSetupProofMaterialTransportStreamChunk',
            absorbedChunkIndex: 0,
            nextChunkIndex: 1,
            observedTotalByteLength: proofChunk.byteLength,
        });

        const finishResult = kernel.finishSetupProofMaterialTransportStream({
            verificationId,
        });

        expect(finishResult).toMatchObject({
            operation: 'finishSetupProofMaterialTransportStream',
            verificationId,
            proofFamily,
            proofMaterialRoot,
            verifiedSetupProofMaterial: {
                objectType: 'VerifiedSetupProofMaterial',
                verificationId,
                proofFamily,
                proofMaterialRoot,
                proofFullObjectHash: fullObjectHash,
                proofChunkRoot: chunkRoot,
                proofChunkHashes: chunkHashes,
            },
        });
    });

    it('verifies golden and malformed fixtures with stable outputs', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.verifyFixture(foundationTranscriptCoreFixture)).toEqual({
            caseName: 'foundation-transcript-roots',
            objectHash512:
                foundationTranscriptCoreFixture.expectedObjectHash512,
            chunkRoot: foundationTranscriptCoreFixture.expectedChunkRoot,
        });
    });

    it('maps canonical rejection errors from command responses', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const malformedMagicHex = '42414421';

        expect(() =>
            kernel.analyzeCanonicalObject({
                canonicalBytesHex: malformedMagicHex,
                chunkSize: 8,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

        let canonicalError: unknown;
        try {
            kernel.analyzeCanonicalObject({
                canonicalBytesHex: malformedMagicHex,
                chunkSize: 8,
            });
        } catch (error) {
            canonicalError = error;
        }
        expect(canonicalError).toBeInstanceOf(TranscriptCoreKernelCommandError);
        expect((canonicalError as TranscriptCoreKernelCommandError).code).toBe(
            'MalformedMagic',
        );
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
        expect(kernel.listReservedRootNamespaces()).toContain(
            'sealed-lattice-root/poll-spec-hash-v1',
        );
        expect(kernel.listReservedRootNamespaces()).toContain(
            'sealed-lattice-root/proof-bytes-hash-v1',
        );
    });
});
