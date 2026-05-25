// This file is one focused part of the split test suite.
import { evaluationProofProfileId } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    roundTripBytesThroughKernel,
    verifyTranscriptCoreFixture,
} from '../../../src/index';
import {
    normalizeTranscriptCoreKernelBytesForDigest,
    TranscriptCoreKernelCommandError,
} from '../../../src/transcript-core-bridge';

import type { NamedFixture } from './shared.js';
import {
    ballotFieldLinearProofBackendVectors,
    encodedRelationVectors,
    expandBallotFieldLinearProofVectorCase,
    findFixture,
    fullyVerifiedActiveFixture,
    fullyVerifiedDevelopmentIntegrationFixture,
    invalidEnumFixture,
    linearProofBackendVectors,
    receiverKeyLinearProofBackendVectors,
    receiverKeyVectors,
    textDecoder,
    textEncoder,
    wasmHeader,
} from './shared.js';

import {
    canonicalJson,
    deriveProtocolDigest,
} from '#packages/crypto/src/index';

describe('transcript-core kernel in Node', () => {
    it('normalizes host-specific Rust source paths before digesting', () => {
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
            normalizeTranscriptCoreKernelBytesForDigest(windowsBytes);
        const normalizedLinuxBytes =
            normalizeTranscriptCoreKernelBytesForDigest(linuxBytes);

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

    it('ignores WASM custom sections before digesting', () => {
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
            Array.from(normalizeTranscriptCoreKernelBytesForDigest(leftBytes)),
        ).toEqual(
            Array.from(normalizeTranscriptCoreKernelBytesForDigest(rightBytes)),
        );
        expect(
            Array.from(normalizeTranscriptCoreKernelBytesForDigest(leftBytes)),
        ).toEqual(
            Array.from(Uint8Array.from([...wasmHeader, ...emptyTypeSection])),
        );
    });

    it('rejects malformed WASM sections before digesting', () => {
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
            normalizeTranscriptCoreKernelBytesForDigest(invalidLengthBytes),
        ).toThrow(
            'The transcript-core kernel contains an invalid WASM section length.',
        );
        expect(() =>
            normalizeTranscriptCoreKernelBytesForDigest(overflowingLengthBytes),
        ).toThrow(
            'The transcript-core kernel contains an invalid WASM section length.',
        );
        expect(() =>
            normalizeTranscriptCoreKernelBytesForDigest(truncatedLengthBytes),
        ).toThrow(
            'The transcript-core kernel contains a truncated WASM section length.',
        );
        expect(() =>
            normalizeTranscriptCoreKernelBytesForDigest(truncatedSectionBytes),
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

        const fullyVerifiedDevelopmentIntegrationAnalysis =
            kernel.analyzeCanonicalObject({
                canonicalBytesHex:
                    fullyVerifiedDevelopmentIntegrationFixture.canonicalBytesHex,
                chunkSize: fullyVerifiedDevelopmentIntegrationFixture.chunkSize,
            });
        const fullyVerifiedActiveAnalysis = kernel.analyzeCanonicalObject({
            canonicalBytesHex: fullyVerifiedActiveFixture.canonicalBytesHex,
            chunkSize: fullyVerifiedActiveFixture.chunkSize,
        });

        expect(
            fullyVerifiedDevelopmentIntegrationAnalysis.baseClaimProfile,
        ).toBe('fullyVerified');
        expect(
            fullyVerifiedDevelopmentIntegrationAnalysis.evaluationProofProfileId,
        ).toBe(evaluationProofProfileId);
        expect(fullyVerifiedActiveAnalysis.mheSecurityClosure).toBe(
            'activeMalicious',
        );
        expect(fullyVerifiedActiveAnalysis.evaluationProofProfileId).toBe(
            evaluationProofProfileId,
        );
        expect(
            fullyVerifiedDevelopmentIntegrationAnalysis.objectHash512,
        ).not.toBe(fullyVerifiedActiveAnalysis.objectHash512);
    });

    it('derives claim-bearing digests and field results through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.deriveProtocolDigest({
                namespace: 'PollSpecDigest',
                value: { poll: 'main' },
            }),
        ).toBe(
            '423c71de65abadb5adc05d9b6b704252420bb738af888c62614c8afc53a2be808662585305e76738b23e4f20154f8779e3827c0c8f313455d84675924f4a2c83',
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
            kernel.deriveProtocolDigest({
                namespace: 'UnreservedDigest',
                value: {},
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('keeps TypeScript and Rust canonical JSON behavior aligned for protocol digests', async () => {
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
                kernel.deriveProtocolDigest({
                    namespace: 'PollSpecDigest',
                    value,
                }),
            ).toBe(deriveProtocolDigest('PollSpecDigest', value));
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

            try {
                kernel.deriveProtocolDigest({
                    namespace: 'PollSpecDigest',
                    value,
                });
                throw new Error('Expected kernel canonical JSON rejection.');
            } catch (error) {
                expect(error).toBeInstanceOf(TranscriptCoreKernelCommandError);
                expect((error as TranscriptCoreKernelCommandError).code).toBe(
                    expectedKernelCode,
                );
            }
        }
    });

    it('verifies golden and malformed fixtures with stable outputs', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.verifyFixture(fullyVerifiedDevelopmentIntegrationFixture),
        ).toEqual({
            verified: true,
            caseName: 'fully-verified-development-integration-transcript-core',
            objectHash512:
                fullyVerifiedDevelopmentIntegrationFixture.expectedObjectHash512,
            chunkRoot:
                fullyVerifiedDevelopmentIntegrationFixture.expectedChunkRoot,
            statusLabels:
                fullyVerifiedDevelopmentIntegrationFixture.expectedStatusLabels,
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

        try {
            kernel.analyzeCanonicalObject({
                canonicalBytesHex: invalidEnumFixture.canonicalBytesHex,
                chunkSize: 8,
            });
        } catch (error) {
            expect(error).toBeInstanceOf(TranscriptCoreKernelCommandError);
            expect((error as TranscriptCoreKernelCommandError).code).toBe(
                'InvalidEnum',
            );
        }
    });

    it('keeps byte round-trip as an allocation smoke path', async () => {
        await expect(
            roundTripBytesThroughKernel(Uint8Array.from([9, 8, 7, 6, 5])),
        ).resolves.toEqual(Uint8Array.from([9, 8, 7, 6, 5]));
    });

    it('verifies fixtures through the public WASM wrapper', async () => {
        await expect(
            verifyTranscriptCoreFixture(
                fullyVerifiedDevelopmentIntegrationFixture,
            ),
        ).resolves.toEqual({
            verified: true,
            caseName: 'fully-verified-development-integration-transcript-core',
            objectHash512:
                fullyVerifiedDevelopmentIntegrationFixture.expectedObjectHash512,
            chunkRoot:
                fullyVerifiedDevelopmentIntegrationFixture.expectedChunkRoot,
            statusLabels:
                fullyVerifiedDevelopmentIntegrationFixture.expectedStatusLabels,
        });
    });

    it('computes internal hash smoke outputs through the command bridge', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.hashRaw('00')).toMatch(/^[a-f0-9]{128}$/u);
        expect(kernel.listCanonicalErrorCodes()).toContain('InvalidEnum');
        expect(kernel.listReservedRootNamespaces()).toContain(
            'sealed-lattice-root/poll-spec-digest-v1',
        );
        expect(kernel.listReservedRootNamespaces()).toContain(
            'sealed-lattice-root/proof-bytes-digest-v1',
        );
    });

    it('reports the ballot privacy proof backend and rejects malformed proof inputs', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const backendStatus = kernel.describeBallotPrivacyProofBackend();

        expect(backendStatus).toMatchObject({
            backendAvailable: true,
            portableRustWasmPortRequired: false,
        });
        expect(backendStatus.requiredComponents).toEqual([]);
        expect(backendStatus.blockedReason).toBeNull();

        expect(
            kernel.verifyReceiverKeyProof({ receiverKeyProof: {} }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            backendStatus: {
                portableRustWasmPortRequired: false,
            },
            operation: 'verifyReceiverKeyProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            kernel.verifyBallotProof({ statement: {}, ballotProof: {} }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            backendStatus: {
                portableRustWasmPortRequired: false,
            },
            operation: 'verifyBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            kernel
                .verifyBallotProof({
                    statement: {},
                    ballotProof: {
                        proofBytesDigest: '0'.repeat(128),
                        proofSizeBytes: 1,
                    },
                    proofBytesHex: 'AA',
                })
                .refusedObjects.some((refusal) =>
                    refusal.message.includes('proof bytes'),
                ),
        ).toBe(true);
        expect(
            kernel.verifyClaimBearingBallotPackage({ ballotPackage: {} }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            backendStatus: {
                portableRustWasmPortRequired: false,
            },
            operation: 'verifyClaimBearingBallotPackage',
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('routes internal linear proof vectors through the WASM backend gate', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const demoVectorCaseNames = new Set(
            linearProofBackendVectors.cases.map((vectorCase) =>
                String(vectorCase.caseName),
            ),
        );
        const receiverKeyVectorCaseNames = new Set(
            receiverKeyLinearProofBackendVectors.cases.map((vectorCase) =>
                String(vectorCase.caseName),
            ),
        );
        const ballotFieldVectorCaseNames = new Set(
            ballotFieldLinearProofBackendVectors.cases.map((vectorCase) =>
                String(vectorCase.caseName),
            ),
        );

        for (const requiredCaseName of linearProofBackendVectors.requiredCaseNames) {
            expect(demoVectorCaseNames.has(requiredCaseName)).toBe(true);
        }
        for (const requiredCaseName of receiverKeyLinearProofBackendVectors.requiredCaseNames) {
            expect(receiverKeyVectorCaseNames.has(requiredCaseName)).toBe(true);
        }
        for (const requiredCaseName of ballotFieldLinearProofBackendVectors.requiredCaseNames) {
            expect(ballotFieldVectorCaseNames.has(requiredCaseName)).toBe(true);
        }

        const demoVerification = kernel.verifyBallotPrivacyLinearProofVector({
            vectorCase: linearProofBackendVectors.cases[0],
        });

        expect(demoVerification).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'valid-small-linear-proof',
            vectorAvailable: true,
            unresolvedReason: null,
        });
        expect(demoVerification.statusLabels).toContain(
            'QuadraticChallengeRecomputed',
        );

        const receiverKeyLinearProofCases =
            receiverKeyLinearProofBackendVectors.cases as readonly (Record<
                string,
                unknown
            > &
                NamedFixture)[];
        const validReceiverKeyCase = findFixture(
            receiverKeyLinearProofCases,
            'valid-receiver-key-linear-proof',
        );
        const mutatedReceiverKeyCase = findFixture(
            receiverKeyLinearProofCases,
            'mutated-receiver-key-target-vector',
        );
        const receiverKeyVerification =
            kernel.verifyBallotPrivacyLinearProofVector({
                vectorCase: validReceiverKeyCase,
            });
        const mutatedReceiverKeyVerification =
            kernel.verifyBallotPrivacyLinearProofVector({
                vectorCase: mutatedReceiverKeyCase,
            });

        expect(receiverKeyVerification).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'valid-receiver-key-linear-proof',
            vectorAvailable: true,
            unresolvedReason: null,
        });
        expect(receiverKeyVerification.statusLabels).toContain(
            'QuadraticChallengeRecomputed',
        );
        expect(mutatedReceiverKeyVerification).toMatchObject({
            ok: false,
            backendAvailable: true,
            caseName: 'mutated-receiver-key-target-vector',
            vectorAvailable: true,
            unresolvedReason: 'InvalidFixture',
        });

        const ballotFieldLinearProofCases =
            ballotFieldLinearProofBackendVectors.cases as readonly (Record<
                string,
                unknown
            > &
                NamedFixture)[];
        const validBallotFieldCase = findFixture(
            ballotFieldLinearProofCases,
            'valid-encoded-score-field-linear-proof',
        );
        const mutatedBallotFieldCase = findFixture(
            ballotFieldLinearProofCases,
            'mutated-encoded-score-field-target-vector',
        );
        const ballotFieldVerification =
            kernel.verifyBallotPrivacyLinearProofVector({
                vectorCase:
                    expandBallotFieldLinearProofVectorCase(
                        validBallotFieldCase,
                    ),
            });
        const mutatedBallotFieldVerification =
            kernel.verifyBallotPrivacyLinearProofVector({
                vectorCase: expandBallotFieldLinearProofVectorCase(
                    mutatedBallotFieldCase,
                ),
            });

        expect(ballotFieldVerification).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'valid-encoded-score-field-linear-proof',
            vectorAvailable: true,
            unresolvedReason: null,
        });
        expect(ballotFieldVerification.statusLabels).toContain(
            'QuadraticChallengeRecomputed',
        );
        expect(mutatedBallotFieldVerification).toMatchObject({
            ok: false,
            backendAvailable: true,
            caseName: 'mutated-encoded-score-field-target-vector',
            vectorAvailable: true,
            unresolvedReason: 'InvalidFixture',
        });
    });

    it('routes encoded ballot relation vectors through the WASM backend gate', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const vectorCaseNames = new Set(
            encodedRelationVectors.cases.map((vectorCase) =>
                String(vectorCase.caseName),
            ),
        );

        for (const requiredCaseName of encodedRelationVectors.requiredCaseNames) {
            expect(vectorCaseNames.has(requiredCaseName)).toBe(true);
        }

        const miniCase = encodedRelationVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName === 'mini-encoded-ballot-relation',
        );
        const rejectCase = encodedRelationVectors.cases.find(
            (vectorCase) => vectorCase.caseName === 'wrong-quotient-rejects',
        );
        const digestChangeCase = encodedRelationVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'wrong-share-commitment-target-changes-digest',
        );
        const explicitShareCommitmentCase = encodedRelationVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'mini-encoded-ballot-share-commitment-explicit-relation',
        );
        const fullExplicitCase = encodedRelationVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'mini-encoded-ballot-full-explicit-relation',
        );
        const backendPreflightRejectCase = encodedRelationVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'noncanonical-backend-coefficient-rejects',
        );
        const proofComponentRejectCase = encodedRelationVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'backend-proof-component-mutation-rejects',
        );

        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: miniCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'mini-encoded-ballot-relation',
            expectedOutcome: 'accept',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: rejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'wrong-quotient-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: digestChangeCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'wrong-share-commitment-target-changes-digest',
            expectedOutcome: 'accept',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: explicitShareCommitmentCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'mini-encoded-ballot-share-commitment-explicit-relation',
            expectedOutcome: 'accept',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: fullExplicitCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'mini-encoded-ballot-full-explicit-relation',
            expectedOutcome: 'accept',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: backendPreflightRejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'noncanonical-backend-coefficient-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyEncodedRelationVector({
                vectorCase: proofComponentRejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'backend-proof-component-mutation-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
    });

    it('routes receiver-key proof vectors through the WASM backend gate', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const vectorCaseNames = new Set(
            receiverKeyVectors.cases.map((vectorCase) =>
                String(vectorCase.caseName),
            ),
        );

        for (const requiredCaseName of receiverKeyVectors.requiredCaseNames) {
            expect(vectorCaseNames.has(requiredCaseName)).toBe(true);
        }

        const validCase = receiverKeyVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'valid-receiver-key-proof-backend-statement',
        );
        const constructionRejectCase = receiverKeyVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName === 'wrong-public-matrix-seed-rejects',
        );
        const backendPreflightRejectCase = receiverKeyVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName === 'noncanonical-backend-modulus-rejects',
        );
        const linearPreflightRejectCase = receiverKeyVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName ===
                'mutated-linear-statement-target-rejects',
        );
        const proofShellRejectCase = receiverKeyVectors.cases.find(
            (vectorCase) =>
                vectorCase.caseName === 'mutated-proof-root-rejects',
        );

        expect(
            kernel.verifyBallotPrivacyReceiverKeyVector({
                vectorCase: validCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'valid-receiver-key-proof-backend-statement',
            expectedOutcome: 'accept',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyReceiverKeyVector({
                vectorCase: constructionRejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'wrong-public-matrix-seed-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyReceiverKeyVector({
                vectorCase: backendPreflightRejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'noncanonical-backend-modulus-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyReceiverKeyVector({
                vectorCase: linearPreflightRejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'mutated-linear-statement-target-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyBallotPrivacyReceiverKeyVector({
                vectorCase: proofShellRejectCase,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'mutated-proof-root-rejects',
            expectedOutcome: 'reject',
            unresolvedReason: null,
        });
    });
});
