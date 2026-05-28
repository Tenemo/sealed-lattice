// This file is one targeted part of the split test suite.
import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '../../../src/index';

import {
    ballotFieldLinearProofBackendVectors,
    cloneJsonValue,
} from './shared.js';

import { createWasmBallotProofRecordGenerationFixture } from '#tests/support/ballot-privacy-proof-record-generation-fixtures';

describe('transcript-core kernel in Node', () => {
    it('generates ballot and dense component proof bytes through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const ringDegree = 64;
        const coefficientModulus = 65_537;
        const createZeroPolynomial = (): number[] =>
            Array.from({ length: ringDegree }, () => 0);
        const unitPolynomial = createZeroPolynomial();
        unitPolynomial[0] = 1;
        const targetPolynomial = createZeroPolynomial();
        targetPolynomial[0] = coefficientModulus - 5;
        const witnessPolynomial = createZeroPolynomial();
        witnessPolynomial[0] = 5;
        const parameterSet = {
            profileId: 'full-encoded-score-ballot-linear-compatibility-v1',
            source: 'sealed-lattice/linear-proof/full-encoded-score-ballot-wasm-test-parameters-v1',
            relation: 'A*w + t = 0',
            ringDegree,
            proofSystemRingDegree: ringDegree,
            coefficientModulus,
            statementRows: 1,
            statementColumns: 1,
            witnessL2BoundSquared: 65_536,
        };
        const proofEncoding = {
            ...cloneJsonValue(
                ballotFieldLinearProofBackendVectors.proofEncoding,
            ),
            profileId: 'full-encoded-score-ballot-linear-proof-encoding-v1',
            source: 'sealed-lattice/linear-proof/full-encoded-score-ballot-wasm-test-encoding-v1',
            shortResponseVectorLength: 2,
        };
        const linearStatement = {
            objectType: 'BallotProofLinearProofStatement',
            objectVersion: 1,
            parameterProfileId: parameterSet.profileId,
            projectionCoverage: 'full-encoded-score-ballot-relation',
            relation: 'A*w + t = 0',
            statementMatrixCoefficients: [[unitPolynomial]],
            targetCoefficientRepresentation: 'centeredSignedSourceModulus',
            targetVectorCoefficients: [targetPolynomial],
        };
        const secretState = {
            sourceWitnessCoefficients: [witnessPolynomial],
        };
        const publicRandomnessHex = '00'.repeat(32);
        const proverRandomnessHex = '07'.repeat(32);

        const generatedProof = kernel.generateBallotProof({
            linearStatement,
            parameterSet,
            proofEncoding,
            publicRandomnessHex,
            secretState,
            proverRandomnessHex,
        });

        expect(generatedProof).toMatchObject({
            ok: true,
            backendAvailable: true,
            generatedProofBytes: true,
            operation: 'generateBallotProof',
            unresolvedReason: null,
        });
        expect(generatedProof.statusLabels).toContain(
            'BallotGeneratedProofVerified',
        );
        expect(generatedProof.proofBytesHex).toMatch(/^[0-9a-f]+$/u);
        expect(generatedProof.proofSizeBytes).toBe(
            String(generatedProof.proofBytesHex).length / 2,
        );

        const proofInput = {
            componentId: 'score-and-shamir-field-component',
            proofStatementFormat: 'dense-polynomial-matrix-linear-proof-v1',
            proofStatement: linearStatement,
            proofParameterSet: parameterSet,
            proofEncoding,
            publicRandomnessHex,
        };
        const componentProof = kernel.generateBallotComponentProof({
            componentId: 'score-and-shamir-field-component',
            proofInput,
            secretState,
            proverRandomnessHex,
        });

        expect(componentProof).toMatchObject({
            ok: true,
            backendAvailable: true,
            generatedProofBytes: true,
            operation: 'generateBallotComponentProof',
            unresolvedReason: null,
        });
        expect(componentProof.statusLabels).toContain(
            'BallotComponentGeneratedProofVerified',
        );

        const wrongSecretState = {
            sourceWitnessCoefficients: [
                [6, ...createZeroPolynomial().slice(1)],
            ],
        };
        expect(
            kernel.generateBallotProof({
                linearStatement,
                parameterSet,
                proofEncoding,
                publicRandomnessHex,
                secretState: wrongSecretState,
                proverRandomnessHex,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'generateBallotProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('generates a ballot proof record with relation-derived component proofs through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const proofRecordGenerationFixture =
            createWasmBallotProofRecordGenerationFixture();
        const { request } = proofRecordGenerationFixture;

        const generation = kernel.generateBallotProofRecord(request);

        expect(generation).toMatchObject({
            ok: true,
            backendAvailable: true,
            generatedProofBytes: true,
            operation: 'generateBallotProofRecord',
            unresolvedReason: null,
        });
        expect(generation.statusLabels).toEqual(
            expect.arrayContaining([
                'BallotComponentProofBundleGenerated',
                'BallotProofRecordGenerated',
                'BallotProofRecordGeneratedProofVerified',
            ]),
        );
        expect(generation.verification).toMatchObject({
            ok: true,
            operation: 'verifyBallotProof',
            unresolvedReason: null,
        });
        expect(generation.proofBytesHex).toMatch(/^[0-9a-f]+$/u);
        expect(generation.proofSizeBytes).toBe(
            String(generation.proofBytesHex).length / 2,
        );
        const componentProofBundle = generation.componentProofBundle as {
            readonly componentProofs: readonly {
                readonly componentId: string;
                readonly proofSizeBytes: number;
            }[];
        };
        const componentProofInputs =
            generation.componentProofInputs as readonly {
                readonly componentId: string;
                readonly proofBytesHex: string;
                readonly proofStatementFormat: string;
            }[];
        expect(componentProofBundle.componentProofs).toHaveLength(5);
        expect(
            componentProofInputs.map((proofInput) => [
                proofInput.componentId,
                proofInput.proofStatementFormat,
            ]),
        ).toEqual([
            [
                'score-and-shamir-field-component',
                'dense-polynomial-matrix-linear-proof-v1',
            ],
            [
                'payload-plaintext-field-component',
                'sparse-polynomial-matrix-linear-proof-v1',
            ],
            [
                'share-commitment-component',
                'sparse-polynomial-matrix-linear-proof-v1',
            ],
            [
                'receiver-encryption-component',
                'structured-module-lwe-linear-proof-v1',
            ],
            [
                'receiver-key-binding-component',
                'public-zero-witness-binding-check-v1',
            ],
        ]);
        expect(
            componentProofInputs.find(
                (proofInput) =>
                    proofInput.componentId === 'receiver-key-binding-component',
            )?.proofBytesHex,
        ).toBe('');
        expect(
            componentProofBundle.componentProofs.find(
                (componentProof) =>
                    componentProof.componentId ===
                    'receiver-key-binding-component',
            )?.proofSizeBytes,
        ).toBe(0);

        const ballotPackage = {
            objectType: 'ClaimBearingBallotPackage',
            objectVersion: 1,
            ballotPackageDigest: request.statement.ballotPackageDigest,
            ballotProofStatement: request.statement,
            ballotProof: generation.ballotProof,
            proofBytesHex: generation.proofBytesHex,
            linearStatement: request.linearStatement,
            parameterSet: generation.parameterSet,
            proofEncoding: generation.proofEncoding,
            publicRandomnessHex: request.publicRandomnessHex,
            componentBundleStatement: request.componentBundleStatement,
            componentProofBundle: generation.componentProofBundle,
            componentProofInputs: generation.componentProofInputs,
            receiverKeyProofRootEvidence:
                proofRecordGenerationFixture.receiverKeyProofRootEvidence,
            receiverPayloads:
                proofRecordGenerationFixture.claimBearingReceiverPayloads,
            shareCommitments:
                proofRecordGenerationFixture.claimBearingShareCommitments,
        };
        const claimVerification = kernel.verifyClaimBearingBallotPackage({
            ballotPackage,
            unsafeSmallRosterAcknowledged:
                proofRecordGenerationFixture.request
                    .unsafeSmallRosterAcknowledged,
        });

        expect(claimVerification).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyClaimBearingBallotPackage',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            claimVerification.refusedObjects.some((refusal) =>
                /at least (?:10|ten) frozen participants/u.test(
                    refusal.message,
                ),
            ),
        ).toBe(true);
        expect(claimVerification.acceptedDigests).not.toContain(
            ballotPackage.ballotPackageDigest,
        );
        expect(
            kernel.verifyClaimBearingBallotPackage({
                ballotPackage: {
                    ...ballotPackage,
                    proofBytesHex: `00${String(generation.proofBytesHex).slice(2)}`,
                },
                unsafeSmallRosterAcknowledged:
                    proofRecordGenerationFixture.request
                        .unsafeSmallRosterAcknowledged,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyClaimBearingBallotPackage',
            unresolvedReason: 'BallotPackageInvalid',
        });
    }, 900_000);
});
