// This file is one focused part of the split test suite.
import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '../../../src/index';

import type { NamedFixture } from './shared.js';
import {
    cloneJsonValue,
    findFixture,
    receiverKeyLinearProofBackendVectors,
} from './shared.js';

describe('transcript-core kernel in Node', () => {
    it('verifies proof-byte-bearing receiver-key records through the WASM linear proof backend', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const receiverKeyLinearProofCases =
            receiverKeyLinearProofBackendVectors.cases as readonly (Record<
                string,
                unknown
            > &
                NamedFixture)[];
        const validProofCase = findFixture(
            receiverKeyLinearProofCases,
            'valid-receiver-key-linear-proof',
        );
        const mutatedTargetCase = findFixture(
            receiverKeyLinearProofCases,
            'mutated-receiver-key-target-vector',
        );
        const proofBytesHex = String(validProofCase.proofHex);
        const publicRandomnessHex = String(validProofCase.publicRandomnessHex);
        const proofSizeBytes = proofBytesHex.length / 2;
        const productionParameterSet = {
            ...(validProofCase.parameterSet as Record<string, unknown>),
            profileId: 'receiver-key-linear-module-lwe-v1',
            source: 'sealed-lattice/linear-proof/receiver-key-parameters-v1',
        };
        const productionProofEncoding = {
            ...(validProofCase.proofEncoding as Record<string, unknown>),
            source: 'sealed-lattice/linear-proof/receiver-key-encoding-v1',
        };
        const digest = (label: string): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    label,
                    purpose: 'receiver-key-proof-record-wasm-test',
                },
            });
        const createLinearStatement = (
            targetVectorCoefficients: unknown,
        ): Record<string, unknown> => {
            const statementPayload = {
                ceremonyId: 'ceremony-receiver-key-proof-record',
                coefficientModulus: '12289',
                keyMaterialDigest: digest('receiver-key-material'),
                manifestDigest: digest('manifest'),
                objectType: 'ReceiverKeyLinearProofStatement',
                objectVersion: 1,
                publicMatrixSeedDigest: digest('receiver-matrix-seed'),
                receiverEncryptionProfileDigest: digest(
                    'receiver-encryption-profile',
                ),
                receiverIdentity: 'receiver-1',
                receiverPublicKeyDigest: digest('receiver-public-key'),
                receiverRosterPosition: 1,
                recoveryEpoch: 0,
                relation: 'A*w + t = 0',
                ringDegree: 256,
                rosterDigest: digest('roster'),
                sourceRing: 'Z_q[X]/(X^256 + 1)',
                statementColumns: 8,
                statementMatrixCoefficients:
                    validProofCase.statementMatrixCoefficients,
                statementMatrixDigest: digest('statement-matrix'),
                statementProfileId:
                    'receiver-key-linear-module-lwe-statement-v1',
                statementRows: 4,
                targetCoefficientRepresentation:
                    validProofCase.targetCoefficientRepresentation,
                targetVectorCoefficients,
                targetVectorDigest: digest('target-vector'),
                witnessInfinityNormBound: 2,
                witnessL2BoundSquared: '8192',
                witnessVectorLayout: [
                    'receiver secret polynomial 0',
                    'receiver secret polynomial 1',
                    'receiver secret polynomial 2',
                    'receiver secret polynomial 3',
                    'receiver error polynomial 0',
                    'receiver error polynomial 1',
                    'receiver error polynomial 2',
                    'receiver error polynomial 3',
                ],
            };

            return {
                ...statementPayload,
                statementDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: statementPayload,
                        purpose: 'receiver-key-linear-proof-statement-v1',
                    },
                }),
            };
        };
        const createReceiverKeyProof = (
            linearStatement: Record<string, unknown>,
            proofInput: {
                readonly parameterSet?: unknown;
                readonly proofEncoding?: unknown;
            } = {},
        ): Record<string, unknown> => {
            const parameterSet =
                proofInput.parameterSet ?? validProofCase.parameterSet;
            const proofEncoding =
                proofInput.proofEncoding ?? validProofCase.proofEncoding;
            const proofBytesDigest = kernel.deriveProtocolDigest({
                namespace: 'ProofBytesDigest',
                value: {
                    objectType: 'ProofBytes',
                    objectVersion: 1,
                    proofBytesHex,
                    proofSizeBytes,
                },
            });
            const proofEncodingProfileDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    proofEncoding,
                    purpose: 'receiver-key-linear-proof-encoding-profile-v1',
                },
            });
            const proofParameterSetDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    parameterSet,
                    purpose: 'receiver-key-linear-proof-parameter-set-v1',
                },
            });
            const publicRandomnessDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    publicRandomnessHex,
                    purpose: 'receiver-key-linear-proof-public-randomness-v1',
                },
            });
            const proofRoot = kernel.deriveProtocolDigest({
                namespace: 'ReceiverKeyProofRoot',
                value: {
                    linearStatementDigest: linearStatement.statementDigest,
                    proofBytesDigest,
                    proofEncodingProfileDigest,
                    proofParameterSetDigest,
                    publicRandomnessDigest,
                    purpose: 'receiver-key-linear-proof-record-root-v1',
                },
            });
            const proofPayload = {
                backendStatementDigest: digest('backend-statement'),
                ceremonyId: 'ceremony-receiver-key-proof-record',
                linearStatementDigest: linearStatement.statementDigest,
                manifestDigest: digest('manifest'),
                objectType: 'ReceiverKeyProof',
                objectVersion: 1,
                proofBackend: 'LocalLinearLatticeRelation',
                proofBytesDigest,
                proofEncodingProfileDigest,
                proofParameterSetDigest,
                proofRoot,
                proofSizeBytes,
                publicRandomnessDigest,
                receiverEncryptionProfileDigest: digest(
                    'receiver-encryption-profile',
                ),
                receiverIdentity: 'receiver-1',
                receiverPublicKeyDigest: digest('receiver-public-key'),
                receiverRosterPosition: 1,
                recoveryEpoch: 0,
                rosterDigest: digest('roster'),
            };

            return {
                ...proofPayload,
                receiverKeyProofRoot: kernel.deriveProtocolDigest({
                    namespace: 'ReceiverKeyProofRoot',
                    value: proofPayload,
                }),
            };
        };
        const validLinearStatement = createLinearStatement(
            validProofCase.targetVectorCoefficients,
        );
        const validReceiverKeyProof = createReceiverKeyProof(
            validLinearStatement,
            {
                parameterSet: productionParameterSet,
                proofEncoding: productionProofEncoding,
            },
        );
        const mutatedLinearStatement = createLinearStatement(
            mutatedTargetCase.targetVectorCoefficients,
        );
        const mutatedReceiverKeyProof = createReceiverKeyProof(
            mutatedLinearStatement,
            {
                parameterSet: productionParameterSet,
                proofEncoding: productionProofEncoding,
            },
        );

        expect(
            kernel.verifyReceiverKeyProof({
                linearStatement: validLinearStatement,
                parameterSet: productionParameterSet,
                proofBytesHex,
                proofEncoding: productionProofEncoding,
                publicRandomnessHex,
                receiverKeyProof: validReceiverKeyProof,
            }),
        ).toMatchObject({
            ok: true,
            backendAvailable: true,
            operation: 'verifyReceiverKeyProof',
            unresolvedReason: null,
        });
        expect(
            kernel.verifyReceiverKeyProof({
                linearStatement: mutatedLinearStatement,
                parameterSet: productionParameterSet,
                proofBytesHex,
                proofEncoding: productionProofEncoding,
                publicRandomnessHex,
                receiverKeyProof: mutatedReceiverKeyProof,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyReceiverKeyProof',
            unresolvedReason: 'InvalidFixture',
        });
        expect(
            kernel.verifyReceiverKeyProof({
                linearStatement: validLinearStatement,
                parameterSet: productionParameterSet,
                proofBytesHex: proofBytesHex.slice(0, -2),
                proofEncoding: productionProofEncoding,
                publicRandomnessHex,
                receiverKeyProof: validReceiverKeyProof,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyReceiverKeyProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        const sizeUnboundParameterSet = {
            ...productionParameterSet,
            expectedProofSizeBytes: proofSizeBytes + 1,
        };
        expect(
            kernel.verifyReceiverKeyProof({
                linearStatement: validLinearStatement,
                parameterSet: sizeUnboundParameterSet,
                proofBytesHex,
                proofEncoding: productionProofEncoding,
                publicRandomnessHex,
                receiverKeyProof: createReceiverKeyProof(validLinearStatement, {
                    parameterSet: sizeUnboundParameterSet,
                }),
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyReceiverKeyProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
        const sizeUnboundProofEncoding = {
            ...productionProofEncoding,
            expectedProofSizeBytes: proofSizeBytes + 1,
        };
        expect(
            kernel.verifyReceiverKeyProof({
                linearStatement: validLinearStatement,
                parameterSet: productionParameterSet,
                proofBytesHex,
                proofEncoding: sizeUnboundProofEncoding,
                publicRandomnessHex,
                receiverKeyProof: createReceiverKeyProof(validLinearStatement, {
                    proofEncoding: sizeUnboundProofEncoding,
                }),
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'verifyReceiverKeyProof',
            unresolvedReason: 'BallotPackageInvalid',
        });
    });

    it('prepares receiver-key proof generation witness material through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const receiverKeyLinearProofCases =
            receiverKeyLinearProofBackendVectors.cases as readonly (Record<
                string,
                unknown
            > &
                NamedFixture)[];
        const validProofCase = findFixture(
            receiverKeyLinearProofCases,
            'valid-receiver-key-linear-proof',
        );
        const productionParameterSet = {
            ...(validProofCase.parameterSet as Record<string, unknown>),
            profileId: 'receiver-key-linear-module-lwe-v1',
            source: 'sealed-lattice/linear-proof/receiver-key-parameters-v1',
        };
        const productionProofEncoding = {
            ...(validProofCase.proofEncoding as Record<string, unknown>),
            source: 'sealed-lattice/linear-proof/receiver-key-encoding-v1',
        };
        const receiverKeyModulus = 12_289;
        const receiverKeyRingDegree = 256;
        const receiverKeyStatementRows = 4;
        const receiverKeyStatementColumns = 8;
        const createZeroPolynomial = (): number[] =>
            Array.from({ length: receiverKeyRingDegree }, () => 0);
        const createUnitPolynomial = (): number[] => {
            const polynomial = createZeroPolynomial();
            polynomial[0] = 1;

            return polynomial;
        };
        const canonicalSignedPolynomial = (
            polynomial: readonly number[],
        ): number[] =>
            polynomial.map((coefficient) =>
                coefficient < 0
                    ? receiverKeyModulus - Math.abs(coefficient)
                    : Math.abs(coefficient),
            );
        const witnessVector: number[][] = Array.from(
            { length: receiverKeyStatementColumns },
            () => createZeroPolynomial(),
        );
        witnessVector[0][0] = 2;
        witnessVector[0][5] = -1;
        witnessVector[1][1] = 1;
        witnessVector[4][0] = -2;
        witnessVector[5][7] = 1;
        const statementMatrixCoefficients = Array.from(
            { length: receiverKeyStatementRows },
            () =>
                Array.from(
                    { length: receiverKeyStatementColumns },
                    createZeroPolynomial,
                ),
        );
        for (
            let rowIndex = 0;
            rowIndex < receiverKeyStatementRows;
            rowIndex += 1
        ) {
            const statementMatrixRow = statementMatrixCoefficients[rowIndex];
            statementMatrixRow[rowIndex] = createUnitPolynomial();
            statementMatrixRow[rowIndex + receiverKeyStatementRows] =
                createUnitPolynomial();
        }
        const targetVectorCoefficients = Array.from(
            { length: receiverKeyStatementRows },
            (_, rowIndex) => {
                const secretPolynomial = canonicalSignedPolynomial(
                    witnessVector[rowIndex],
                );
                const errorPolynomial = canonicalSignedPolynomial(
                    witnessVector[rowIndex + receiverKeyStatementRows],
                );

                return secretPolynomial.map((coefficient, coefficientIndex) => {
                    const publicKeyCoefficient =
                        (coefficient +
                            (errorPolynomial[coefficientIndex] ?? 0)) %
                        receiverKeyModulus;

                    return publicKeyCoefficient === 0
                        ? 0
                        : receiverKeyModulus - publicKeyCoefficient;
                });
            },
        );
        const digest = (label: string): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    label,
                    purpose: 'receiver-key-prover-preflight-wasm-test',
                },
            });
        const linearStatementPayload = {
            ceremonyId: 'ceremony-receiver-key-prover-preflight',
            coefficientModulus: '12289',
            keyMaterialDigest: digest('receiver-key-material'),
            manifestDigest: digest('manifest'),
            objectType: 'ReceiverKeyLinearProofStatement',
            objectVersion: 1,
            publicMatrixSeedDigest: digest('receiver-matrix-seed'),
            receiverEncryptionProfileDigest: digest(
                'receiver-encryption-profile',
            ),
            receiverIdentity: 'receiver-1',
            receiverPublicKeyDigest: digest('receiver-public-key'),
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            relation: 'A*w + t = 0',
            ringDegree: receiverKeyRingDegree,
            rosterDigest: digest('roster'),
            sourceRing: 'Z_q[X]/(X^256 + 1)',
            statementColumns: receiverKeyStatementColumns,
            statementMatrixCoefficients,
            statementMatrixDigest: digest('statement-matrix'),
            statementProfileId: 'receiver-key-linear-module-lwe-statement-v1',
            statementRows: receiverKeyStatementRows,
            targetCoefficientRepresentation: 'centeredSignedSourceModulus',
            targetVectorCoefficients,
            targetVectorDigest: digest('target-vector'),
            witnessInfinityNormBound: 2,
            witnessL2BoundSquared: '8192',
            witnessVectorLayout: [
                'receiver secret polynomial 0',
                'receiver secret polynomial 1',
                'receiver secret polynomial 2',
                'receiver secret polynomial 3',
                'receiver error polynomial 0',
                'receiver error polynomial 1',
                'receiver error polynomial 2',
                'receiver error polynomial 3',
            ],
        };
        const linearStatement = {
            ...linearStatementPayload,
            statementDigest: kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    payload: linearStatementPayload,
                    purpose: 'receiver-key-linear-proof-statement-v1',
                },
            }),
        };
        const secretState = {
            secretVector: witnessVector.slice(0, receiverKeyStatementRows),
            errorVector: witnessVector.slice(receiverKeyStatementRows),
        };
        const preparation = kernel.prepareReceiverKeyProofGeneration({
            linearStatement,
            parameterSet: productionParameterSet,
            proofEncoding: productionProofEncoding,
            publicRandomnessHex: '00'.repeat(32),
            secretState,
            proverRandomnessHex: '09'.repeat(32),
        });

        expect(preparation).toMatchObject({
            ok: true,
            backendAvailable: true,
            generatedProofBytes: false,
            operation: 'prepareReceiverKeyProofGeneration',
            summary: {
                normSlack: '8181',
                preparedShortWitnessPolynomialCount: 33,
                relationWitnessPolynomialCount: 32,
                shortWitnessPolynomialCount: 33,
                witnessL2Squared: '11',
                abdlopCommitment: {
                    compressedCommitmentPolynomialCount: 19,
                    openingRandomnessPolynomialCount: 55,
                    openingRemainderPolynomialCount: 19,
                    proverRandomnessSeedBytes: 32,
                    subprotocolSeedBytes: 32,
                },
            },
            unresolvedReason: null,
        });
        expect(preparation.statusLabels).toContain(
            'ReceiverKeyProofRingWitnessPrepared',
        );
        expect(preparation.statusLabels).toContain(
            'ReceiverKeyAbdlopCommitmentPrepared',
        );
        expect(
            preparation.summary?.abdlopCommitment?.abdlopCommitmentHash,
        ).toMatch(/^[0-9a-f]{64}$/u);

        const generatedProof = kernel.generateReceiverKeyProof({
            linearStatement,
            parameterSet: productionParameterSet,
            proofEncoding: productionProofEncoding,
            publicRandomnessHex: '00'.repeat(32),
            secretState,
            proverRandomnessHex: '09'.repeat(32),
        });
        const repeatedGeneratedProof = kernel.generateReceiverKeyProof({
            linearStatement,
            parameterSet: productionParameterSet,
            proofEncoding: productionProofEncoding,
            publicRandomnessHex: '00'.repeat(32),
            secretState,
            proverRandomnessHex: '09'.repeat(32),
        });
        const changedGeneratedProof = kernel.generateReceiverKeyProof({
            linearStatement,
            parameterSet: productionParameterSet,
            proofEncoding: productionProofEncoding,
            publicRandomnessHex: '00'.repeat(32),
            secretState,
            proverRandomnessHex: '0a'.repeat(32),
        });
        const freshRandomnessGeneratedProof = kernel.generateReceiverKeyProof({
            linearStatement,
            parameterSet: productionParameterSet,
            proofEncoding: productionProofEncoding,
            secretState,
        });

        expect(generatedProof).toMatchObject({
            ok: true,
            backendAvailable: true,
            generatedProofBytes: true,
            operation: 'generateReceiverKeyProof',
            unresolvedReason: null,
        });
        expect(generatedProof.statusLabels).toContain(
            'ReceiverKeyProofGenerationVerified',
        );
        expect(generatedProof.proofBytesHex).toMatch(/^[0-9a-f]+$/u);
        expect(generatedProof.proofSizeBytes).toBe(
            String(generatedProof.proofBytesHex).length / 2,
        );
        expect(repeatedGeneratedProof.proofBytesHex).toBe(
            generatedProof.proofBytesHex,
        );
        expect(changedGeneratedProof.proofBytesHex).not.toBe(
            generatedProof.proofBytesHex,
        );
        expect(freshRandomnessGeneratedProof).toMatchObject({
            ok: true,
            backendAvailable: true,
            generatedProofBytes: true,
            operation: 'generateReceiverKeyProof',
            unresolvedReason: null,
        });
        expect(freshRandomnessGeneratedProof.proofBytesHex).toMatch(
            /^[0-9a-f]+$/u,
        );

        const generatedVectorCase = {
            caseName: 'generated-receiver-key-proof',
            description:
                'Receiver-key linear proof generated by the internal Rust prover.',
            mutation: 'none',
            expectedOutcome: 'accept',
            upstreamVectorAvailable: true,
            parameterSet: productionParameterSet,
            proofEncoding: productionProofEncoding,
            publicRandomnessHex: '00'.repeat(32),
            statementMatrixCoefficients,
            targetVectorCoefficients,
            targetCoefficientRepresentation: 'centeredSignedSourceModulus',
            proofHex: generatedProof.proofBytesHex,
            expectedProofSizeBytes: generatedProof.proofSizeBytes,
        };
        const generatedVerification =
            kernel.verifyBallotPrivacyLinearProofVector({
                vectorCase: generatedVectorCase,
            });
        expect(generatedVerification).toMatchObject({
            ok: true,
            backendAvailable: true,
            caseName: 'generated-receiver-key-proof',
            unresolvedReason: null,
        });

        const mutatedGeneratedVectorCase = cloneJsonValue(generatedVectorCase);
        mutatedGeneratedVectorCase.caseName =
            'generated-receiver-key-proof-mutated-target';
        mutatedGeneratedVectorCase.expectedOutcome = 'reject';
        mutatedGeneratedVectorCase.targetVectorCoefficients[0][0] =
            (mutatedGeneratedVectorCase.targetVectorCoefficients[0][0] + 1) %
            receiverKeyModulus;
        expect(
            kernel.verifyBallotPrivacyLinearProofVector({
                vectorCase: mutatedGeneratedVectorCase,
            }),
        ).toMatchObject({
            ok: false,
            backendAvailable: true,
            caseName: 'generated-receiver-key-proof-mutated-target',
            unresolvedReason: 'InvalidFixture',
        });

        const wrongSecretState = cloneJsonValue(secretState);
        wrongSecretState.secretVector[0][0] = 3;
        const rejection = kernel.prepareReceiverKeyProofGeneration({
            linearStatement,
            parameterSet: productionParameterSet,
            proofEncoding: productionProofEncoding,
            publicRandomnessHex: '00'.repeat(32),
            secretState: wrongSecretState,
            proverRandomnessHex: '09'.repeat(32),
        });

        expect(rejection).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'prepareReceiverKeyProofGeneration',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(String(rejection.refusedObjects[0]?.message)).toContain(
            'source witness',
        );

        const compatibilityProfileRejection =
            kernel.prepareReceiverKeyProofGeneration({
                linearStatement,
                parameterSet: {
                    ...productionParameterSet,
                    profileId:
                        'receiver-key-linear-module-lwe-compatibility-v1',
                },
                proofEncoding: productionProofEncoding,
                publicRandomnessHex: '00'.repeat(32),
                secretState,
                proverRandomnessHex: '09'.repeat(32),
            });

        expect(compatibilityProfileRejection).toMatchObject({
            ok: false,
            backendAvailable: true,
            operation: 'prepareReceiverKeyProofGeneration',
            unresolvedReason: 'BallotPackageInvalid',
        });
        expect(
            String(compatibilityProfileRejection.refusedObjects[0]?.message),
        ).toContain('production receiver-key parameter profile');
    });
});
