import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import { beforeAll, describe, expect, it } from 'vitest';

import {
    buildBallotProofRecordGenerationRequest,
    type BallotProofRecordGenerationProofContracts,
} from '../../src/ballot-privacy/ballot-proof-linear-statement';

import {
    type BallotProofRecordGenerationFixture,
    cloneJsonValue,
    createBallotProofRecordGenerationFixture,
} from './ballot-privacy-proof-record-generation-fixtures';

const digest = (label: string): string =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        label,
        purpose: 'ballot-proof-record-generation-input-test',
    });

const requireRecord = (
    value: unknown,
    label: string,
): Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${label} should be an object.`);
    }

    return value as Record<string, unknown>;
};

describe('ballot proof record generation input', () => {
    let fixture: BallotProofRecordGenerationFixture;

    beforeAll(() => {
        fixture = createBallotProofRecordGenerationFixture();
    }, 120_000);

    it('assembles a full relation-derived generation request from explicit components', () => {
        const request = fixture.request;

        expect(request.componentBundleStatement.bundleCoverage).toBe(
            'full-encoded-score-ballot-relation',
        );
        expect(request.linearStatement).toMatchObject({
            componentBundleStatementDigest:
                request.componentBundleStatement.componentBundleStatementDigest,
            objectType: 'BallotProofLinearProofStatement',
            parameterProfileId:
                'full-encoded-score-ballot-linear-compatibility-v1',
            projectionCoverage: 'full-encoded-score-ballot-relation',
            relationBindingKind: 'component-bundle-and-lowered-relation',
            statementColumns: 1,
            statementRows: 1,
        });
        expect(request.linearStatement.relationBindingDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(
            request.componentProofInputs.map(
                (proofInput) => proofInput.componentId,
            ),
        ).toEqual([
            'score-and-shamir-field-component',
            'payload-plaintext-field-component',
            'share-commitment-component',
            'receiver-encryption-component',
            'receiver-key-binding-component',
        ]);
        expect(
            request.componentProofInputs.map(
                (proofInput) => proofInput.proofStatementFormat,
            ),
        ).toEqual([
            'dense-polynomial-matrix-linear-proof-v1',
            'sparse-polynomial-matrix-linear-proof-v1',
            'sparse-polynomial-matrix-linear-proof-v1',
            'structured-module-lwe-linear-proof-v1',
            'public-zero-witness-binding-check-v1',
        ]);
        expect(Object.keys(request.componentSecretStates).sort()).toEqual([
            'payload-plaintext-field-component',
            'receiver-encryption-component',
            'score-and-shamir-field-component',
            'share-commitment-component',
        ]);
        const receiverEncryptionInput = request.componentProofInputs.find(
            (proofInput) =>
                proofInput.componentId === 'receiver-encryption-component',
        );
        if (receiverEncryptionInput === undefined) {
            throw new Error('Receiver-encryption input should be present.');
        }
        const receiverEncryptionStatement =
            receiverEncryptionInput.proofStatement as {
                readonly receiverRows: readonly {
                    readonly ciphertextChunkCount: number;
                    readonly plaintextBitLength: number;
                }[];
                readonly sourceBackendColumnIndices: readonly number[];
            };

        expect(receiverEncryptionStatement.receiverRows).toHaveLength(1);
        expect(receiverEncryptionStatement.receiverRows[0]).toMatchObject({
            ciphertextChunkCount: 4,
            plaintextBitLength: 955,
        });
        expect(
            request.componentSecretStates['receiver-encryption-component']
                ?.sourceWitnessCoefficients,
        ).toHaveLength(
            receiverEncryptionStatement.sourceBackendColumnIndices.length,
        );
    });

    it('rejects statement and payload context drift before constructing proof inputs', () => {
        expect(() =>
            buildBallotProofRecordGenerationRequest({
                proofContracts: fixture.proofContracts,
                projectionWitness: fixture.projectionWitness,
                publicContext: {
                    ...fixture.publicContext,
                    ballotProofStatementDigest: digest(
                        'wrong-ballot-proof-statement',
                    ),
                },
                randomness: fixture.randomness,
                relationInput: fixture.relationInput,
                statement: fixture.statement,
            }),
        ).toThrow(/ballot proof statement digest/u);

        expect(() =>
            buildBallotProofRecordGenerationRequest({
                proofContracts: fixture.proofContracts,
                projectionWitness: fixture.projectionWitness,
                publicContext: {
                    ...fixture.publicContext,
                    receiverPayloads:
                        fixture.publicContext.receiverPayloads.map(
                            (receiverPayload) => ({
                                ...receiverPayload,
                                plaintextBitLength:
                                    receiverPayload.plaintextBitLength ===
                                    undefined
                                        ? undefined
                                        : receiverPayload.plaintextBitLength -
                                          1,
                            }),
                        ),
                },
                randomness: fixture.randomness,
                relationInput: fixture.relationInput,
                statement: fixture.statement,
            }),
        ).toThrow(/full encoded-score receiver payload bit length/u);
    });

    it('rejects missing component witnesses and mismatched proof contracts', () => {
        expect(() =>
            buildBallotProofRecordGenerationRequest({
                proofContracts: fixture.proofContracts,
                projectionWitness: {
                    ...fixture.projectionWitness,
                    receiverEncryptionWitnesses: [],
                },
                publicContext: fixture.publicContext,
                randomness: fixture.randomness,
                relationInput: fixture.relationInput,
                statement: fixture.statement,
            }),
        ).toThrow(/Receiver encryption witness is missing/u);

        const receiverEncryptionParameterSet = requireRecord(
            fixture.proofContracts.componentProofParameterSets[
                'receiver-encryption-component'
            ],
            'receiver-encryption parameter set',
        );
        const wrongContracts: BallotProofRecordGenerationProofContracts = {
            ...cloneJsonValue(fixture.proofContracts),
            componentProofParameterSets: {
                ...fixture.proofContracts.componentProofParameterSets,
                'receiver-encryption-component': {
                    ...receiverEncryptionParameterSet,
                    profileId: 'wrong-receiver-encryption-profile',
                },
            },
        };

        expect(() =>
            buildBallotProofRecordGenerationRequest({
                proofContracts: wrongContracts,
                projectionWitness: fixture.projectionWitness,
                publicContext: fixture.publicContext,
                randomness: fixture.randomness,
                relationInput: fixture.relationInput,
                statement: fixture.statement,
            }),
        ).toThrow(/receiver-encryption-component parameter set/u);
    });
});
