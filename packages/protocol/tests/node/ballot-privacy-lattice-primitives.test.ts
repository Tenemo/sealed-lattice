import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type { ProtocolDigest } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    addShareCommitmentOpenings,
    addShareCommitmentPolynomialVectors,
    assertNoFixtureRandomnessInProduction,
    createFixtureRandomnessSource,
    createReceiverKeyProof,
    createShareCommitment,
    encodeReceiverPayloadPlaintextForTests,
    encryptReceiverPayload,
    generateReceiverState,
    verifyReceiverKeyWitness,
    verifyReceiverPayloadWitness,
    verifyShareCommitmentWitness,
    type ReceiverPayloadPlaintextWitness,
    type ShareCommitmentOpeningWitness,
} from '../../src/ballot-privacy/lattice-primitives';
import {
    deriveProofBytesDigest,
    deriveReceiverKeyProofEncodingProfileDigest,
    deriveReceiverKeyProofParameterSetDigest,
    deriveReceiverKeyProofPublicRandomnessDigest,
} from '../../src/ballot-privacy/objects';
import { createBallotPrivacyProfileSet } from '../../src/ballot-privacy/profiles';
import { createReceiverKeyProofBackendStatement } from '../../src/ballot-privacy/receiver-key-backend-statement';
import {
    createReceiverKeyLinearProofStatement,
    verifyReceiverKeyLinearWitness,
} from '../../src/ballot-privacy/receiver-key-linear-statement';
import {
    createReceiverKeyLinearProofEncoding,
    createReceiverKeyLinearProofParameterSet,
    createReceiverKeyProofMaterial,
} from '../../src/ballot-privacy/receiver-key-proof-parameters';

const digest = (label: string): ProtocolDigest =>
    deriveProtocolDigest('ActionContextDigest', { label });

const fixtureRandomness = createFixtureRandomnessSource(
    'ballot-privacy-lattice-primitives',
);

const shareVector = (
    firstShare: number,
    secondShare: number,
): readonly number[] => [
    firstShare,
    secondShare,
    ...Array.from({ length: 218 }, () => 0),
];

const opening = (seed: number): ShareCommitmentOpeningWitness => ({
    openingRandomness: Array.from(
        { length: 64 },
        (_unusedValue, coordinateIndex) => ((seed + coordinateIndex) % 17) - 8,
    ),
});

const createReceiverPlaintext = (
    receiverShareVector: readonly number[],
    shareCommitmentOpening: ShareCommitmentOpeningWitness,
): ReceiverPayloadPlaintextWitness => ({
    ballotPackageContextDigest: digest('ballot-package-context'),
    ceremonyId: 'ceremony-1',
    manifestDigest: digest('manifest'),
    pollSpecDigest: digest('poll-spec'),
    receiverIdentity: 'receiver-1',
    receiverRosterPosition: 1,
    receiverShareVector,
    rosterDigest: digest('roster'),
    shareCommitmentOpening,
    voterIdentityDigest: digest('voter-1'),
});

describe('ballot privacy lattice primitives', () => {
    it('generates deterministic receiver encryption state for fixture inputs', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const firstState = generateReceiverState({
            ceremonyId: 'ceremony-1',
            manifestDigest: digest('manifest'),
            randomnessSource: fixtureRandomness,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            rosterDigest: digest('roster'),
        });
        const secondState = generateReceiverState({
            ceremonyId: 'ceremony-1',
            manifestDigest: digest('manifest'),
            randomnessSource: fixtureRandomness,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            rosterDigest: digest('roster'),
        });
        const changedState = generateReceiverState({
            ceremonyId: 'ceremony-1',
            manifestDigest: digest('manifest'),
            randomnessSource: fixtureRandomness,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: 'receiver-2',
            receiverRosterPosition: 2,
            recoveryEpoch: 0,
            rosterDigest: digest('roster'),
        });

        expect(firstState.receiverPublicKey).toEqual(
            secondState.receiverPublicKey,
        );
        expect(firstState.publicKeyMaterial).toEqual(
            secondState.publicKeyMaterial,
        );
        expect(firstState.secretState).toEqual(secondState.secretState);
        expect(firstState.receiverPublicKey.receiverPublicKeyDigest).not.toBe(
            changedState.receiverPublicKey.receiverPublicKeyDigest,
        );
        expect(firstState.receiverPublicKey).not.toHaveProperty('secretVector');
        expect(firstState.receiverPublicKey).not.toHaveProperty('errorVector');
    });

    it('creates receiver-key proof records only after the key witness relation checks', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const receiverState = generateReceiverState({
            ceremonyId: 'ceremony-1',
            manifestDigest: digest('manifest'),
            randomnessSource: fixtureRandomness,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            rosterDigest: digest('roster'),
        });
        const backendStatement = createReceiverKeyProofBackendStatement({
            publicKeyMaterial: receiverState.publicKeyMaterial,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverPublicKey: receiverState.receiverPublicKey,
        });
        const linearStatement = createReceiverKeyLinearProofStatement({
            publicKeyMaterial: receiverState.publicKeyMaterial,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverPublicKey: receiverState.receiverPublicKey,
        });
        const proofRecord = createReceiverKeyProof({
            publicKeyMaterial: receiverState.publicKeyMaterial,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverPublicKey: receiverState.receiverPublicKey,
            secretState: receiverState.secretState,
        });

        expect(proofRecord).toMatchObject({
            ceremonyId: 'ceremony-1',
            objectType: 'ReceiverKeyProof',
            proofBackend: 'LaZerStyleLocalLatticeRelation',
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
        });
        expect(proofRecord.proofRoot).toMatch(/^[a-f0-9]{128}$/u);
        expect(proofRecord.receiverKeyProofRoot).toMatch(/^[a-f0-9]{128}$/u);
        expect(proofRecord).not.toHaveProperty('secretVector');
        expect(proofRecord).not.toHaveProperty('errorVector');
        expect(backendStatement).toMatchObject({
            backendStatementFormat: 'SparseSignedIntegerBackendStatement-v1',
            columnCount: 2_048,
            digestExpandedRowCount: 1_024,
            explicitRowCount: 0,
            objectType: 'ReceiverKeyProofBackendStatement',
            receiverPublicKeyDigest:
                receiverState.receiverPublicKey.receiverPublicKeyDigest,
            relationLabel: 'ReceiverKeyWellFormednessRelation',
            rowCount: 1_024,
        });
        expect(backendStatement.backendStatementDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(backendStatement.variableColumns).toHaveLength(2_048);
        expect(backendStatement.rowBatches).toHaveLength(1);
        expect(backendStatement.bounds).toHaveLength(2);
        expect(backendStatement).not.toHaveProperty('secretVector');
        expect(backendStatement).not.toHaveProperty('errorVector');
        expect(linearStatement).toMatchObject({
            coefficientModulus: '12289',
            objectType: 'ReceiverKeyLinearProofStatement',
            relation: 'A*w + t = 0',
            ringDegree: 256,
            sourceRing: 'Z_q[X]/(X^256 + 1)',
            statementColumns: 8,
            statementProfileId: 'receiver-key-linear-module-lwe-statement-v1',
            statementRows: 4,
            witnessInfinityNormBound: 2,
            witnessL2BoundSquared: '8192',
        });
        expect(linearStatement.statementMatrixCoefficients).toHaveLength(4);
        expect(linearStatement.statementMatrixCoefficients[0]).toHaveLength(8);
        expect(linearStatement.targetVectorCoefficients).toHaveLength(4);
        expect(linearStatement.statementDigest).toMatch(/^[a-f0-9]{128}$/u);
        expect(linearStatement).not.toHaveProperty('secretVector');
        expect(linearStatement).not.toHaveProperty('errorVector');
        expect(
            verifyReceiverKeyLinearWitness({
                publicKeyMaterial: receiverState.publicKeyMaterial,
                receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
                receiverPublicKey: receiverState.receiverPublicKey,
                secretState: receiverState.secretState,
            }),
        ).toMatchObject({
            ok: true,
            statementDigest: linearStatement.statementDigest,
        });
        expect(
            verifyReceiverKeyWitness({
                publicKeyMaterial: receiverState.publicKeyMaterial,
                receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
                receiverPublicKey: receiverState.receiverPublicKey,
                secretState: receiverState.secretState,
            }),
        ).toEqual([]);

        const changedPublicKeyMaterial = {
            ...receiverState.publicKeyMaterial,
            publicKeyVector:
                receiverState.publicKeyMaterial.publicKeyVector.map(
                    (polynomial, polynomialIndex) =>
                        polynomialIndex === 0
                            ? polynomial.map((coefficient, coefficientIndex) =>
                                  coefficientIndex === 0
                                      ? (coefficient + 1) % 12_289
                                      : coefficient,
                              )
                            : polynomial,
                ),
        };
        expect(
            verifyReceiverKeyWitness({
                publicKeyMaterial: changedPublicKeyMaterial,
                receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
                receiverPublicKey: receiverState.receiverPublicKey,
                secretState: receiverState.secretState,
            }).map((refusal) => refusal.message),
        ).toEqual(
            expect.arrayContaining([
                expect.stringContaining(
                    'public key material does not match the frozen receiver key',
                ),
                expect.stringContaining(
                    'does not satisfy the frozen receiver-key equation',
                ),
            ]),
        );
        expect(() =>
            createReceiverKeyProof({
                publicKeyMaterial: changedPublicKeyMaterial,
                receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
                receiverPublicKey: receiverState.receiverPublicKey,
                secretState: receiverState.secretState,
            }),
        ).toThrow(/receiver-key equation/u);
        expect(() =>
            createReceiverKeyLinearProofStatement({
                publicKeyMaterial: changedPublicKeyMaterial,
                receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
                receiverPublicKey: receiverState.receiverPublicKey,
            }),
        ).toThrow(/public key material/u);
    });

    it('binds supplied receiver-key proof material into the generated proof record', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const receiverState = generateReceiverState({
            ceremonyId: 'ceremony-1',
            manifestDigest: digest('manifest'),
            randomnessSource: fixtureRandomness,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            rosterDigest: digest('roster'),
        });
        const proofBytesHex = '001122aabbcc';
        const publicRandomnessHex = '00'.repeat(32);
        const proofMaterial = createReceiverKeyProofMaterial({
            proofBytesHex,
            publicRandomnessHex,
        });
        const { proofEncoding, proofParameterSet } = proofMaterial;
        const backendStatement = createReceiverKeyProofBackendStatement({
            publicKeyMaterial: receiverState.publicKeyMaterial,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverPublicKey: receiverState.receiverPublicKey,
        });
        const linearStatement = createReceiverKeyLinearProofStatement({
            publicKeyMaterial: receiverState.publicKeyMaterial,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverPublicKey: receiverState.receiverPublicKey,
        });
        const proofRecord = createReceiverKeyProof({
            proofMaterial,
            publicKeyMaterial: receiverState.publicKeyMaterial,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverPublicKey: receiverState.receiverPublicKey,
            secretState: receiverState.secretState,
        });
        const proofBytesDigest = deriveProofBytesDigest({ proofBytesHex });
        const proofEncodingProfileDigest =
            deriveReceiverKeyProofEncodingProfileDigest({ proofEncoding });
        const proofParameterSetDigest =
            deriveReceiverKeyProofParameterSetDigest({
                parameterSet: proofParameterSet,
            });
        const publicRandomnessDigest =
            deriveReceiverKeyProofPublicRandomnessDigest({
                publicRandomnessHex,
            });

        expect(proofRecord).toMatchObject({
            backendStatementDigest: backendStatement.backendStatementDigest,
            linearStatementDigest: linearStatement.statementDigest,
            proofBytesDigest,
            proofEncodingProfileDigest,
            proofParameterSetDigest,
            proofSizeBytes: proofBytesHex.length / 2,
            publicRandomnessDigest,
        });
        expect(proofRecord.proofRoot).toBe(
            deriveProtocolDigest('ReceiverKeyProofRoot', {
                linearStatementDigest: linearStatement.statementDigest,
                proofBytesDigest,
                proofEncodingProfileDigest,
                proofParameterSetDigest,
                publicRandomnessDigest,
                purpose: 'receiver-key-linear-proof-record-root-v1',
            }),
        );
        expect(() =>
            createReceiverKeyProof({
                proofMaterial: {
                    proofBytesHex: '001122AABBCC',
                    proofEncoding,
                    proofParameterSet,
                    publicRandomnessHex,
                },
                publicKeyMaterial: receiverState.publicKeyMaterial,
                receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
                receiverPublicKey: receiverState.receiverPublicKey,
                secretState: receiverState.secretState,
            }),
        ).toThrow(/lowercase hexadecimal/u);
        expect(() =>
            createReceiverKeyProof({
                proofMaterial: {
                    ...proofMaterial,
                    proofEncoding: createReceiverKeyLinearProofEncoding(),
                },
                publicKeyMaterial: receiverState.publicKeyMaterial,
                receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
                receiverPublicKey: receiverState.receiverPublicKey,
                secretState: receiverState.secretState,
            }),
        ).toThrow(/proof encoding contract/u);
        expect(() =>
            createReceiverKeyProof({
                proofMaterial: {
                    ...proofMaterial,
                    proofParameterSet: createReceiverKeyLinearProofParameterSet(
                        {
                            expectedProofSizeBytes:
                                proofBytesHex.length / 2 + 1,
                        },
                    ),
                },
                publicKeyMaterial: receiverState.publicKeyMaterial,
                receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
                receiverPublicKey: receiverState.receiverPublicKey,
                secretState: receiverState.secretState,
            }),
        ).toThrow(/proof parameter contract/u);
    });

    it('computes additively homomorphic share commitments', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const firstOpening = opening(1);
        const secondOpening = opening(9);
        const firstCommitment = createShareCommitment({
            ceremonyId: 'ceremony-1',
            manifestDigest: digest('manifest'),
            opening: firstOpening,
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            receiverShareVector: shareVector(5, 7),
            rosterDigest: digest('roster'),
            shareCommitmentProfile: profileSet.shareCommitmentProfile,
        });
        const secondCommitment = createShareCommitment({
            ceremonyId: 'ceremony-1',
            manifestDigest: digest('manifest'),
            opening: secondOpening,
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            receiverShareVector: shareVector(11, 13),
            rosterDigest: digest('roster'),
            shareCommitmentProfile: profileSet.shareCommitmentProfile,
        });
        const summedCommitment = createShareCommitment({
            ceremonyId: 'ceremony-1',
            manifestDigest: digest('manifest'),
            opening: addShareCommitmentOpenings(firstOpening, secondOpening),
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            receiverShareVector: shareVector(16, 20),
            rosterDigest: digest('roster'),
            shareCommitmentProfile: profileSet.shareCommitmentProfile,
        });

        expect(
            addShareCommitmentPolynomialVectors(
                firstCommitment.commitmentPolynomialVector,
                secondCommitment.commitmentPolynomialVector,
            ),
        ).toEqual(summedCommitment.commitmentPolynomialVector);
        expect(firstCommitment.shareCommitment).not.toHaveProperty(
            'openingRandomness',
        );
        expect(
            verifyShareCommitmentWitness({
                ceremonyId: 'ceremony-1',
                expectedCommitmentPolynomialVector:
                    firstCommitment.commitmentPolynomialVector,
                expectedShareCommitment: firstCommitment.shareCommitment,
                manifestDigest: digest('manifest'),
                opening: firstOpening,
                receiverIdentity: 'receiver-1',
                receiverRosterPosition: 1,
                receiverShareVector: shareVector(5, 7),
                rosterDigest: digest('roster'),
                shareCommitmentProfile: profileSet.shareCommitmentProfile,
            }),
        ).toEqual([]);
        expect(
            verifyShareCommitmentWitness({
                ceremonyId: 'ceremony-1',
                expectedCommitmentPolynomialVector:
                    firstCommitment.commitmentPolynomialVector,
                expectedShareCommitment: firstCommitment.shareCommitment,
                manifestDigest: digest('manifest'),
                opening: opening(2),
                receiverIdentity: 'receiver-1',
                receiverRosterPosition: 1,
                receiverShareVector: shareVector(5, 7),
                rosterDigest: digest('roster'),
                shareCommitmentProfile: profileSet.shareCommitmentProfile,
            }).map((refusal) => refusal.code),
        ).toContain('BallotPackageInvalid');
    });

    it('encrypts receiver payload plaintext with per-chunk randomness and context binding', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const receiverState = generateReceiverState({
            ceremonyId: 'ceremony-1',
            manifestDigest: digest('manifest'),
            randomnessSource: fixtureRandomness,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            rosterDigest: digest('roster'),
        });
        const plaintext = createReceiverPlaintext(
            shareVector(21, 34),
            opening(4),
        );
        const encryptedPayload = encryptReceiverPayload({
            plaintext,
            publicKeyMaterial: receiverState.publicKeyMaterial,
            randomnessSource: fixtureRandomness,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverPublicKey: receiverState.receiverPublicKey,
            shareCommitmentProfile: profileSet.shareCommitmentProfile,
        });
        const changedPlaintext = {
            ...plaintext,
            shareCommitmentOpening: opening(5),
        };
        const changedPayload = encryptReceiverPayload({
            plaintext: changedPlaintext,
            publicKeyMaterial: receiverState.publicKeyMaterial,
            randomnessSource: fixtureRandomness,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverPublicKey: receiverState.receiverPublicKey,
            shareCommitmentProfile: profileSet.shareCommitmentProfile,
        });

        expect(encryptedPayload.ciphertextChunks.length).toBeGreaterThan(1);
        expect(encryptedPayload.witness.chunkWitnesses).toHaveLength(
            encryptedPayload.ciphertextChunks.length,
        );
        expect(
            encryptedPayload.witness.chunkWitnesses[0]
                ?.encryptionRandomnessVector,
        ).not.toEqual(
            encryptedPayload.witness.chunkWitnesses[1]
                ?.encryptionRandomnessVector,
        );
        expect(encryptedPayload.receiverPayload).not.toHaveProperty(
            'receiverShareVector',
        );
        expect(encryptedPayload.receiverPayload).not.toHaveProperty(
            'shareCommitmentOpening',
        );
        expect(encryptedPayload.receiverPayload.receiverPayloadDigest).not.toBe(
            changedPayload.receiverPayload.receiverPayloadDigest,
        );
        expect(
            encodeReceiverPayloadPlaintextForTests({
                plaintext,
                shareCommitmentProfile: profileSet.shareCommitmentProfile,
            }),
        ).toMatch(/^[0-1]+$/u);
        expect(
            verifyReceiverPayloadWitness({
                expectedCiphertextChunks: encryptedPayload.ciphertextChunks,
                expectedReceiverPayload: encryptedPayload.receiverPayload,
                plaintext,
                publicKeyMaterial: receiverState.publicKeyMaterial,
                receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
                receiverPublicKey: receiverState.receiverPublicKey,
                shareCommitmentProfile: profileSet.shareCommitmentProfile,
                witness: encryptedPayload.witness,
            }),
        ).toEqual([]);
        expect(
            verifyReceiverPayloadWitness({
                expectedCiphertextChunks: encryptedPayload.ciphertextChunks,
                expectedReceiverPayload: encryptedPayload.receiverPayload,
                plaintext: changedPlaintext,
                publicKeyMaterial: receiverState.publicKeyMaterial,
                receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
                receiverPublicKey: receiverState.receiverPublicKey,
                shareCommitmentProfile: profileSet.shareCommitmentProfile,
                witness: encryptedPayload.witness,
            }).map((refusal) => refusal.code),
        ).toContain('BallotPackageInvalid');
    });

    it('rejects fixture randomness outside explicit test construction and mismatched receiver keys', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const receiverState = generateReceiverState({
            ceremonyId: 'ceremony-1',
            manifestDigest: digest('manifest'),
            randomnessSource: fixtureRandomness,
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            recoveryEpoch: 0,
            rosterDigest: digest('roster'),
        });

        expect(() =>
            assertNoFixtureRandomnessInProduction(fixtureRandomness),
        ).toThrow(/fixture randomness/u);
        expect(() =>
            encryptReceiverPayload({
                plaintext: {
                    ...createReceiverPlaintext(shareVector(1, 2), opening(3)),
                    receiverRosterPosition: 2,
                },
                publicKeyMaterial: receiverState.publicKeyMaterial,
                randomnessSource: fixtureRandomness,
                receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
                receiverPublicKey: receiverState.receiverPublicKey,
                shareCommitmentProfile: profileSet.shareCommitmentProfile,
            }),
        ).toThrow(/frozen receiver key/u);
    });
});
