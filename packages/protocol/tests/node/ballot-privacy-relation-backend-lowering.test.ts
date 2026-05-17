import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    buildBallotProofComponentBundleStatement,
    buildBallotProofComponentLinearProofProjection,
    buildBallotProofComponentProofStatementPlans,
    buildBallotProofSparseComponentLinearProofStatement,
    buildEncodedScoreFieldLinearProofProjection,
    verifyBallotProofComponentExplicitRows,
    type BallotProofComponentProjectionWitness,
    type BallotProofSparseComponentLinearProofStatement,
} from '../../src/ballot-privacy/ballot-proof-linear-statement';
import {
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    type BallotPrivacyRelationCompilerInput,
} from '../../src/ballot-privacy/index';
import {
    createFixtureRandomnessSource,
    createShareCommitmentPolynomialVector,
    deriveShareCommitmentBodyDigest,
    generateReceiverState,
} from '../../src/ballot-privacy/lattice-primitives';
import {
    ballotPrivacyBackendProofComponentOrder,
    lowerBallotPrivacyRelationToBackendStatement,
    type BallotPrivacyRelationBackendPublicContext,
} from '../../src/ballot-privacy/relation-backend-lowering';

const digest = (label: string): string =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        label,
        purpose: 'ballot-privacy-relation-lowering-test',
    });
const shareCommitmentModulus = 18_446_744_069_414_584_321n;

const oneHotScore = (score: number): readonly number[] =>
    Array.from({ length: 10 }, (_unusedValue, scoreIndex) =>
        scoreIndex + 1 === score ? 1 : 0,
    );

const encodedShareVector = (input: {
    readonly firstOptionScoreShare: number;
    readonly secondOptionScoreShare: number;
}): readonly number[] => [
    input.firstOptionScoreShare,
    ...oneHotScore(7),
    input.secondOptionScoreShare,
    ...oneHotScore(3),
];

const encodedCoordinateShamirCoefficients =
    (): readonly (readonly number[])[] => [
        [65_536],
        ...Array.from({ length: 10 }, () => [0] as const),
        [9],
        ...Array.from({ length: 10 }, () => [0] as const),
    ];

type BackendProofComponentView = {
    readonly componentDigest: string;
    readonly componentId: string;
    readonly rowBatchNames: readonly string[];
    readonly variableColumnIndices: readonly number[];
};

const validRelationInput = (): BallotPrivacyRelationCompilerInput => ({
    encodedCoordinateShamirCoefficients: encodedCoordinateShamirCoefficients(),
    normalizedScores: [7, 3],
    optionCount: 2,
    pvssThreshold: 2,
    receivers: [
        {
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            receiverShareVector: encodedShareVector({
                firstOptionScoreShare: 6,
                secondOptionScoreShare: 12,
            }),
        },
        {
            receiverIdentity: 'receiver-2',
            receiverRosterPosition: 2,
            receiverShareVector: encodedShareVector({
                firstOptionScoreShare: 5,
                secondOptionScoreShare: 21,
            }),
        },
        {
            receiverIdentity: 'receiver-3',
            receiverRosterPosition: 3,
            receiverShareVector: encodedShareVector({
                firstOptionScoreShare: 4,
                secondOptionScoreShare: 30,
            }),
        },
    ],
    rosterSize: 3,
    scoreOneHotWitnesses: [oneHotScore(7), oneHotScore(3)],
});

const singleOptionRelationInput = (): BallotPrivacyRelationCompilerInput => ({
    encodedCoordinateShamirCoefficients: [
        [2],
        ...Array.from({ length: 10 }, () => [0] as const),
    ],
    normalizedScores: [5],
    optionCount: 1,
    pvssThreshold: 2,
    receivers: [1, 2, 3].map((receiverRosterPosition) => ({
        receiverIdentity: `receiver-${receiverRosterPosition}`,
        receiverRosterPosition,
        receiverShareVector: [
            5 + 2 * receiverRosterPosition,
            ...oneHotScore(5),
        ],
    })),
    rosterSize: 3,
    scoreOneHotWitnesses: [oneHotScore(5)],
});

const shareCommitmentOpeningForReceiver = (
    receiverRosterPosition: number,
): readonly number[] =>
    Array.from(
        { length: 64 },
        (_unusedValue, openingCoordinateIndex) =>
            ((receiverRosterPosition + openingCoordinateIndex) % 5) - 2,
    );

const receiverEncryptionModuleRank = 4;
const receiverEncryptionModuleDegree = 256;
const receiverEncryptionModulus = 12_289;
const receiverEncryptionMessageScale = Math.floor(
    receiverEncryptionModulus / 2,
);
const receiverShareRepresentativeBitLength = 17;
const receiverOpeningRandomnessBitLength = 12;
const receiverOpeningEncodingOffset = 1_024;

const unsignedBits = (value: number, bitLength: number): readonly number[] =>
    Array.from(
        { length: bitLength },
        (_unusedValue, bitIndex) => (value >> bitIndex) & 1,
    );

const receiverPayloadPlaintextBitsForTest = (input: {
    readonly openingRandomness: readonly number[];
    readonly receiverShareVector: readonly number[];
}): readonly number[] => [
    ...input.receiverShareVector.flatMap((shareRepresentative) =>
        unsignedBits(shareRepresentative, receiverShareRepresentativeBitLength),
    ),
    ...input.openingRandomness.flatMap((openingCoordinate) =>
        unsignedBits(
            openingCoordinate + receiverOpeningEncodingOffset,
            receiverOpeningRandomnessBitLength,
        ),
    ),
];

const zeroReceiverEncryptionVector = (): readonly (readonly number[])[] =>
    Array.from({ length: receiverEncryptionModuleRank }, () =>
        Array.from({ length: receiverEncryptionModuleDegree }, () => 0),
    );

const zeroReceiverEncryptionPolynomial = (): readonly number[] =>
    Array.from({ length: receiverEncryptionModuleDegree }, () => 0);

const deterministicReceiverPayloadCiphertextForTest = (input: {
    readonly plaintextBits: readonly number[];
    readonly receiverEncryptionProfileDigest: string;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
}): {
    readonly ciphertextBodyDigest: string;
    readonly ciphertextChunkDigest: string;
    readonly ciphertextChunks: readonly {
        readonly chunkIndex: number;
        readonly firstCiphertextVector: readonly (readonly number[])[];
        readonly secondCiphertextPolynomial: readonly number[];
    }[];
    readonly plaintextBitLength: number;
    readonly receiverPayloadCiphertextRoot: string;
    readonly receiverPayloadDigest: string;
    readonly witness: NonNullable<
        BallotProofComponentProjectionWitness['receiverEncryptionWitnesses']
    >[number];
} => {
    const chunkCount = Math.ceil(
        input.plaintextBits.length / receiverEncryptionModuleDegree,
    );
    const ciphertextChunks = Array.from(
        { length: chunkCount },
        (_unusedValue, chunkIndex) => ({
            chunkIndex,
            firstCiphertextVector: zeroReceiverEncryptionVector(),
            secondCiphertextPolynomial: Array.from(
                { length: receiverEncryptionModuleDegree },
                (_unusedCoefficient, coefficientIndex) =>
                    input.plaintextBits[
                        chunkIndex * receiverEncryptionModuleDegree +
                            coefficientIndex
                    ] === 1
                        ? receiverEncryptionMessageScale
                        : 0,
            ),
        }),
    );
    const ciphertextBodyDigest = deriveProtocolDigest(
        'ReceiverPayloadCiphertextRoot',
        {
            ciphertextChunks,
            plaintextBitLength: input.plaintextBits.length,
            receiverEncryptionProfileDigest:
                input.receiverEncryptionProfileDigest,
        },
    );
    const receiverPayloadCiphertextRoot = deriveProtocolDigest(
        'ReceiverPayloadCiphertextRoot',
        {
            ciphertextBodyDigest,
            receiverIdentity: input.receiverIdentity,
            receiverRosterPosition: input.receiverRosterPosition,
        },
    );
    const receiverPayloadDigest = deriveProtocolDigest(
        'ReceiverPayloadDigest',
        {
            receiverPayloadCiphertextRoot,
            receiverIdentity: input.receiverIdentity,
            receiverRosterPosition: input.receiverRosterPosition,
        },
    );

    return {
        ciphertextBodyDigest,
        ciphertextChunkDigest: deriveProtocolDigest('ChallengeDomainDigest', {
            ciphertextChunks,
            plaintextBitLength: input.plaintextBits.length,
            purpose: 'ballot-privacy-test-receiver-ciphertext-chunks',
        }),
        ciphertextChunks,
        plaintextBitLength: input.plaintextBits.length,
        receiverPayloadCiphertextRoot,
        receiverPayloadDigest,
        witness: {
            chunkWitnesses: ciphertextChunks.map((ciphertextChunk) => ({
                chunkIndex: ciphertextChunk.chunkIndex,
                encryptionRandomnessVector: zeroReceiverEncryptionVector(),
                firstNoiseVector: zeroReceiverEncryptionVector(),
                secondNoisePolynomial: zeroReceiverEncryptionPolynomial(),
            })),
            receiverRosterPosition: input.receiverRosterPosition,
        },
    };
};

const projectionWitness = (
    relationInput: BallotPrivacyRelationCompilerInput = validRelationInput(),
): BallotProofComponentProjectionWitness => ({
    receiverPayloadPlaintexts: relationInput.receivers.map((receiver) => ({
        openingRandomness: shareCommitmentOpeningForReceiver(
            receiver.receiverRosterPosition,
        ),
        receiverRosterPosition: receiver.receiverRosterPosition,
        receiverShareVector: receiver.receiverShareVector,
    })),
    shareCommitmentOpenings: relationInput.receivers.map((receiver) => ({
        openingRandomness: shareCommitmentOpeningForReceiver(
            receiver.receiverRosterPosition,
        ),
        receiverRosterPosition: receiver.receiverRosterPosition,
    })),
});

const publicContext = (
    relationInput: BallotPrivacyRelationCompilerInput = validRelationInput(),
): BallotPrivacyRelationBackendPublicContext => {
    const profileSet = createBallotPrivacyProfileSet();
    const certificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const receiverReferences = relationInput.receivers.map((receiver) => ({
        receiverIdentity: receiver.receiverIdentity,
        receiverRosterPosition: receiver.receiverRosterPosition,
    }));

    return {
        actionContextDigest: digest('action-context'),
        aggregateInputEncodingProfileDigest:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileDigest,
        ballotProofProfileDigest:
            profileSet.ballotProofProfile.ballotProofProfileDigest,
        ballotProofStatementDigest: digest('ballot-proof-statement'),
        ballotScoreEncodingProfileDigest:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileDigest,
        ballotShareLayoutProfileDigest:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileDigest,
        ceremonyId: 'ceremony-relation-lowering',
        encodedAggregateLayoutDigest:
            profileSet.encodedAggregateLayoutProfile
                .encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutDigest,
        manifestDigest: digest('manifest'),
        pollSpecDigest: digest('poll-spec'),
        receiverEncryptionProfileDigest:
            profileSet.receiverEncryptionProfile
                .receiverEncryptionProfileDigest,
        receiverKeyProofRoot: digest('receiver-key-proof-root'),
        receiverKeyRoot: digest('receiver-key-root'),
        receiverPayloads: receiverReferences.map((receiverReference) => ({
            ...receiverReference,
            receiverPayloadCiphertextRoot: digest(
                `receiver-payload-ciphertext-root-${receiverReference.receiverRosterPosition}`,
            ),
            receiverPayloadDigest: digest(
                `receiver-payload-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        receiverPublicKeys: receiverReferences.map((receiverReference) => ({
            ...receiverReference,
            receiverPublicKeyDigest: digest(
                `receiver-public-key-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        rosterDigest: digest('roster'),
        rosterExternalAcceptanceDigest: digest('external-acceptance'),
        scoreMembershipProfileDigest:
            profileSet.scoreMembershipProfile.scoreMembershipProfileDigest,
        shareCommitmentMessageBoundCertDigest:
            certificate.shareCommitmentMessageBoundCertDigest,
        shareCommitmentProfileDigest:
            profileSet.shareCommitmentProfile.shareCommitmentProfileDigest,
        shareCommitments: relationInput.receivers.map((receiver) => {
            const commitmentPolynomialVector =
                createShareCommitmentPolynomialVector({
                    opening: {
                        openingRandomness: shareCommitmentOpeningForReceiver(
                            receiver.receiverRosterPosition,
                        ),
                    },
                    receiverShareVector: receiver.receiverShareVector,
                    shareCommitmentProfile: profileSet.shareCommitmentProfile,
                    shareVectorWidth: relationInput.optionCount * 11,
                });
            const commitmentBodyDigest = deriveShareCommitmentBodyDigest({
                commitmentPolynomialVector,
                shareCommitmentProfileDigest:
                    profileSet.shareCommitmentProfile
                        .shareCommitmentProfileDigest,
            });

            return {
                commitmentBodyDigest,
                commitmentPolynomialVector,
                commitmentPolynomialVectorDigest: deriveProtocolDigest(
                    'ChallengeDomainDigest',
                    {
                        commitmentPolynomialVector,
                        purpose:
                            'ballot-privacy-test-share-commitment-polynomial-vector',
                    },
                ),
                receiverIdentity: receiver.receiverIdentity,
                receiverRosterPosition: receiver.receiverRosterPosition,
                shareCommitmentDigest: digest(
                    `share-commitment-${receiver.receiverRosterPosition}`,
                ),
            };
        }),
    };
};

const explicitReceiverEncryptionFixture = (
    relationInput: BallotPrivacyRelationCompilerInput = singleOptionRelationInput(),
): {
    readonly context: BallotPrivacyRelationBackendPublicContext;
    readonly projectionWitness: BallotProofComponentProjectionWitness;
} => {
    const profileSet = createBallotPrivacyProfileSet();
    const context = publicContext(relationInput);
    const encryptedReceiverRecords = relationInput.receivers.map((receiver) => {
        const receiverState = generateReceiverState({
            ceremonyId: context.ceremonyId,
            manifestDigest: context.manifestDigest,
            randomnessSource: createFixtureRandomnessSource(
                `receiver-key-${receiver.receiverRosterPosition}`,
            ),
            receiverEncryptionProfile: profileSet.receiverEncryptionProfile,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition: receiver.receiverRosterPosition,
            recoveryEpoch: 0,
            rosterDigest: context.rosterDigest,
        });
        const encryptedPayload = deterministicReceiverPayloadCiphertextForTest({
            plaintextBits: receiverPayloadPlaintextBitsForTest({
                openingRandomness: shareCommitmentOpeningForReceiver(
                    receiver.receiverRosterPosition,
                ),
                receiverShareVector: receiver.receiverShareVector,
            }),
            receiverEncryptionProfileDigest:
                profileSet.receiverEncryptionProfile
                    .receiverEncryptionProfileDigest,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition: receiver.receiverRosterPosition,
        });

        return {
            encryptedPayload,
            receiver,
            receiverState,
        };
    });

    return {
        context: {
            ...context,
            receiverPayloads: encryptedReceiverRecords.map(
                ({ encryptedPayload, receiver }) => ({
                    ciphertextBodyDigest: encryptedPayload.ciphertextBodyDigest,
                    ciphertextChunkCount:
                        encryptedPayload.ciphertextChunks.length,
                    ciphertextChunkDigest:
                        encryptedPayload.ciphertextChunkDigest,
                    ciphertextChunks: encryptedPayload.ciphertextChunks,
                    plaintextBitLength: encryptedPayload.plaintextBitLength,
                    receiverIdentity: receiver.receiverIdentity,
                    receiverPayloadCiphertextRoot:
                        encryptedPayload.receiverPayloadCiphertextRoot,
                    receiverPayloadDigest:
                        encryptedPayload.receiverPayloadDigest,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                }),
            ),
            receiverPublicKeys: encryptedReceiverRecords.map(
                ({ receiver, receiverState }) => ({
                    keyMaterialDigest:
                        receiverState.receiverPublicKey.keyMaterialDigest,
                    publicKeyVector:
                        receiverState.publicKeyMaterial.publicKeyVector,
                    publicMatrixSeedDigest:
                        receiverState.publicKeyMaterial.publicMatrixSeedDigest,
                    receiverIdentity: receiver.receiverIdentity,
                    receiverPublicKeyDigest:
                        receiverState.receiverPublicKey.receiverPublicKeyDigest,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                }),
            ),
        },
        projectionWitness: {
            ...projectionWitness(relationInput),
            receiverEncryptionWitnesses: encryptedReceiverRecords.map(
                ({ encryptedPayload, receiver }) => ({
                    chunkWitnesses: encryptedPayload.witness.chunkWitnesses,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                }),
            ),
        },
    };
};

describe('ballot privacy relation backend lowering', () => {
    it('lowers encoded score constraints into sparse backend rows without witness values', () => {
        const result = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: publicContext(),
            relationInput: validRelationInput(),
        });

        expect(result.ok).toBe(true);
        if (!result.ok) {
            throw new Error('valid relation input should lower');
        }

        expect(result.statement).toMatchObject({
            encodedCoordinateCount: 22,
            fieldModulus: 65_537,
            optionCount: 2,
            pvssThreshold: 2,
            relationLabel: 'BallotPrivacyPvssRelation',
            relationStatementFormat:
                'SparseIntegerRowsModuloGF65537WithBoundGadgets-v1',
            rosterSize: 3,
            shareVectorWidth: 22,
        });
        expect(result.statement.relationStatementDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(result.statement.linearRows).toHaveLength(
            2 * 2 + 3 * 22 + 3 * (22 + 64),
        );
        expect(result.statement.algebraicRows).toHaveLength(3 * 3);
        expect(result.statement.variables).toHaveLength(
            22 + 22 + 3 * 22 * 2 + 3 * (22 + 64 + 64 + 2),
        );
        expect(result.statement.backendStatement).toMatchObject({
            backendStatementFormat: 'SparseSignedIntegerBackendStatement-v1',
            columnCount: 632,
            digestExpandedRowCount: 3 * (1_280 + 1_024),
            explicitRowCount: 70 + 3 * (22 + 64) + 3 * 1_024,
            objectType: 'BallotPrivacyProofBackendStatement',
            rowCount: 70 + 3 * (1_024 + 86 + 1_280 + 1_024),
        });
        expect(result.statement.backendStatement.proofComponents).toHaveLength(
            5,
        );
        const proofComponents = result.statement.backendStatement
            .proofComponents as unknown as readonly BackendProofComponentView[];
        expect(
            proofComponents.map((component) => component.componentId),
        ).toEqual([
            'score-and-shamir-field-component',
            'payload-plaintext-field-component',
            'share-commitment-component',
            'receiver-encryption-component',
            'receiver-key-binding-component',
        ]);
        expect(result.statement.backendStatement.proofComponents).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    coefficientModulus: '65537',
                    componentId: 'score-and-shamir-field-component',
                    proofLoweringStatus: 'explicitRowsAvailable',
                    rowCount: 70,
                    rowKinds: ['EncodedScoreFieldRows'],
                    variableColumnCount: 176,
                }),
                expect.objectContaining({
                    coefficientModulus: '65537',
                    componentId: 'payload-plaintext-field-component',
                    proofLoweringStatus: 'explicitRowsAvailable',
                    rowCount: 3 * 86,
                    rowKinds: ['ReceiverPayloadPlaintextBindingRows'],
                    variableColumnCount: 516,
                }),
                expect.objectContaining({
                    coefficientModulus: '18446744069414584321',
                    componentId: 'share-commitment-component',
                    proofLoweringStatus: 'explicitRowsAvailable',
                    rowCount: 3 * 1_024,
                    rowKinds: ['ShareCommitmentEquationRows'],
                    variableColumnCount: 258,
                }),
                expect.objectContaining({
                    coefficientModulus: '12289',
                    componentId: 'receiver-encryption-component',
                    proofLoweringStatus: 'digestExpandedRowsPending',
                    rowCount: 3 * 1_280,
                    rowKinds: ['ReceiverPayloadEncryptionEquation'],
                }),
                expect.objectContaining({
                    coefficientModulus: '12289',
                    componentId: 'receiver-key-binding-component',
                    proofLoweringStatus: 'digestExpandedRowsPending',
                    rowCount: 3 * 1_024,
                    rowKinds: ['ReceiverKeyBinding'],
                    variableColumnCount: 0,
                }),
            ]),
        );
        for (const proofComponent of proofComponents) {
            expect(proofComponent.componentDigest).toMatch(/^[a-f0-9]{128}$/u);
            expect(proofComponent.rowBatchNames.length).toBeGreaterThan(0);
            expect(proofComponent.variableColumnIndices).toEqual(
                [...proofComponent.variableColumnIndices].sort(
                    (leftColumnIndex, rightColumnIndex) =>
                        leftColumnIndex - rightColumnIndex,
                ),
            );
        }
        expect(result.statement.backendStatement.proofComponentsDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(
            result.statement.backendStatement.backendStatementDigest,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(result.statement.backendStatement.rowBatches).toHaveLength(9);
        expect(result.statement.backendStatement.rowBatches[0]).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            batchName: 'encoded_score_field_rows',
            rowCount: 70,
            rowOffset: 0,
        });
        expect(result.statement.backendStatement.rowBatches[1]).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            batchName: 'receiver_payload_plaintext_binding_rows',
            rowCount: 258,
            rowOffset: 70,
            rowKind: 'ReceiverPayloadPlaintextBindingRows',
        });
        expect(result.statement.backendStatement.rowBatches[2]).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            batchName: 'share_commitment_equation_rows',
            rowCount: 3_072,
            rowOffset: 328,
            rowKind: 'ShareCommitmentEquationRows',
        });
        const explicitShareCommitmentRowBatch =
            result.statement.backendStatement.rowBatches[2];
        if (
            explicitShareCommitmentRowBatch?.batchKind !== 'ExplicitSparseRows'
        ) {
            throw new Error('Expected share commitment rows to be explicit.');
        }
        const firstShareCommitmentEquationRow =
            explicitShareCommitmentRowBatch.rows.find(
                (row) =>
                    row.rowName ===
                    'receiver_1_share_commitment_vector_0_coefficient_0_equation',
            );
        if (firstShareCommitmentEquationRow === undefined) {
            throw new Error('Missing first share commitment equation row.');
        }
        const firstReceiver = validRelationInput().receivers[0];
        const validWitnessValues = new Map<string, bigint>();
        firstReceiver?.receiverShareVector.forEach(
            (shareRepresentative, encodedCoordinateIndex) => {
                validWitnessValues.set(
                    `receiver_1_encoded_coordinate_${encodedCoordinateIndex}_share`,
                    BigInt(shareRepresentative),
                );
            },
        );
        shareCommitmentOpeningForReceiver(1).forEach(
            (openingCoordinate, openingCoordinateIndex) => {
                validWitnessValues.set(
                    `receiver_1_share_commitment_opening_coordinate_${openingCoordinateIndex}`,
                    BigInt(openingCoordinate),
                );
            },
        );
        const evaluateShareCommitmentRow = (
            witnessValues: ReadonlyMap<string, bigint>,
        ): bigint =>
            firstShareCommitmentEquationRow.terms.reduce(
                (accumulatedValue, term) =>
                    (accumulatedValue +
                        BigInt(term.coefficient) *
                            (witnessValues.get(term.variableName) ?? 0n)) %
                    shareCommitmentModulus,
                0n,
            );
        expect(
            (evaluateShareCommitmentRow(validWitnessValues) +
                shareCommitmentModulus) %
                shareCommitmentModulus,
        ).toBe(BigInt(firstShareCommitmentEquationRow.target));
        const wrongOpeningWitnessValues = new Map(validWitnessValues);
        wrongOpeningWitnessValues.set(
            'receiver_1_share_commitment_opening_coordinate_0',
            (wrongOpeningWitnessValues.get(
                'receiver_1_share_commitment_opening_coordinate_0',
            ) ?? 0n) + 1n,
        );
        expect(
            (evaluateShareCommitmentRow(wrongOpeningWitnessValues) +
                shareCommitmentModulus) %
                shareCommitmentModulus,
        ).not.toBe(BigInt(firstShareCommitmentEquationRow.target));
        expect(
            result.statement.backendStatement.rowBatches[
                result.statement.backendStatement.rowBatches.length - 1
            ],
        ).toMatchObject({
            batchKind: 'DigestExpandedRows',
            rowCount: 1_024,
            rowKind: 'ReceiverKeyBinding',
        });
        expect(
            result.statement.backendStatement.rowBatches[0]?.matrixDigest,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(
            result.statement.backendStatement.rowBatches[0]?.targetVectorDigest,
        ).toMatch(/^[a-f0-9]{128}$/u);
        const explicitBackendRowBatch =
            result.statement.backendStatement.rowBatches[0];
        if (explicitBackendRowBatch?.batchKind !== 'ExplicitSparseRows') {
            throw new Error('Expected the first backend batch to be explicit.');
        }

        expect(explicitBackendRowBatch.rows[4]).toMatchObject({
            rowKind: 'ShamirEvaluationQuotient',
            target: '0',
            terms: [
                {
                    coefficient: '1',
                    variableName: 'option_1_scalar_constant',
                },
                {
                    coefficient: '1',
                    variableName: 'encoded_coordinate_0_coefficient_degree_1',
                },
                {
                    coefficient: '-1',
                    variableName: 'receiver_1_encoded_coordinate_0_share',
                },
                {
                    coefficient: '-65537',
                    variableName: 'receiver_1_encoded_coordinate_0_quotient',
                },
            ],
        });
        const shareCommitmentOpeningBackendBound =
            result.statement.backendStatement.bounds.find(
                (bound) =>
                    bound.boundName ===
                    'share_commitment_openings_certified_absolute_bound',
            );
        expect(shareCommitmentOpeningBackendBound).toMatchObject({
            absoluteMaximum: '1024',
        });
        expect(shareCommitmentOpeningBackendBound?.variableNames).toEqual(
            expect.arrayContaining([
                'receiver_1_share_commitment_opening_coordinate_0',
            ]),
        );
        expect(result.statement.linearRows).toEqual(
            expect.arrayContaining([
                {
                    modulus: 65_537,
                    optionIndex: 0,
                    rowKind: 'OneHotSum',
                    rowName: 'option_1_one_hot_sum',
                    target: 1,
                    terms: Array.from(
                        { length: 10 },
                        (_unusedValue, score) => ({
                            coefficient: 1,
                            variableName: `option_1_score_bucket_${score + 1}`,
                        }),
                    ),
                },
                {
                    modulus: 65_537,
                    optionIndex: 0,
                    rowKind: 'ScalarScoreConsistency',
                    rowName: 'option_1_scalar_score_consistency',
                    target: 0,
                    terms: [
                        {
                            coefficient: 1,
                            variableName: 'option_1_scalar_constant',
                        },
                        ...Array.from(
                            { length: 10 },
                            (_unusedValue, score) => ({
                                coefficient: -(score + 1),
                                variableName: `option_1_score_bucket_${
                                    score + 1
                                }`,
                            }),
                        ),
                    ],
                },
                {
                    encodedCoordinateIndex: 0,
                    modulus: 65_537,
                    optionIndex: 0,
                    receiverRosterPosition: 2,
                    rowKind: 'ShamirEvaluationQuotient',
                    rowName:
                        'receiver_2_encoded_coordinate_0_shamir_evaluation',
                    target: 0,
                    terms: [
                        {
                            coefficient: 1,
                            variableName: 'option_1_scalar_constant',
                        },
                        {
                            coefficient: 2,
                            variableName:
                                'encoded_coordinate_0_coefficient_degree_1',
                        },
                        {
                            coefficient: -1,
                            variableName:
                                'receiver_2_encoded_coordinate_0_share',
                        },
                        {
                            coefficient: -65_537,
                            variableName:
                                'receiver_2_encoded_coordinate_0_quotient',
                        },
                    ],
                },
            ]),
        );
        expect(result.statement.bounds).toContainEqual({
            boundKind: 'Boolean',
            boundName: 'option_1_score_bucket_7_boolean',
            maximum: 1,
            minimum: 0,
            variableNames: ['option_1_score_bucket_7'],
        });
        const quotientBound = result.statement.bounds.find(
            (bound) =>
                bound.boundName === 'shamir_quotients_certified_absolute_bound',
        );
        expect(quotientBound).toMatchObject({
            absoluteMaximum: 65_537,
            boundKind: 'SignedIntegerAbsoluteBound',
        });
        expect(quotientBound?.variableNames).toEqual(
            expect.arrayContaining([
                'receiver_1_encoded_coordinate_0_quotient',
                'receiver_3_encoded_coordinate_21_quotient',
            ]),
        );
        const firstCommitmentRow = result.statement.algebraicRows.find(
            (row) =>
                row.rowKind === 'ShareCommitmentEquation' &&
                row.receiverRosterPosition === 1,
        );
        const firstEncryptionRow = result.statement.algebraicRows.find(
            (row) =>
                row.rowKind === 'ReceiverPayloadEncryptionEquation' &&
                row.receiverRosterPosition === 1,
        );
        const firstReceiverKeyRow = result.statement.algebraicRows.find(
            (row) =>
                row.rowKind === 'ReceiverKeyBinding' &&
                row.receiverRosterPosition === 1,
        );

        expect(firstCommitmentRow).toMatchObject({
            equationCount: 1_024,
            modulus: '18446744069414584321',
            rowName: 'receiver_1_share_commitment_equation',
        });
        expect(firstCommitmentRow?.variableNames).toEqual(
            expect.arrayContaining([
                'receiver_1_encoded_coordinate_0_share',
                'receiver_1_share_commitment_opening_coordinate_63',
            ]),
        );
        const explicitPayloadPlaintextRowBatch =
            result.statement.backendStatement.rowBatches[1];
        if (
            explicitPayloadPlaintextRowBatch?.batchKind !== 'ExplicitSparseRows'
        ) {
            throw new Error(
                'Expected payload plaintext binding rows to be explicit.',
            );
        }
        const payloadShareBindingRow =
            explicitPayloadPlaintextRowBatch.rows.find(
                (row) =>
                    row.rowName ===
                    'receiver_1_payload_plaintext_encoded_coordinate_21_share_binding',
            );
        expect(payloadShareBindingRow).toMatchObject({
            rowKind: 'ReceiverPayloadSharePlaintextBinding',
            target: '0',
        });
        expect(
            payloadShareBindingRow?.terms.map(
                ({ coefficient, variableName }) => ({
                    coefficient,
                    variableName,
                }),
            ),
        ).toEqual([
            {
                coefficient: '1',
                variableName:
                    'receiver_1_payload_plaintext_encoded_coordinate_21_share',
            },
            {
                coefficient: '-1',
                variableName: 'receiver_1_encoded_coordinate_21_share',
            },
        ]);
        expect(
            payloadShareBindingRow?.terms.every((term) =>
                Number.isInteger(term.columnIndex),
            ),
        ).toBe(true);
        const payloadOpeningBindingRow =
            explicitPayloadPlaintextRowBatch.rows.find(
                (row) =>
                    row.rowName ===
                    'receiver_1_payload_plaintext_opening_coordinate_0_binding',
            );
        expect(payloadOpeningBindingRow).toMatchObject({
            rowKind: 'ReceiverPayloadOpeningPlaintextBinding',
            target: '0',
        });
        expect(
            payloadOpeningBindingRow?.terms.map(
                ({ coefficient, variableName }) => ({
                    coefficient,
                    variableName,
                }),
            ),
        ).toEqual([
            {
                coefficient: '1',
                variableName:
                    'receiver_1_payload_plaintext_opening_coordinate_0',
            },
            {
                coefficient: '-1',
                variableName:
                    'receiver_1_share_commitment_opening_coordinate_0',
            },
        ]);
        expect(
            payloadOpeningBindingRow?.terms.every((term) =>
                Number.isInteger(term.columnIndex),
            ),
        ).toBe(true);
        expect(firstEncryptionRow).toMatchObject({
            equationCount: 1_280,
            modulus: 12_289,
        });
        expect(firstEncryptionRow?.variableNames).toEqual(
            expect.arrayContaining([
                'receiver_1_payload_plaintext_encoded_coordinate_0_share',
                'receiver_1_payload_plaintext_opening_coordinate_63',
                'receiver_1_receiver_encryption_randomness',
                'receiver_1_receiver_encryption_noise',
            ]),
        );
        expect(firstReceiverKeyRow).toMatchObject({
            equationCount: 1_024,
            modulus: 12_289,
            variableNames: [],
        });
        expect(result.statement.bounds).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    absoluteMaximum: 1_024,
                    boundName:
                        'share_commitment_openings_certified_absolute_bound',
                }),
                expect.objectContaining({
                    absoluteMaximum: 1_024,
                    boundName:
                        'receiver_payload_plaintext_openings_certified_absolute_bound',
                }),
                expect.objectContaining({
                    absoluteMaximum: 2,
                    boundName:
                        'receiver_encryption_randomness_certified_absolute_bound',
                }),
                expect.objectContaining({
                    absoluteMaximum: 2,
                    boundName:
                        'receiver_encryption_noise_certified_absolute_bound',
                }),
            ]),
        );
        expect(
            result.statement.bounds.find(
                (bound) =>
                    bound.boundName ===
                    'share_commitment_openings_certified_absolute_bound',
            )?.variableNames,
        ).toEqual(
            expect.arrayContaining([
                'receiver_1_share_commitment_opening_coordinate_0',
            ]),
        );
        expect(JSON.stringify(result.statement)).not.toMatch(
            /normalizedScores|scoreOneHotWitnesses|receiverShareVector|encodedCoordinateShamirCoefficients/u,
        );
    });

    it('projects encoded-score field rows into the linear proof backend shape', () => {
        const relationInput = validRelationInput();
        const context = publicContext();
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        const projection = buildEncodedScoreFieldLinearProofProjection({
            ballotProofStatementDigest: context.ballotProofStatementDigest,
            loweredStatement: loweringResult.statement,
            parameterProfileId: 'encoded-score-field-linear-compatibility-v1',
            relationInput,
            sourceRingDegree: 64,
            witnessL2BoundSquared: '65536',
        });

        expect(projection.sourceRowBatchName).toBe('encoded_score_field_rows');
        expect(projection.sourceBackendColumnIndices).toHaveLength(176);
        expect(projection.sourceBackendColumnIndices[0]).toBe(0);
        expect(
            projection.sourceBackendColumnIndices[
                projection.sourceBackendColumnIndices.length - 1
            ],
        ).toBe(175);
        expect(projection.linearStatement).toMatchObject({
            ballotProofStatementDigest: context.ballotProofStatementDigest,
            coefficientModulus: '65537',
            objectType: 'BallotProofLinearProofStatement',
            parameterProfileId: 'encoded-score-field-linear-compatibility-v1',
            projectionCoverage: 'encoded-score-field-rows-only',
            relation: 'A*w + t = 0',
            ringDegree: 64,
            statementColumns: 176,
            statementRows: 70,
            witnessL2BoundSquared: '65536',
        });
        expect(
            projection.linearStatement.statementMatrixCoefficients,
        ).toHaveLength(70);
        expect(
            projection.linearStatement.statementMatrixCoefficients[0],
        ).toHaveLength(176);
        expect(
            projection.linearStatement.statementMatrixCoefficients[0]?.[0],
        ).toHaveLength(64);
        expect(
            projection.linearStatement.targetVectorCoefficients,
        ).toHaveLength(70);
        expect(projection.linearStatement.statementDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(projection.privateWitnessVectorCoefficients).toHaveLength(176);
        expect(
            projection.privateWitnessVectorCoefficients.some(
                (polynomial) => polynomial[0] === -1,
            ),
        ).toBe(true);
        expect(
            projection.privateWitnessVectorCoefficients.every(
                (polynomial) =>
                    polynomial.length === 64 &&
                    polynomial
                        .slice(1)
                        .every((coefficient) => coefficient === 0),
            ),
        ).toBe(true);
        expect(projection.linearStatement).not.toHaveProperty(
            'privateWitnessVectorCoefficients',
        );
        expect(JSON.stringify(projection.linearStatement)).not.toMatch(
            /normalizedScores|scoreOneHotWitnesses|receiverShareVector|privateWitness/u,
        );
    });

    it('projects receiver payload plaintext binding rows into an explicit component statement', () => {
        const relationInput = validRelationInput();
        const context = publicContext(relationInput);
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        const projection = buildBallotProofComponentLinearProofProjection({
            ballotProofStatementDigest: context.ballotProofStatementDigest,
            componentId: 'payload-plaintext-field-component',
            loweredStatement: loweringResult.statement,
            parameterProfileId:
                'payload-plaintext-field-linear-compatibility-v1',
            projectionWitness: projectionWitness(relationInput),
            relationInput,
            sourceRingDegree: 1,
            witnessL2BoundSquared: '65536',
        });

        expect(projection.sourceRowBatchNames).toEqual([
            'receiver_payload_plaintext_binding_rows',
        ]);
        expect(projection.linearStatement).toMatchObject({
            coefficientModulus: '65537',
            projectionCoverage: 'payload-plaintext-field-rows-only',
            ringDegree: 1,
            statementColumns: 516,
            statementRows: 258,
        });
        expect(projection.privateWitnessVectorCoefficients).toHaveLength(516);
        expect(projection.linearStatement).not.toHaveProperty(
            'privateWitnessVectorCoefficients',
        );

        const wrongPayloadOpeningWitness = {
            ...projectionWitness(relationInput),
            receiverPayloadPlaintexts: relationInput.receivers.map(
                (receiver) => ({
                    openingRandomness: shareCommitmentOpeningForReceiver(
                        receiver.receiverRosterPosition,
                    ).map((openingCoordinate, openingCoordinateIndex) =>
                        receiver.receiverRosterPosition === 1 &&
                        openingCoordinateIndex === 0
                            ? openingCoordinate + 1
                            : openingCoordinate,
                    ),
                    receiverRosterPosition: receiver.receiverRosterPosition,
                    receiverShareVector: receiver.receiverShareVector,
                }),
            ),
        };
        expect(() =>
            buildBallotProofComponentLinearProofProjection({
                ballotProofStatementDigest: context.ballotProofStatementDigest,
                componentId: 'payload-plaintext-field-component',
                loweredStatement: loweringResult.statement,
                parameterProfileId:
                    'payload-plaintext-field-linear-compatibility-v1',
                projectionWitness: wrongPayloadOpeningWitness,
                relationInput,
                sourceRingDegree: 1,
                witnessL2BoundSquared: '65536',
            }),
        ).toThrow(/payload-plaintext-field-component row/u);
    });

    it('projects share commitment rows with BigInt-safe decimal coefficients', () => {
        const relationInput = validRelationInput();
        const context = publicContext(relationInput);
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        const projection = buildBallotProofComponentLinearProofProjection({
            ballotProofStatementDigest: context.ballotProofStatementDigest,
            componentId: 'share-commitment-component',
            loweredStatement: loweringResult.statement,
            parameterProfileId: 'share-commitment-linear-compatibility-v1',
            projectionWitness: projectionWitness(relationInput),
            relationInput,
            sourceRingDegree: 1,
            witnessL2BoundSquared: '1048576',
        });

        expect(projection.sourceRowBatchNames).toEqual([
            'share_commitment_equation_rows',
        ]);
        expect(projection.linearStatement).toMatchObject({
            coefficientModulus: '18446744069414584321',
            projectionCoverage: 'share-commitment-rows-only',
            ringDegree: 1,
            statementColumns: 258,
            statementRows: 3_072,
        });
        expect(
            typeof projection.linearStatement
                .statementMatrixCoefficients[0]?.[0]?.[0],
        ).toBe('string');
        expect(
            typeof projection.linearStatement.targetVectorCoefficients[0]?.[0],
        ).toBe('string');
        expect(projection.linearStatement.statementDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(projection.privateWitnessVectorCoefficients).toHaveLength(258);
        expect(projection.linearStatement).not.toHaveProperty(
            'privateWitnessVectorCoefficients',
        );

        const wrongCommitmentOpeningWitness = {
            ...projectionWitness(relationInput),
            shareCommitmentOpenings: relationInput.receivers.map(
                (receiver) => ({
                    openingRandomness: shareCommitmentOpeningForReceiver(
                        receiver.receiverRosterPosition,
                    ).map((openingCoordinate, openingCoordinateIndex) =>
                        receiver.receiverRosterPosition === 1 &&
                        openingCoordinateIndex === 0
                            ? openingCoordinate + 1
                            : openingCoordinate,
                    ),
                    receiverRosterPosition: receiver.receiverRosterPosition,
                }),
            ),
        };
        expect(() =>
            buildBallotProofComponentLinearProofProjection({
                ballotProofStatementDigest: context.ballotProofStatementDigest,
                componentId: 'share-commitment-component',
                loweredStatement: loweringResult.statement,
                parameterProfileId: 'share-commitment-linear-compatibility-v1',
                projectionWitness: wrongCommitmentOpeningWitness,
                relationInput,
                sourceRingDegree: 1,
                witnessL2BoundSquared: '1048576',
            }),
        ).toThrow(/share-commitment-component row/u);
    });

    it('refuses a share commitment projection when commitment polynomial vectors are digest-expanded', () => {
        const relationInput = validRelationInput();
        const contextWithExplicitCommitments = publicContext(relationInput);
        const contextWithDigestExpandedCommitments = {
            ...contextWithExplicitCommitments,
            shareCommitments:
                contextWithExplicitCommitments.shareCommitments.map(
                    (shareCommitment) => ({
                        commitmentBodyDigest:
                            shareCommitment.commitmentBodyDigest,
                        commitmentPolynomialVectorDigest:
                            shareCommitment.commitmentPolynomialVectorDigest,
                        receiverIdentity: shareCommitment.receiverIdentity,
                        receiverRosterPosition:
                            shareCommitment.receiverRosterPosition,
                        shareCommitmentDigest:
                            shareCommitment.shareCommitmentDigest,
                    }),
                ),
        };
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: contextWithDigestExpandedCommitments,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        expect(() =>
            buildBallotProofComponentLinearProofProjection({
                ballotProofStatementDigest:
                    contextWithDigestExpandedCommitments.ballotProofStatementDigest,
                componentId: 'share-commitment-component',
                loweredStatement: loweringResult.statement,
                parameterProfileId: 'share-commitment-linear-compatibility-v1',
                projectionWitness: projectionWitness(relationInput),
                relationInput,
                sourceRingDegree: 1,
                witnessL2BoundSquared: '1048576',
            }),
        ).toThrow(/not fully lowered to explicit rows/u);
    });

    it('builds compact sparse component statements without dense matrices or witnesses', () => {
        const relationInput = validRelationInput();
        const context = publicContext(relationInput);
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        const payloadStatement: BallotProofSparseComponentLinearProofStatement =
            buildBallotProofSparseComponentLinearProofStatement({
                ballotProofStatementDigest: context.ballotProofStatementDigest,
                componentId: 'payload-plaintext-field-component',
                loweredStatement: loweringResult.statement,
                parameterProfileId: 'payload-plaintext-field-linear-sparse-v1',
                sourceRingDegree: 64,
                witnessL2BoundSquared: '65536',
            });
        const shareCommitmentStatement: BallotProofSparseComponentLinearProofStatement =
            buildBallotProofSparseComponentLinearProofStatement({
                ballotProofStatementDigest: context.ballotProofStatementDigest,
                componentId: 'share-commitment-component',
                loweredStatement: loweringResult.statement,
                parameterProfileId: 'share-commitment-linear-sparse-v1',
                sourceRingDegree: 256,
                witnessL2BoundSquared: '1048576',
            });
        const shareCommitmentRowBatch =
            loweringResult.statement.backendStatement.rowBatches.find(
                (rowBatch) =>
                    rowBatch.batchName === 'share_commitment_equation_rows',
            );
        if (shareCommitmentRowBatch?.batchKind !== 'ExplicitSparseRows') {
            throw new Error('Expected explicit share commitment rows.');
        }
        const expectedShareTermCount = shareCommitmentRowBatch.rows.reduce(
            (termCount, row) => termCount + row.terms.length,
            0,
        );

        expect(payloadStatement).toMatchObject({
            coefficientModulus: '65537',
            objectType: 'BallotProofSparseComponentLinearProofStatement',
            proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
            projectionCoverage: 'payload-plaintext-field-rows-only',
            sourceRingDegree: 64,
            sparseStatementTermCount: '516',
            statementColumns: 516,
            statementRows: 258,
            targetVectorEntryCount: '0',
        });
        expect(shareCommitmentStatement).toMatchObject({
            coefficientModulus: '18446744069414584321',
            projectionCoverage: 'share-commitment-rows-only',
            sourceRingDegree: 256,
            sparseStatementTermCount: expectedShareTermCount.toString(),
            statementColumns: 258,
            statementRows: 3_072,
        });
        expect(
            shareCommitmentStatement.targetVectorEntries.length,
        ).toBeGreaterThan(0);
        expect(shareCommitmentStatement.statementDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(shareCommitmentStatement).not.toHaveProperty(
            'statementMatrixCoefficients',
        );
        expect(payloadStatement).not.toHaveProperty(
            'privateWitnessVectorCoefficients',
        );
        expect(
            JSON.stringify([payloadStatement, shareCommitmentStatement]),
        ).not.toMatch(
            /normalizedScores|scoreOneHotWitnesses|receiverShareVector|privateWitness/u,
        );
    });

    it('binds sparse share-commitment statement digests to public targets', () => {
        const relationInput = validRelationInput();
        const context = publicContext(relationInput);
        const firstCommitment = context.shareCommitments[0];
        const changedCommitmentPolynomialVector =
            firstCommitment?.commitmentPolynomialVector?.map(
                (commitmentPolynomial, polynomialIndex) =>
                    commitmentPolynomial.map((coefficient, coefficientIndex) =>
                        polynomialIndex === 0 && coefficientIndex === 0
                            ? (
                                  (BigInt(coefficient) + 1n) %
                                  shareCommitmentModulus
                              ).toString()
                            : coefficient,
                    ),
            );
        if (
            firstCommitment === undefined ||
            changedCommitmentPolynomialVector === undefined
        ) {
            throw new Error('Missing share commitment vector for mutation.');
        }
        const changedContext: BallotPrivacyRelationBackendPublicContext = {
            ...context,
            shareCommitments: context.shareCommitments.map((shareCommitment) =>
                shareCommitment.receiverRosterPosition === 1
                    ? {
                          ...shareCommitment,
                          commitmentBodyDigest: deriveShareCommitmentBodyDigest(
                              {
                                  commitmentPolynomialVector:
                                      changedCommitmentPolynomialVector,
                                  shareCommitmentProfileDigest:
                                      context.shareCommitmentProfileDigest,
                              },
                          ),
                          commitmentPolynomialVector:
                              changedCommitmentPolynomialVector,
                          commitmentPolynomialVectorDigest:
                              deriveProtocolDigest('ChallengeDomainDigest', {
                                  commitmentPolynomialVector:
                                      changedCommitmentPolynomialVector,
                                  purpose:
                                      'ballot-privacy-test-share-commitment-polynomial-vector',
                              }),
                      }
                    : shareCommitment,
            ),
        };
        const originalLoweringResult =
            lowerBallotPrivacyRelationToBackendStatement({
                publicContext: context,
                relationInput,
            });
        const changedLoweringResult =
            lowerBallotPrivacyRelationToBackendStatement({
                publicContext: changedContext,
                relationInput,
            });

        expect(originalLoweringResult.ok).toBe(true);
        expect(changedLoweringResult.ok).toBe(true);
        if (!originalLoweringResult.ok || !changedLoweringResult.ok) {
            throw new Error('valid relation inputs should lower');
        }

        const originalStatement =
            buildBallotProofSparseComponentLinearProofStatement({
                ballotProofStatementDigest: context.ballotProofStatementDigest,
                componentId: 'share-commitment-component',
                loweredStatement: originalLoweringResult.statement,
                parameterProfileId: 'share-commitment-linear-sparse-v1',
                sourceRingDegree: 256,
                witnessL2BoundSquared: '1048576',
            });
        const changedStatement =
            buildBallotProofSparseComponentLinearProofStatement({
                ballotProofStatementDigest:
                    changedContext.ballotProofStatementDigest,
                componentId: 'share-commitment-component',
                loweredStatement: changedLoweringResult.statement,
                parameterProfileId: 'share-commitment-linear-sparse-v1',
                sourceRingDegree: 256,
                witnessL2BoundSquared: '1048576',
            });

        expect(originalStatement.sparseStatementMatrixDigest).toBe(
            changedStatement.sparseStatementMatrixDigest,
        );
        expect(originalStatement.targetVectorDigest).not.toBe(
            changedStatement.targetVectorDigest,
        );
        expect(originalStatement.statementDigest).not.toBe(
            changedStatement.statementDigest,
        );
    });

    it('builds an ordered component bundle statement for the full ballot relation', () => {
        const context = publicContext();
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput: validRelationInput(),
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        const componentBundle = buildBallotProofComponentBundleStatement({
            ballotProofStatementDigest: context.ballotProofStatementDigest,
            loweredStatement: loweringResult.statement,
        });

        expect(componentBundle).toMatchObject({
            backendStatementDigest:
                loweringResult.statement.backendStatement
                    .backendStatementDigest,
            ballotProofStatementDigest: context.ballotProofStatementDigest,
            bundleCoverage: 'component-bundle-incomplete',
            objectType: 'BallotProofComponentBundleStatement',
            objectVersion: 1,
            relationLabel: 'BallotPrivacyPvssRelation',
            relationStatementDigest:
                loweringResult.statement.relationStatementDigest,
            requiredComponentIds: ballotPrivacyBackendProofComponentOrder,
        });
        expect(componentBundle.componentBundleStatementDigest).toMatch(
            /^[a-f0-9]{128}$/u,
        );
        expect(componentBundle.componentStatements).toHaveLength(5);
        expect(
            componentBundle.componentStatements.map(
                (componentStatement) => componentStatement.componentId,
            ),
        ).toEqual(ballotPrivacyBackendProofComponentOrder);
        expect(componentBundle.componentStatements[0]).toMatchObject({
            coefficientModulus: '65537',
            componentId: 'score-and-shamir-field-component',
            proofLoweringStatus: 'explicitRowsAvailable',
            rowBatchNames: ['encoded_score_field_rows'],
            rowCount: 70,
            rowKinds: ['EncodedScoreFieldRows'],
            variableColumnCount: 176,
        });
        expect(componentBundle.componentStatements[1]).toMatchObject({
            coefficientModulus: '65537',
            componentId: 'payload-plaintext-field-component',
            proofLoweringStatus: 'explicitRowsAvailable',
            rowBatchNames: ['receiver_payload_plaintext_binding_rows'],
            rowCount: 258,
            rowKinds: ['ReceiverPayloadPlaintextBindingRows'],
            variableColumnCount: 516,
        });
        expect(componentBundle.componentStatements[2]).toMatchObject({
            coefficientModulus: '18446744069414584321',
            componentId: 'share-commitment-component',
            proofLoweringStatus: 'explicitRowsAvailable',
            rowBatchNames: ['share_commitment_equation_rows'],
            rowCount: 3_072,
            rowKinds: ['ShareCommitmentEquationRows'],
            variableColumnCount: 258,
        });
        expect(
            componentBundle.componentStatements
                .slice(3)
                .every(
                    (componentStatement) =>
                        componentStatement.proofLoweringStatus ===
                        'digestExpandedRowsPending',
                ),
        ).toBe(true);
        expect(
            componentBundle.componentStatements.every(
                (componentStatement) =>
                    /^[a-f0-9]{128}$/u.exec(
                        componentStatement.componentStatementDigest,
                    ) !== null &&
                    componentStatement.rowBatchMatrixDigests.length ===
                        componentStatement.rowBatchNames.length &&
                    componentStatement.rowBatchTargetVectorDigests.length ===
                        componentStatement.rowBatchNames.length,
            ),
        ).toBe(true);
        expect(JSON.stringify(componentBundle)).not.toMatch(
            /normalizedScores|scoreOneHotWitnesses|receiverShareVector|privateWitness/u,
        );
    });

    it('builds component proof statement plans for sparse and structured proof paths', () => {
        const relationInput = singleOptionRelationInput();
        const { context } = explicitReceiverEncryptionFixture(relationInput);
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid relation input should lower');
        }

        const componentBundle = buildBallotProofComponentBundleStatement({
            ballotProofStatementDigest: context.ballotProofStatementDigest,
            loweredStatement: loweringResult.statement,
        });
        const plans = buildBallotProofComponentProofStatementPlans({
            ballotProofStatementDigest: context.ballotProofStatementDigest,
            componentBundleStatement: componentBundle,
            loweredStatement: loweringResult.statement,
        });

        expect(plans.map((plan) => plan.componentId)).toEqual(
            ballotPrivacyBackendProofComponentOrder,
        );
        expect(plans[0]).toMatchObject({
            denseCoefficientCount: '197120',
            proofBytesAvailability: 'available-for-small-dense-oracle',
            proofStatementFormat: 'dense-polynomial-matrix-linear-proof-v1',
            rowBatchTermCounts: ['153'],
            sourceRingDegree: 64,
        });
        expect(plans[1]).toMatchObject({
            proofBytesAvailability: 'requires-sparse-proof-statement',
            proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
            rowBatchTermCounts: ['450', '3090'],
            sparseTermCount: '3540',
        });
        expect(plans[2]).toMatchObject({
            proofBytesAvailability: 'requires-sparse-proof-statement',
            proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
            rowBatchTermCounts: ['230400'],
            sparseTermCount: '230400',
        });
        expect(plans[3]).toMatchObject({
            proofBytesAvailability: 'requires-structured-proof-statement',
            proofStatementFormat: 'structured-module-lwe-linear-proof-v1',
            rowBatchTermCounts: ['15746865'],
            structuredCiphertextChunkCount: 12,
            structuredReceiverCount: 3,
            structuredWitnessTermCount: '15746865',
        });
        expect(plans[4]).toMatchObject({
            denseCoefficientCount: null,
            proofBytesAvailability: 'public-zero-witness-binding-check',
            proofStatementFormat: 'public-zero-witness-binding-check-v1',
            rowBatchTermCounts: ['0'],
            sourceRingDegree: null,
            variableColumnCount: 0,
        });
        expect(
            plans.every((plan) =>
                /^[a-f0-9]{128}$/u.test(plan.componentProofStatementDigest),
            ),
        ).toBe(true);
        expect(JSON.stringify(plans)).not.toMatch(
            /normalizedScores|scoreOneHotWitnesses|receiverShareVector|privateWitness/u,
        );
    });

    it('binds public share commitment vectors into explicit backend targets', () => {
        const relationInput = validRelationInput();
        const context = publicContext(relationInput);
        const firstResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });
        const firstCommitment = context.shareCommitments[0];
        const changedCommitmentPolynomialVector =
            firstCommitment?.commitmentPolynomialVector?.map(
                (commitmentPolynomial, polynomialIndex) =>
                    commitmentPolynomial.map((coefficient, coefficientIndex) =>
                        polynomialIndex === 0 && coefficientIndex === 0
                            ? (
                                  (BigInt(coefficient) + 1n) %
                                  shareCommitmentModulus
                              ).toString()
                            : coefficient,
                    ),
            );
        if (
            firstCommitment === undefined ||
            changedCommitmentPolynomialVector === undefined
        ) {
            throw new Error('Missing share commitment vector for mutation.');
        }
        const changedContext: BallotPrivacyRelationBackendPublicContext = {
            ...context,
            shareCommitments: context.shareCommitments.map((shareCommitment) =>
                shareCommitment.receiverRosterPosition === 1
                    ? {
                          ...shareCommitment,
                          commitmentBodyDigest: deriveShareCommitmentBodyDigest(
                              {
                                  commitmentPolynomialVector:
                                      changedCommitmentPolynomialVector,
                                  shareCommitmentProfileDigest:
                                      context.shareCommitmentProfileDigest,
                              },
                          ),
                          commitmentPolynomialVector:
                              changedCommitmentPolynomialVector,
                          commitmentPolynomialVectorDigest:
                              deriveProtocolDigest('ChallengeDomainDigest', {
                                  commitmentPolynomialVector:
                                      changedCommitmentPolynomialVector,
                                  purpose:
                                      'ballot-privacy-test-share-commitment-polynomial-vector',
                              }),
                      }
                    : shareCommitment,
            ),
        };
        const secondResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: changedContext,
            relationInput,
        });

        expect(firstResult.ok).toBe(true);
        expect(secondResult.ok).toBe(true);
        if (!firstResult.ok || !secondResult.ok) {
            throw new Error('valid relation inputs should lower');
        }
        expect(firstResult.statement.relationStatementDigest).not.toBe(
            secondResult.statement.relationStatementDigest,
        );
        expect(
            firstResult.statement.backendStatement.rowBatches[2]
                ?.targetVectorDigest,
        ).not.toBe(
            secondResult.statement.backendStatement.rowBatches[2]
                ?.targetVectorDigest,
        );
    });

    it('does not let a reused public commitment satisfy another receiver opening', () => {
        const relationInput = validRelationInput();
        const context = publicContext(relationInput);
        const firstCommitment = context.shareCommitments[0];
        if (firstCommitment?.commitmentPolynomialVector === undefined) {
            throw new Error('Missing first commitment vector.');
        }
        const firstCommitmentPolynomialVector =
            firstCommitment.commitmentPolynomialVector;
        const reusedCommitmentContext: BallotPrivacyRelationBackendPublicContext =
            {
                ...context,
                shareCommitments: context.shareCommitments.map(
                    (shareCommitment) =>
                        shareCommitment.receiverRosterPosition === 2
                            ? {
                                  ...shareCommitment,
                                  commitmentBodyDigest:
                                      deriveShareCommitmentBodyDigest({
                                          commitmentPolynomialVector:
                                              firstCommitmentPolynomialVector,
                                          shareCommitmentProfileDigest:
                                              context.shareCommitmentProfileDigest,
                                      }),
                                  commitmentPolynomialVector:
                                      firstCommitmentPolynomialVector,
                                  commitmentPolynomialVectorDigest:
                                      deriveProtocolDigest(
                                          'ChallengeDomainDigest',
                                          {
                                              commitmentPolynomialVector:
                                                  firstCommitmentPolynomialVector,
                                              purpose:
                                                  'ballot-privacy-test-share-commitment-polynomial-vector',
                                          },
                                      ),
                              }
                            : shareCommitment,
                ),
            };
        const result = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: reusedCommitmentContext,
            relationInput,
        });

        expect(result.ok).toBe(true);
        if (!result.ok) {
            throw new Error('relation with public commitment mutation lowers');
        }
        const shareCommitmentRowBatch =
            result.statement.backendStatement.rowBatches[2];
        if (shareCommitmentRowBatch?.batchKind !== 'ExplicitSparseRows') {
            throw new Error('Expected share commitment rows to be explicit.');
        }
        const reusedReceiverRow = shareCommitmentRowBatch.rows.find(
            (row) =>
                row.rowName ===
                'receiver_2_share_commitment_vector_0_coefficient_0_equation',
        );
        if (reusedReceiverRow === undefined) {
            throw new Error('Missing reused receiver commitment row.');
        }
        const secondReceiver = relationInput.receivers[1];
        const witnessValues = new Map<string, bigint>();
        secondReceiver?.receiverShareVector.forEach(
            (shareRepresentative, encodedCoordinateIndex) => {
                witnessValues.set(
                    `receiver_2_encoded_coordinate_${encodedCoordinateIndex}_share`,
                    BigInt(shareRepresentative),
                );
            },
        );
        shareCommitmentOpeningForReceiver(2).forEach(
            (openingCoordinate, openingCoordinateIndex) => {
                witnessValues.set(
                    `receiver_2_share_commitment_opening_coordinate_${openingCoordinateIndex}`,
                    BigInt(openingCoordinate),
                );
            },
        );
        const evaluatedValue = reusedReceiverRow.terms.reduce(
            (accumulatedValue, term) =>
                (accumulatedValue +
                    BigInt(term.coefficient) *
                        (witnessValues.get(term.variableName) ?? 0n)) %
                shareCommitmentModulus,
            0n,
        );

        expect(
            (evaluatedValue + shareCommitmentModulus) % shareCommitmentModulus,
        ).not.toBe(BigInt(reusedReceiverRow.target));
    });

    it('lowers receiver encryption and receiver-key bindings into explicit backend rows', () => {
        const relationInput = singleOptionRelationInput();
        const { context, projectionWitness: explicitProjectionWitness } =
            explicitReceiverEncryptionFixture(relationInput);
        const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: context,
            relationInput,
        });

        expect(loweringResult.ok).toBe(true);
        if (!loweringResult.ok) {
            throw new Error('valid explicit relation input should lower');
        }

        expect(loweringResult.statement.linearRows).toHaveLength(
            2 + 3 * 11 + 3 * (11 + 64) + 3 * (11 + 64),
        );
        expect(loweringResult.statement.backendStatement).toMatchObject({
            digestExpandedRowCount: 0,
            explicitRowCount:
                35 + 3 * 75 + 3 * 75 + 3 * 1_024 + 3 * 5_120 + 3 * 1_024,
            rowCount: 35 + 3 * 75 + 3 * 75 + 3 * 1_024 + 3 * 5_120 + 3 * 1_024,
        });
        expect(
            loweringResult.statement.backendStatement.rowBatches.map(
                (rowBatch) => rowBatch.batchName,
            ),
        ).toEqual([
            'encoded_score_field_rows',
            'receiver_payload_plaintext_binding_rows',
            'receiver_payload_plaintext_bit_decomposition_rows',
            'share_commitment_equation_rows',
            'receiver_payload_encryption_equation_rows',
            'receiver_key_binding_rows',
        ]);
        expect(
            loweringResult.statement.backendStatement.proofComponents.map(
                (component) => ({
                    componentId: component.componentId,
                    proofLoweringStatus: component.proofLoweringStatus,
                }),
            ),
        ).toEqual([
            {
                componentId: 'score-and-shamir-field-component',
                proofLoweringStatus: 'explicitRowsAvailable',
            },
            {
                componentId: 'payload-plaintext-field-component',
                proofLoweringStatus: 'explicitRowsAvailable',
            },
            {
                componentId: 'share-commitment-component',
                proofLoweringStatus: 'explicitRowsAvailable',
            },
            {
                componentId: 'receiver-encryption-component',
                proofLoweringStatus: 'explicitRowsAvailable',
            },
            {
                componentId: 'receiver-key-binding-component',
                proofLoweringStatus: 'explicitRowsAvailable',
            },
        ]);

        const componentBundle = buildBallotProofComponentBundleStatement({
            ballotProofStatementDigest: context.ballotProofStatementDigest,
            loweredStatement: loweringResult.statement,
        });
        expect(componentBundle.bundleCoverage).toBe(
            'full-encoded-score-ballot-relation',
        );
        expect(
            verifyBallotProofComponentExplicitRows({
                componentId: 'receiver-encryption-component',
                loweredStatement: loweringResult.statement,
                projectionWitness: explicitProjectionWitness,
                relationInput,
            }),
        ).toMatchObject({
            checkedRowBatchNames: ['receiver_payload_encryption_equation_rows'],
            componentId: 'receiver-encryption-component',
            rowCount: 3 * 5_120,
            verificationStatus: 'explicitRowsSatisfied',
        });
        expect(
            verifyBallotProofComponentExplicitRows({
                componentId: 'receiver-key-binding-component',
                loweredStatement: loweringResult.statement,
                projectionWitness: explicitProjectionWitness,
                relationInput,
            }),
        ).toMatchObject({
            checkedRowBatchNames: ['receiver_key_binding_rows'],
            componentId: 'receiver-key-binding-component',
            rowCount: 3 * 1_024,
            verificationStatus: 'explicitRowsSatisfied',
        });
        const payloadBitDecompositionRowBatch =
            loweringResult.statement.backendStatement.rowBatches.find(
                (rowBatch) =>
                    rowBatch.batchName ===
                    'receiver_payload_plaintext_bit_decomposition_rows',
            );
        expect(payloadBitDecompositionRowBatch).toMatchObject({
            batchKind: 'ExplicitSparseRows',
            rowCount: 3 * 75,
            rowKind: 'ReceiverPayloadPlaintextBitDecompositionRows',
        });
        expect(loweringResult.statement.backendStatement.bounds).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    boundKind: 'Boolean',
                    boundName: 'receiver_payload_plaintext_bits_boolean',
                }),
                expect.objectContaining({
                    absoluteMaximum: '2',
                    boundName:
                        'receiver_encryption_first_noise_certified_absolute_bound',
                }),
                expect.objectContaining({
                    absoluteMaximum: '2',
                    boundName:
                        'receiver_encryption_second_noise_certified_absolute_bound',
                }),
            ]),
        );
    });

    it('rejects explicit receiver-encryption rows when ciphertext or encrypted opening material changes', () => {
        const relationInput = singleOptionRelationInput();
        const { context, projectionWitness: explicitProjectionWitness } =
            explicitReceiverEncryptionFixture(relationInput);
        const firstLoweringResult =
            lowerBallotPrivacyRelationToBackendStatement({
                publicContext: context,
                relationInput,
            });

        expect(firstLoweringResult.ok).toBe(true);
        if (!firstLoweringResult.ok) {
            throw new Error('valid explicit relation input should lower');
        }

        const changedCiphertextContext: BallotPrivacyRelationBackendPublicContext =
            {
                ...context,
                receiverPayloads: context.receiverPayloads.map(
                    (receiverPayload) =>
                        receiverPayload.receiverRosterPosition === 1
                            ? {
                                  ...receiverPayload,
                                  ciphertextChunks:
                                      receiverPayload.ciphertextChunks?.map(
                                          (ciphertextChunk) =>
                                              ciphertextChunk.chunkIndex === 0
                                                  ? {
                                                        ...ciphertextChunk,
                                                        firstCiphertextVector:
                                                            ciphertextChunk.firstCiphertextVector.map(
                                                                (
                                                                    polynomial,
                                                                    vectorIndex,
                                                                ) =>
                                                                    vectorIndex ===
                                                                    0
                                                                        ? polynomial.map(
                                                                              (
                                                                                  coefficient,
                                                                                  coefficientIndex,
                                                                              ) =>
                                                                                  coefficientIndex ===
                                                                                  0
                                                                                      ? (coefficient +
                                                                                            1) %
                                                                                        12_289
                                                                                      : coefficient,
                                                                          )
                                                                        : polynomial,
                                                            ),
                                                    }
                                                  : ciphertextChunk,
                                      ),
                              }
                            : receiverPayload,
                ),
            };
        const changedCiphertextLoweringResult =
            lowerBallotPrivacyRelationToBackendStatement({
                publicContext: changedCiphertextContext,
                relationInput,
            });

        expect(changedCiphertextLoweringResult.ok).toBe(true);
        if (!changedCiphertextLoweringResult.ok) {
            throw new Error('mutated public ciphertext should still lower');
        }
        expect(() =>
            verifyBallotProofComponentExplicitRows({
                componentId: 'receiver-encryption-component',
                loweredStatement: changedCiphertextLoweringResult.statement,
                projectionWitness: explicitProjectionWitness,
                relationInput,
            }),
        ).toThrow(/receiver-encryption-component row/u);

        const wrongOpeningProjectionWitness: BallotProofComponentProjectionWitness =
            {
                ...explicitProjectionWitness,
                receiverPayloadPlaintexts:
                    explicitProjectionWitness.receiverPayloadPlaintexts?.map(
                        (plaintext) =>
                            plaintext.receiverRosterPosition === 1
                                ? {
                                      ...plaintext,
                                      openingRandomness:
                                          plaintext.openingRandomness.map(
                                              (
                                                  openingCoordinate,
                                                  openingCoordinateIndex,
                                              ) =>
                                                  openingCoordinateIndex === 0
                                                      ? openingCoordinate + 1
                                                      : openingCoordinate,
                                          ),
                                  }
                                : plaintext,
                    ),
            };
        expect(() =>
            verifyBallotProofComponentExplicitRows({
                componentId: 'receiver-encryption-component',
                loweredStatement: firstLoweringResult.statement,
                projectionWitness: wrongOpeningProjectionWitness,
                relationInput,
            }),
        ).toThrow(/receiver-encryption-component row/u);

        const wrongRandomnessProjectionWitness: BallotProofComponentProjectionWitness =
            {
                ...explicitProjectionWitness,
                receiverEncryptionWitnesses:
                    explicitProjectionWitness.receiverEncryptionWitnesses?.map(
                        (receiverWitness) =>
                            receiverWitness.receiverRosterPosition === 1
                                ? {
                                      ...receiverWitness,
                                      chunkWitnesses:
                                          receiverWitness.chunkWitnesses.map(
                                              (chunkWitness) =>
                                                  chunkWitness.chunkIndex === 0
                                                      ? {
                                                            ...chunkWitness,
                                                            encryptionRandomnessVector:
                                                                chunkWitness.encryptionRandomnessVector.map(
                                                                    (
                                                                        polynomial,
                                                                        vectorIndex,
                                                                    ) =>
                                                                        vectorIndex ===
                                                                        0
                                                                            ? polynomial.map(
                                                                                  (
                                                                                      coefficient,
                                                                                      coefficientIndex,
                                                                                  ) =>
                                                                                      coefficientIndex ===
                                                                                      0
                                                                                          ? coefficient +
                                                                                            1
                                                                                          : coefficient,
                                                                              )
                                                                            : polynomial,
                                                                ),
                                                        }
                                                      : chunkWitness,
                                          ),
                                  }
                                : receiverWitness,
                    ),
            };
        expect(() =>
            verifyBallotProofComponentExplicitRows({
                componentId: 'receiver-encryption-component',
                loweredStatement: firstLoweringResult.statement,
                projectionWitness: wrongRandomnessProjectionWitness,
                relationInput,
            }),
        ).toThrow(/receiver-encryption-component row/u);
    });

    it('binds every public context digest into the relation statement digest', () => {
        const firstResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: publicContext(),
            relationInput: validRelationInput(),
        });
        const changedContext = {
            ...publicContext(),
            actionContextDigest: digest('changed-action-context'),
        };
        const secondResult = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: changedContext,
            relationInput: validRelationInput(),
        });

        expect(firstResult.ok).toBe(true);
        expect(secondResult.ok).toBe(true);
        if (firstResult.ok && secondResult.ok) {
            expect(firstResult.statement.relationStatementDigest).not.toBe(
                secondResult.statement.relationStatementDigest,
            );
        }
    });

    it('keeps hostile compiler inputs as relation refusals before lowering', () => {
        const wrongShareInput = validRelationInput();
        const result = lowerBallotPrivacyRelationToBackendStatement({
            publicContext: publicContext(),
            relationInput: {
                ...wrongShareInput,
                receivers: wrongShareInput.receivers.map((receiver) =>
                    receiver.receiverRosterPosition === 2
                        ? {
                              ...receiver,
                              receiverShareVector:
                                  receiver.receiverShareVector.map(
                                      (shareRepresentative, coordinateIndex) =>
                                          coordinateIndex === 0
                                              ? shareRepresentative + 1
                                              : shareRepresentative,
                                  ),
                          }
                        : receiver,
                ),
            },
        });

        expect(result).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPrivacyRelationInvalid',
        });
        if (!result.ok) {
            expect(
                result.refusedObjects.some((refusal) =>
                    refusal.message.includes(
                        'Shamir quotient constraint is not exact',
                    ),
                ),
            ).toBe(true);
        }
    });
});
