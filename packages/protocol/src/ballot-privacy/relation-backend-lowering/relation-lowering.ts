import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { fieldModulus } from '../plaintext-oracle-helpers.js';
import { getBallotPrivacyEncodedShareVectorWidth } from '../protocol-parameters.js';
import {
    compileBallotPrivacyRelation,
    type BallotPrivacyRelationCompilerInput,
} from '../relation-compiler.js';

import { shouldUseCompactReceiverEncryptionWitnessColumns } from './backend-batches-and-bounds.js';
import type {
    BallotPrivacyAlgebraicRelationRow,
    BallotPrivacyLinearRelationBound,
    BallotPrivacyLoweredLinearRelationStatement,
    BallotPrivacyRelationBackendLoweringResult,
    BallotPrivacyRelationBackendPublicContext,
    VariableRegistry,
} from './backend-contracts.js';
import {
    createVariableRegistry,
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverEncryptionModulus,
    receiverEncryptionShortVectorInfinityNormBound,
    receiverOpeningRandomnessBitLength,
    receiverShareRepresentativeBitLength,
    relationStatementHashPurpose,
    relationStatementFormat,
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
    shareCommitmentModulus,
    shareCommitmentOpeningDimension,
    shareCommitmentOpeningInfinityNormBound,
} from './backend-contracts.js';
import {
    deriveAlgebraicTargetHash,
    referencesByReceiver,
} from './backend-row-helpers.js';
import {
    buildBackendStatement,
    explicitReceiverEncryptionRelationKeys,
    resolveCiphertextChunkCount,
} from './backend-statement-builder.js';
import {
    receiverEncryptionVariableNames,
    receiverOpeningVariableNames,
    receiverPayloadPlaintextBitVariableNames,
    receiverPayloadPlaintextOpeningVariableNames,
    receiverPayloadPlaintextShareVariableNames,
    receiverShareVariableNames,
} from './backend-variable-names.js';
import {
    addHashExpandedReceiverEncryptionNoiseVariable,
    addHashExpandedReceiverEncryptionRandomnessVariable,
    buildMembershipRows,
    buildReceiverPayloadPlaintextBindingRows,
    buildReceiverPayloadPlaintextBitDecompositionRows,
    buildShamirRows,
    receiverReferenceKey,
} from './relation-row-builders.js';

const buildAlgebraicRows = (
    input: {
        readonly publicContext: BallotPrivacyRelationBackendPublicContext;
        readonly relationInput: BallotPrivacyRelationCompilerInput;
    },
    registry: VariableRegistry,
): readonly BallotPrivacyAlgebraicRelationRow[] => {
    const rows: BallotPrivacyAlgebraicRelationRow[] = [];
    const encodedCoordinateCount = getBallotPrivacyEncodedShareVectorWidth(
        input.relationInput.optionCount,
    );
    const publicKeysByReceiver = referencesByReceiver(
        input.publicContext.receiverPublicKeys,
    );
    const payloadsByReceiver = referencesByReceiver(
        input.publicContext.receiverPayloads,
    );
    const commitmentsByReceiver = referencesByReceiver(
        input.publicContext.shareCommitments,
    );

    for (const receiver of input.relationInput.receivers) {
        const receiverKey = receiverReferenceKey(receiver);
        const publicKey = publicKeysByReceiver.get(receiverKey);
        const receiverPayload = payloadsByReceiver.get(receiverKey);
        const shareCommitment = commitmentsByReceiver.get(receiverKey);
        const receiverRosterPosition = receiver.receiverRosterPosition;
        const shareVariableNames = receiverShareVariableNames(
            registry,
            receiverRosterPosition,
            encodedCoordinateCount,
        );
        const openingVariableNames = receiverOpeningVariableNames(
            registry,
            receiverRosterPosition,
        );
        const payloadPlaintextShareVariableNames =
            receiverPayloadPlaintextShareVariableNames(
                registry,
                receiverRosterPosition,
                encodedCoordinateCount,
            );
        const payloadPlaintextOpeningVariableNames =
            receiverPayloadPlaintextOpeningVariableNames(
                registry,
                receiverRosterPosition,
            );
        const shareCommitmentPublicInputs = {
            commitmentBodyHash:
                shareCommitment?.commitmentBodyHash ??
                shareCommitment?.shareCommitmentHash ??
                input.publicContext.shareCommitmentProfileHash,
            commitmentPolynomialVectorHash:
                shareCommitment?.commitmentPolynomialVectorHash ??
                shareCommitment?.shareCommitmentHash ??
                input.publicContext.shareCommitmentProfileHash,
            shareCommitmentHash:
                shareCommitment?.shareCommitmentHash ??
                input.publicContext.shareCommitmentProfileHash,
            shareCommitmentProfileHash:
                input.publicContext.shareCommitmentProfileHash,
        };
        const receiverPayloadPublicInputs = {
            ciphertextBodyHash:
                receiverPayload?.ciphertextBodyHash ??
                receiverPayload?.receiverPayloadHash ??
                input.publicContext.receiverEncryptionProfileHash,
            ciphertextChunkHash:
                receiverPayload?.ciphertextChunkHash ??
                receiverPayload?.receiverPayloadCiphertextRoot ??
                input.publicContext.receiverEncryptionProfileHash,
            receiverPayloadCiphertextRoot:
                receiverPayload?.receiverPayloadCiphertextRoot ??
                input.publicContext.receiverEncryptionProfileHash,
            receiverPayloadHash:
                receiverPayload?.receiverPayloadHash ??
                input.publicContext.receiverEncryptionProfileHash,
        };
        const receiverKeyPublicInputs = {
            keyMaterialHash:
                publicKey?.keyMaterialHash ??
                publicKey?.receiverPublicKeyHash ??
                input.publicContext.receiverKeyRoot,
            publicMatrixSeedHash:
                publicKey?.publicMatrixSeedHash ??
                publicKey?.receiverPublicKeyHash ??
                input.publicContext.receiverKeyRoot,
            receiverKeyProofRoot: input.publicContext.receiverKeyProofRoot,
            receiverKeyRoot: input.publicContext.receiverKeyRoot,
            receiverPublicKeyHash:
                publicKey?.receiverPublicKeyHash ??
                input.publicContext.receiverKeyRoot,
        };
        const ciphertextChunkCount =
            resolveCiphertextChunkCount(receiverPayload);
        const hasExplicitReceiverEncryptionRows =
            publicKey?.publicKeyVector !== undefined &&
            publicKey.publicMatrixSeedHash !== undefined &&
            receiverPayload?.ciphertextChunks !== undefined;
        const plaintextBitLength =
            receiverPayload?.plaintextBitLength ??
            encodedCoordinateCount * receiverShareRepresentativeBitLength +
                shareCommitmentOpeningDimension *
                    receiverOpeningRandomnessBitLength;
        const payloadPlaintextBitVariableNames =
            hasExplicitReceiverEncryptionRows
                ? receiverPayloadPlaintextBitVariableNames(
                      registry,
                      receiverRosterPosition,
                      encodedCoordinateCount,
                      plaintextBitLength,
                  )
                : [];
        const encryptionVariableNames = hasExplicitReceiverEncryptionRows
            ? shouldUseCompactReceiverEncryptionWitnessColumns({
                  receiverCount: input.relationInput.receivers.length,
                  shareVectorWidth: encodedCoordinateCount,
              })
                ? []
                : receiverEncryptionVariableNames(
                      registry,
                      receiverRosterPosition,
                      ciphertextChunkCount,
                  )
            : [
                  addHashExpandedReceiverEncryptionRandomnessVariable(
                      registry,
                      receiverRosterPosition,
                  ),
                  addHashExpandedReceiverEncryptionNoiseVariable(
                      registry,
                      receiverRosterPosition,
                  ),
              ];

        rows.push({
            equationCount:
                shareCommitmentModuleRank * shareCommitmentModuleDegree,
            modulus: shareCommitmentModulus,
            publicInputHashes: shareCommitmentPublicInputs,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition,
            rowKind: 'ShareCommitmentEquation',
            rowName: `receiver_${receiverRosterPosition}_share_commitment_equation`,
            ...(shareCommitment?.commitmentPolynomialVector === undefined
                ? {}
                : {
                      shareCommitmentPolynomialVector:
                          shareCommitment.commitmentPolynomialVector,
                  }),
            targetHash: deriveAlgebraicTargetHash(
                'ballot-privacy-share-commitment-equation-target-v1',
                {
                    receiverIdentity: receiver.receiverIdentity,
                    receiverRosterPosition,
                    shareCommitmentPublicInputs,
                },
            ),
            variableNames: [...shareVariableNames, ...openingVariableNames],
        });
        rows.push({
            equationCount:
                ciphertextChunkCount *
                (receiverEncryptionModuleRank + 1) *
                receiverEncryptionModuleDegree,
            modulus: receiverEncryptionModulus,
            publicInputHashes: {
                ...receiverPayloadPublicInputs,
                ...receiverKeyPublicInputs,
            },
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition,
            rowKind: 'ReceiverPayloadEncryptionEquation',
            rowName: `receiver_${receiverRosterPosition}_receiver_payload_encryption_equation`,
            targetHash: deriveAlgebraicTargetHash(
                'ballot-privacy-receiver-payload-encryption-equation-target-v1',
                {
                    ciphertextChunkCount,
                    receiverIdentity: receiver.receiverIdentity,
                    receiverKeyPublicInputs,
                    receiverPayloadPublicInputs,
                    receiverRosterPosition,
                },
            ),
            variableNames: [
                ...payloadPlaintextShareVariableNames,
                ...payloadPlaintextOpeningVariableNames,
                ...payloadPlaintextBitVariableNames,
                ...encryptionVariableNames,
            ],
        });
        rows.push({
            equationCount:
                receiverEncryptionModuleRank * receiverEncryptionModuleDegree,
            modulus: receiverEncryptionModulus,
            publicInputHashes: receiverKeyPublicInputs,
            receiverIdentity: receiver.receiverIdentity,
            receiverRosterPosition,
            rowKind: 'ReceiverKeyBinding',
            rowName: `receiver_${receiverRosterPosition}_receiver_key_binding`,
            targetHash: deriveAlgebraicTargetHash(
                'ballot-privacy-receiver-key-binding-target-v1',
                {
                    receiverIdentity: receiver.receiverIdentity,
                    receiverKeyPublicInputs,
                    receiverRosterPosition,
                },
            ),
            variableNames: [],
        });
    }

    return rows;
};

const calculateCertifiedShamirQuotientBound = (input: {
    readonly pvssThreshold: number;
}): number => {
    const maximumFieldRepresentative = fieldModulus - 1;
    const maximumEvaluationBeforeReduction =
        maximumFieldRepresentative +
        (input.pvssThreshold - 1) *
            maximumFieldRepresentative *
            maximumFieldRepresentative;
    const maximumNumeratorMagnitude =
        maximumEvaluationBeforeReduction + maximumFieldRepresentative;

    return Math.ceil(maximumNumeratorMagnitude / fieldModulus);
};

const buildBounds = (
    input: BallotPrivacyRelationCompilerInput,
    registry: VariableRegistry,
): readonly BallotPrivacyLinearRelationBound[] => {
    const bounds: BallotPrivacyLinearRelationBound[] = [];
    const scoreBucketBounds: BallotPrivacyLinearRelationBound[] = [];
    const scalarFieldVariables: string[] = [];
    const coefficientFieldVariables: string[] = [];
    const receiverShareFieldVariables: string[] = [];
    const quotientVariables: string[] = [];
    const receiverPayloadPlaintextShareFieldVariables: string[] = [];
    const receiverPayloadPlaintextOpeningVariables: string[] = [];
    const receiverPayloadPlaintextBitVariables: string[] = [];
    const shareCommitmentOpeningVariables: string[] = [];
    const receiverEncryptionRandomnessVariables: string[] = [];
    const receiverEncryptionFirstNoiseVariables: string[] = [];
    const receiverEncryptionSecondNoiseVariables: string[] = [];
    const receiverEncryptionNoiseVariables: string[] = [];

    for (const variable of registry.values()) {
        if (variable.variableRole === 'ScoreBucketConstant') {
            scoreBucketBounds.push({
                boundKind: 'Boolean',
                boundName: `${variable.variableName}_boolean`,
                maximum: 1,
                minimum: 0,
                variableNames: [variable.variableName],
            });
        } else if (variable.variableRole === 'ScalarScoreConstant') {
            scalarFieldVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ShamirCoefficient') {
            coefficientFieldVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ReceiverShare') {
            receiverShareFieldVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ShamirQuotient') {
            quotientVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ReceiverPayloadPlaintextShare') {
            receiverPayloadPlaintextShareFieldVariables.push(
                variable.variableName,
            );
        } else if (
            variable.variableRole === 'ReceiverPayloadPlaintextOpening'
        ) {
            receiverPayloadPlaintextOpeningVariables.push(
                variable.variableName,
            );
        } else if (variable.variableRole === 'ReceiverPayloadPlaintextBit') {
            receiverPayloadPlaintextBitVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ShareCommitmentOpening') {
            shareCommitmentOpeningVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ReceiverEncryptionRandomness') {
            receiverEncryptionRandomnessVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ReceiverEncryptionFirstNoise') {
            receiverEncryptionFirstNoiseVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ReceiverEncryptionSecondNoise') {
            receiverEncryptionSecondNoiseVariables.push(variable.variableName);
        } else if (variable.variableRole === 'ReceiverEncryptionNoise') {
            receiverEncryptionNoiseVariables.push(variable.variableName);
        }
    }

    bounds.push(...scoreBucketBounds);
    for (const [boundName, variableNames] of [
        ['scalar_score_constants_canonical', scalarFieldVariables],
        ['shamir_coefficients_canonical', coefficientFieldVariables],
        ['receiver_shares_canonical', receiverShareFieldVariables],
        [
            'receiver_payload_plaintext_shares_canonical',
            receiverPayloadPlaintextShareFieldVariables,
        ],
    ] as const) {
        bounds.push({
            boundKind: 'CanonicalFieldElement',
            boundName,
            maximum: fieldModulus - 1,
            minimum: 0,
            variableNames,
        });
    }
    bounds.push({
        absoluteMaximum: calculateCertifiedShamirQuotientBound(input),
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName: 'shamir_quotients_certified_absolute_bound',
        variableNames: quotientVariables,
    });
    bounds.push({
        absoluteMaximum: shareCommitmentOpeningInfinityNormBound,
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName: 'share_commitment_openings_certified_absolute_bound',
        variableNames: shareCommitmentOpeningVariables,
    });
    bounds.push({
        absoluteMaximum: shareCommitmentOpeningInfinityNormBound,
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName:
            'receiver_payload_plaintext_openings_certified_absolute_bound',
        variableNames: receiverPayloadPlaintextOpeningVariables,
    });
    bounds.push({
        boundKind: 'Boolean',
        boundName: 'receiver_payload_plaintext_bits_boolean',
        maximum: 1,
        minimum: 0,
        variableNames: receiverPayloadPlaintextBitVariables,
    });
    bounds.push({
        absoluteMaximum: receiverEncryptionShortVectorInfinityNormBound,
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName: 'receiver_encryption_randomness_certified_absolute_bound',
        variableNames: receiverEncryptionRandomnessVariables,
    });
    bounds.push({
        absoluteMaximum: receiverEncryptionShortVectorInfinityNormBound,
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName: 'receiver_encryption_first_noise_certified_absolute_bound',
        variableNames: receiverEncryptionFirstNoiseVariables,
    });
    bounds.push({
        absoluteMaximum: receiverEncryptionShortVectorInfinityNormBound,
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName: 'receiver_encryption_second_noise_certified_absolute_bound',
        variableNames: receiverEncryptionSecondNoiseVariables,
    });
    bounds.push({
        absoluteMaximum: receiverEncryptionShortVectorInfinityNormBound,
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName: 'receiver_encryption_noise_certified_absolute_bound',
        variableNames: receiverEncryptionNoiseVariables,
    });

    return bounds;
};

const deriveRelationStatementHash = (
    statementPayload: Omit<
        BallotPrivacyLoweredLinearRelationStatement,
        'relationStatementHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        purpose: relationStatementHashPurpose,
        statementPayload,
    });

export const lowerBallotPrivacyRelationToBackendStatement = (input: {
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
}): BallotPrivacyRelationBackendLoweringResult => {
    const relationCompilation = compileBallotPrivacyRelation(
        input.relationInput,
    );

    if (!relationCompilation.ok) {
        return relationCompilation;
    }

    const registry = createVariableRegistry();
    const hasExplicitReceiverEncryptionMaterial =
        explicitReceiverEncryptionRelationKeys({
            publicContext: input.publicContext,
            receivers: input.relationInput.receivers,
        }).size > 0;
    const linearRows = [
        ...buildMembershipRows(input.relationInput, registry),
        ...buildShamirRows(input.relationInput, registry),
        ...buildReceiverPayloadPlaintextBindingRows(
            input.relationInput,
            registry,
        ),
        ...(hasExplicitReceiverEncryptionMaterial
            ? buildReceiverPayloadPlaintextBitDecompositionRows(
                  input.relationInput,
                  registry,
              )
            : []),
    ];
    const algebraicRows = buildAlgebraicRows(input, registry);
    const bounds = buildBounds(input.relationInput, registry);
    const variables = registry.values();
    const backendStatement = buildBackendStatement({
        algebraicRows,
        bounds,
        encodedCoordinateCount: relationCompilation.encodedCoordinateCount,
        linearRows,
        optionCount: relationCompilation.optionCount,
        publicContext: input.publicContext,
        pvssThreshold: relationCompilation.pvssThreshold,
        receivers: input.relationInput.receivers,
        rosterSize: relationCompilation.rosterSize,
        shareCommitmentProfileHash:
            input.publicContext.shareCommitmentProfileHash,
        shareVectorWidth: relationCompilation.shareVectorWidth,
        variables,
    });
    const statementPayload: Omit<
        BallotPrivacyLoweredLinearRelationStatement,
        'relationStatementHash'
    > = {
        algebraicRows,
        backendStatement,
        bounds,
        encodedCoordinateCount: relationCompilation.encodedCoordinateCount,
        fieldModulus,
        linearRows,
        objectType: 'BallotPrivacyLinearRelationStatement',
        objectVersion: 1,
        optionCount: relationCompilation.optionCount,
        publicContext: input.publicContext,
        pvssThreshold: relationCompilation.pvssThreshold,
        relationLabel: relationCompilation.relationLabel,
        relationStatementFormat,
        rosterSize: relationCompilation.rosterSize,
        shareVectorWidth: relationCompilation.shareVectorWidth,
        variables,
    };

    return {
        ok: true,
        statement: {
            ...statementPayload,
            relationStatementHash:
                deriveRelationStatementHash(statementPayload),
        },
    };
};
