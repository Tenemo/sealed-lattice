import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotProofComponentId,
    BallotProofComponentProofRecord,
    BallotProofRecord,
    BallotProofStatement,
    ProtocolDigest,
    RefusalRecord,
} from '@sealed-lattice/types';

import { createRefusal } from '../../common/verification-helpers.js';
import { getBallotPrivacyEncodedShareVectorWidth } from '../encoded-share-layout.js';

import type {
    BallotProofComponentProofVerificationInput,
    UnknownObject,
} from './object-contracts.js';
import {
    ballotProofComponentProofPolicyById,
    collectReceiverReferenceRefusals,
    deriveBallotProofChallengeDigest,
    deriveBallotProofRecordDigest,
    deriveBallotProofStatementDigest,
    deriveProofBytesDigest,
    isUnknownObject,
    omitProperty,
    omitUnknownObjectProperty,
    proofBytesHexPattern,
    protocolDigestPattern,
    unsignedDecimalStringPattern,
} from './object-contracts.js';

const collectBallotProofStructuralRefusals = (
    statement: BallotProofStatement,
    ballotProof: BallotProofRecord,
    proofBytesHex?: string,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const statementPayload = omitProperty(
        statement,
        'ballotProofStatementDigest',
    );
    const expectedStatementDigest =
        deriveBallotProofStatementDigest(statementPayload);
    const proofPayload = omitProperty(ballotProof, 'ballotProofRecordDigest');
    const expectedProofRecordDigest =
        deriveBallotProofRecordDigest(proofPayload);
    const expectedChallengeDigest = deriveBallotProofChallengeDigest({
        backendStatementDigest: ballotProof.backendStatementDigest,
        componentBundleStatementDigest:
            ballotProof.componentBundleStatementDigest,
        componentProofBundleDigest: ballotProof.componentProofBundleDigest,
        proofBytesDigest: ballotProof.proofBytesDigest,
        proofEncodingProfileDigest: ballotProof.proofEncodingProfileDigest,
        proofParameterSetDigest: ballotProof.proofParameterSetDigest,
        proofRoot: ballotProof.proofRoot,
        publicRandomnessDigest: ballotProof.publicRandomnessDigest,
        relationStatementDigest: ballotProof.relationStatementDigest,
        linearStatementDigest: ballotProof.linearStatementDigest,
        statementMatrixDigest: ballotProof.statementMatrixDigest,
        statement,
        targetVectorDigest: ballotProof.targetVectorDigest,
    });

    if (
        statement.objectType !== 'BallotProofStatement' ||
        statement.objectVersion !== 1 ||
        statement.shareVectorWidth !==
            getBallotPrivacyEncodedShareVectorWidth(statement.optionCount)
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof statement has an invalid canonical shape.',
                statement.ballotProofStatementDigest,
            ),
        );
    }
    if (statement.ballotProofStatementDigest !== expectedStatementDigest) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof statement digest does not match its canonical payload.',
                statement.ballotProofStatementDigest,
            ),
        );
    }
    refusedObjects.push(
        ...collectReceiverReferenceRefusals({
            label: 'Ballot proof receiver-key references',
            objectDigest: statement.ballotProofStatementDigest,
            references: statement.receiverPublicKeys,
        }),
        ...collectReceiverReferenceRefusals({
            label: 'Ballot proof receiver-payload references',
            objectDigest: statement.ballotProofStatementDigest,
            references: statement.receiverPayloads,
        }),
        ...collectReceiverReferenceRefusals({
            label: 'Ballot proof share-commitment references',
            objectDigest: statement.ballotProofStatementDigest,
            references: statement.shareCommitments,
        }),
    );
    if (
        statement.receiverPublicKeys.length === 0 ||
        statement.receiverPublicKeys.length !==
            statement.receiverPayloads.length ||
        statement.receiverPublicKeys.length !==
            statement.shareCommitments.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof statement must bind the same non-empty receiver set across keys, payloads, and commitments.',
                statement.ballotProofStatementDigest,
            ),
        );
    }
    if (
        ballotProof.objectType !== 'BallotProofRecord' ||
        ballotProof.objectVersion !== 1 ||
        ballotProof.proofBackend !== 'LocalLinearLatticeRelation' ||
        (ballotProof.backendStatementDigest !== undefined &&
            !protocolDigestPattern.test(ballotProof.backendStatementDigest)) ||
        (ballotProof.componentBundleStatementDigest !== undefined &&
            !protocolDigestPattern.test(
                ballotProof.componentBundleStatementDigest,
            )) ||
        (ballotProof.componentProofBundleDigest !== undefined &&
            !protocolDigestPattern.test(
                ballotProof.componentProofBundleDigest,
            )) ||
        !protocolDigestPattern.test(ballotProof.relationStatementDigest) ||
        (ballotProof.linearStatementDigest !== undefined &&
            !protocolDigestPattern.test(ballotProof.linearStatementDigest)) ||
        (ballotProof.statementMatrixDigest !== undefined &&
            !protocolDigestPattern.test(ballotProof.statementMatrixDigest)) ||
        (ballotProof.targetVectorDigest !== undefined &&
            !protocolDigestPattern.test(ballotProof.targetVectorDigest)) ||
        !protocolDigestPattern.test(ballotProof.proofRoot) ||
        !protocolDigestPattern.test(ballotProof.proofBytesDigest) ||
        (ballotProof.proofEncodingProfileDigest !== undefined &&
            !protocolDigestPattern.test(
                ballotProof.proofEncodingProfileDigest,
            )) ||
        (ballotProof.proofParameterSetDigest !== undefined &&
            !protocolDigestPattern.test(ballotProof.proofParameterSetDigest)) ||
        (ballotProof.publicRandomnessDigest !== undefined &&
            !protocolDigestPattern.test(ballotProof.publicRandomnessDigest)) ||
        !Number.isSafeInteger(ballotProof.proofSizeBytes) ||
        ballotProof.proofSizeBytes <= 0
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record has an invalid canonical shape.',
                ballotProof.ballotProofRecordDigest,
            ),
        );
    }
    const proofBackendMetadataFieldNames = [
        'backendStatementDigest',
        'linearStatementDigest',
        'statementMatrixDigest',
        'targetVectorDigest',
        'proofEncodingProfileDigest',
        'proofParameterSetDigest',
        'publicRandomnessDigest',
    ] as const;
    const presentProofBackendMetadataFieldCount =
        proofBackendMetadataFieldNames.filter(
            (fieldName) => ballotProof[fieldName] !== undefined,
        ).length;
    if (
        presentProofBackendMetadataFieldCount > 0 &&
        presentProofBackendMetadataFieldCount !==
            proofBackendMetadataFieldNames.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof backend metadata must be complete when any backend proof field is present.',
                ballotProof.ballotProofRecordDigest,
            ),
        );
    }
    if (
        ballotProof.ballotProofStatementDigest !==
        statement.ballotProofStatementDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record is not bound to the supplied statement.',
                ballotProof.ballotProofRecordDigest,
            ),
        );
    }
    if (
        ballotProof.ballotProofProfileDigest !==
        statement.ballotProofProfileDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record is not bound to the statement proof profile.',
                ballotProof.ballotProofRecordDigest,
            ),
        );
    }
    if (ballotProof.challengeDigest !== expectedChallengeDigest) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof challenge digest does not match the statement and proof roots.',
                ballotProof.ballotProofRecordDigest,
            ),
        );
    }
    if (ballotProof.ballotProofRecordDigest !== expectedProofRecordDigest) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record digest does not match its canonical payload.',
                ballotProof.ballotProofRecordDigest,
            ),
        );
    }
    if (proofBytesHex !== undefined) {
        if (!proofBytesHexPattern.test(proofBytesHex)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot proof bytes must be non-empty lowercase hexadecimal bytes.',
                    ballotProof.ballotProofRecordDigest,
                ),
            );
        } else {
            const proofSizeBytes = proofBytesHex.length / 2;
            const proofBytesDigest = deriveProofBytesDigest({
                proofBytesHex,
            });
            if (proofSizeBytes !== ballotProof.proofSizeBytes) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Ballot proof byte length does not match the proof record.',
                        ballotProof.ballotProofRecordDigest,
                    ),
                );
            }
            if (proofBytesDigest !== ballotProof.proofBytesDigest) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Ballot proof bytes do not match the proof record digest.',
                        ballotProof.ballotProofRecordDigest,
                    ),
                );
            }
        }
    }

    return refusedObjects;
};

const deriveSuppliedComponentProofStatementDigest = (input: {
    readonly proofStatement: UnknownObject;
    readonly proofStatementFormat: BallotProofComponentProofVerificationInput['proofStatementFormat'];
}): { readonly digest?: ProtocolDigest; readonly digestFieldName?: string } => {
    const objectType = input.proofStatement.objectType;

    if (
        input.proofStatementFormat ===
            'dense-polynomial-matrix-linear-proof-v1' &&
        objectType === 'BallotProofLinearProofStatement'
    ) {
        return {
            digest: deriveProtocolDigest('ChallengeDomainDigest', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'statementDigest',
                ),
                purpose: 'ballot-proof-linear-proof-statement-v1',
            }),
            digestFieldName: 'statementDigest',
        };
    }
    if (
        input.proofStatementFormat ===
            'sparse-polynomial-matrix-linear-proof-v1' &&
        objectType === 'BallotProofSparseComponentLinearProofStatement'
    ) {
        return {
            digest: deriveProtocolDigest('ChallengeDomainDigest', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'statementDigest',
                ),
                purpose: 'ballot-proof-sparse-linear-proof-statement-v1',
            }),
            digestFieldName: 'statementDigest',
        };
    }
    if (
        input.proofStatementFormat ===
            'structured-module-sis-share-commitment-v1' &&
        objectType === 'BallotProofStructuredShareCommitmentProofStatement'
    ) {
        return {
            digest: deriveProtocolDigest('ChallengeDomainDigest', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'statementDigest',
                ),
                purpose:
                    'ballot-proof-structured-share-commitment-proof-statement-v1',
            }),
            digestFieldName: 'statementDigest',
        };
    }
    if (
        input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1' &&
        objectType === 'BallotProofStructuredReceiverEncryptionProofStatement'
    ) {
        return {
            digest: deriveProtocolDigest('ChallengeDomainDigest', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'statementDigest',
                ),
                purpose:
                    'ballot-proof-structured-receiver-encryption-proof-statement-v1',
            }),
            digestFieldName: 'statementDigest',
        };
    }
    if (
        (input.proofStatementFormat ===
            'structured-module-sis-share-commitment-v1' ||
            input.proofStatementFormat ===
                'structured-module-lwe-linear-proof-v1' ||
            input.proofStatementFormat ===
                'public-zero-witness-binding-check-v1') &&
        objectType === 'BallotProofComponentProofStatementPlan'
    ) {
        return {
            digest: deriveProtocolDigest('ChallengeDomainDigest', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'componentProofStatementDigest',
                ),
                purpose: 'ballot-proof-component-proof-statement-plan-v1',
            }),
            digestFieldName: 'componentProofStatementDigest',
        };
    }

    return {};
};

const isProtocolDigestValue = (value: unknown): value is ProtocolDigest =>
    typeof value === 'string' && protocolDigestPattern.test(value);

const isUnsignedDecimalString = (value: unknown): value is string =>
    typeof value === 'string' && unsignedDecimalStringPattern.test(value);

const isNonNegativeSafeInteger = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

const isPositiveSafeInteger = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value > 0;

const isStringArray = (value: unknown): value is readonly string[] => {
    if (!Array.isArray(value)) {
        return false;
    }

    return value.every((entry: unknown) => typeof entry === 'string');
};

const isProtocolDigestArray = (
    value: unknown,
): value is readonly ProtocolDigest[] => {
    if (!Array.isArray(value)) {
        return false;
    }

    return value.every((entry: unknown) => isProtocolDigestValue(entry));
};

const isNonNegativeIntegerArray = (
    value: unknown,
): value is readonly number[] => {
    if (!Array.isArray(value)) {
        return false;
    }

    return value.every((entry: unknown) => isNonNegativeSafeInteger(entry));
};

const collectComponentProofStatementPlanShapeRefusals = (input: {
    readonly expectedComponentId: BallotProofComponentId;
    readonly proofRecordDigest: ProtocolDigest;
    readonly proofStatement: UnknownObject;
}): readonly RefusalRecord[] => {
    const componentProofPolicy =
        ballotProofComponentProofPolicyById[input.expectedComponentId];
    if (
        input.proofStatement.objectType !==
        'BallotProofComponentProofStatementPlan'
    ) {
        return [];
    }

    const rowBatchNames = input.proofStatement.rowBatchNames;
    const rowBatchMatrixDigests = input.proofStatement.rowBatchMatrixDigests;
    const rowBatchTargetVectorDigests =
        input.proofStatement.rowBatchTargetVectorDigests;
    const rowBatchTermCounts = input.proofStatement.rowBatchTermCounts;
    const variableColumnIndices = input.proofStatement.variableColumnIndices;
    const rowBatchCount =
        Array.isArray(rowBatchNames) && rowBatchNames.length > 0
            ? rowBatchNames.length
            : undefined;
    const rowBatchFieldsMatch =
        rowBatchCount !== undefined &&
        Array.isArray(rowBatchMatrixDigests) &&
        rowBatchMatrixDigests.length === rowBatchCount &&
        Array.isArray(rowBatchTargetVectorDigests) &&
        rowBatchTargetVectorDigests.length === rowBatchCount &&
        Array.isArray(rowBatchTermCounts) &&
        rowBatchTermCounts.length === rowBatchCount;
    const commonShapeIsValid =
        input.proofStatement.objectVersion === 1 &&
        input.proofStatement.componentId === input.expectedComponentId &&
        input.proofStatement.proofStatementFormat ===
            componentProofPolicy.proofStatementFormat &&
        input.proofStatement.proofBytesAvailability ===
            componentProofPolicy.proofBytesAvailability &&
        input.proofStatement.proofLoweringStatus === 'explicitRowsAvailable' &&
        input.proofStatement.relation === 'A*w + t = 0' &&
        isUnsignedDecimalString(input.proofStatement.coefficientModulus) &&
        isProtocolDigestValue(input.proofStatement.backendStatementDigest) &&
        isProtocolDigestValue(
            input.proofStatement.componentProofStatementDigest,
        ) &&
        isProtocolDigestValue(input.proofStatement.componentStatementDigest) &&
        isProtocolDigestValue(input.proofStatement.matrixDigest) &&
        isProtocolDigestValue(input.proofStatement.relationStatementDigest) &&
        isProtocolDigestValue(input.proofStatement.targetVectorDigest) &&
        isProtocolDigestArray(rowBatchMatrixDigests) &&
        isStringArray(rowBatchNames) &&
        isProtocolDigestArray(rowBatchTargetVectorDigests) &&
        Array.isArray(rowBatchTermCounts) &&
        rowBatchTermCounts.every(isUnsignedDecimalString) &&
        rowBatchFieldsMatch &&
        isPositiveSafeInteger(input.proofStatement.rowCount) &&
        isNonNegativeSafeInteger(input.proofStatement.variableColumnCount) &&
        isNonNegativeIntegerArray(variableColumnIndices);

    const componentSpecificShapeIsValid = (() => {
        if (
            input.expectedComponentId === 'receiver-encryption-component' &&
            componentProofPolicy.proofStatementFormat ===
                'structured-module-lwe-linear-proof-v1'
        ) {
            return (
                input.proofStatement.sourceRingDegree === 256 &&
                input.proofStatement.proofSystemRingDegree === 64 &&
                isUnsignedDecimalString(
                    input.proofStatement.denseCoefficientCount,
                ) &&
                input.proofStatement.sparseTermCount === null &&
                isPositiveSafeInteger(
                    input.proofStatement.structuredCiphertextChunkCount,
                ) &&
                isPositiveSafeInteger(
                    input.proofStatement.structuredReceiverCount,
                ) &&
                isUnsignedDecimalString(
                    input.proofStatement.structuredWitnessTermCount,
                ) &&
                input.proofStatement.structuredWitnessTermCount !== '0' &&
                Number(input.proofStatement.variableColumnCount) > 0 &&
                Array.isArray(variableColumnIndices) &&
                variableColumnIndices.length ===
                    input.proofStatement.variableColumnCount
            );
        }
        if (
            input.expectedComponentId === 'receiver-key-binding-component' &&
            componentProofPolicy.proofStatementFormat ===
                'public-zero-witness-binding-check-v1'
        ) {
            return (
                input.proofStatement.sourceRingDegree === null &&
                input.proofStatement.proofSystemRingDegree === null &&
                input.proofStatement.denseCoefficientCount === null &&
                input.proofStatement.sparseTermCount === null &&
                input.proofStatement.structuredCiphertextChunkCount === null &&
                input.proofStatement.structuredReceiverCount === null &&
                input.proofStatement.structuredWitnessTermCount === null &&
                input.proofStatement.variableColumnCount === 0 &&
                Array.isArray(variableColumnIndices) &&
                variableColumnIndices.length === 0 &&
                Array.isArray(rowBatchTermCounts) &&
                rowBatchTermCounts.every((termCount) => termCount === '0')
            );
        }

        return true;
    })();

    if (!commonShapeIsValid || !componentSpecificShapeIsValid) {
        return [
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement plan for ${input.expectedComponentId} has an invalid canonical shape.`,
                input.proofRecordDigest,
            ),
        ];
    }

    return [];
};

const collectSuppliedComponentProofStatementRefusals = (input: {
    readonly componentProof: BallotProofComponentProofRecord;
    readonly expectedComponentId: BallotProofComponentId;
    readonly proofInput: BallotProofComponentProofVerificationInput;
    readonly proofRecordDigest: ProtocolDigest;
}): readonly RefusalRecord[] => {
    const proofStatement = input.proofInput.proofStatement;
    if (proofStatement === undefined) {
        return [];
    }
    if (!isUnknownObject(proofStatement)) {
        return [
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement object for ${input.expectedComponentId} is malformed.`,
                input.proofRecordDigest,
            ),
        ];
    }

    const refusedObjects: RefusalRecord[] = [];
    refusedObjects.push(
        ...collectComponentProofStatementPlanShapeRefusals({
            expectedComponentId: input.expectedComponentId,
            proofRecordDigest: input.proofRecordDigest,
            proofStatement,
        }),
    );
    const suppliedFormat = proofStatement.proofStatementFormat;
    const suppliedComponentId = proofStatement.componentId;
    const suppliedComponentStatementDigest =
        proofStatement.componentStatementDigest;
    const suppliedStatementDigest = proofStatement.statementDigest;
    const suppliedComponentProofStatementDigest =
        proofStatement.componentProofStatementDigest;
    const derivedStatementDigest = deriveSuppliedComponentProofStatementDigest({
        proofStatement,
        proofStatementFormat: input.proofInput.proofStatementFormat,
    });

    if (derivedStatementDigest.digest === undefined) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement object for ${input.expectedComponentId} does not match its declared statement format.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        suppliedFormat !== undefined &&
        suppliedFormat !== input.proofInput.proofStatementFormat
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement format for ${input.expectedComponentId} does not match the supplied proof input.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        suppliedComponentId !== undefined &&
        suppliedComponentId !== input.expectedComponentId
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement for ${input.expectedComponentId} is bound to the wrong component.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        suppliedComponentStatementDigest !== undefined &&
        suppliedComponentStatementDigest !==
            input.componentProof.componentStatementDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement for ${input.expectedComponentId} is not bound to the component statement.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        derivedStatementDigest.digestFieldName === 'statementDigest' &&
        suppliedStatementDigest !== derivedStatementDigest.digest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement digest for ${input.expectedComponentId} does not match its canonical payload.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        derivedStatementDigest.digestFieldName ===
            'componentProofStatementDigest' &&
        suppliedComponentProofStatementDigest !== derivedStatementDigest.digest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement digest for ${input.expectedComponentId} does not match its canonical payload.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        derivedStatementDigest.digest !== undefined &&
        input.proofInput.componentProofStatementDigest !==
            derivedStatementDigest.digest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement for ${input.expectedComponentId} does not match the supplied proof input digest.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        derivedStatementDigest.digest !== undefined &&
        input.componentProof.componentProofStatementDigest !==
            derivedStatementDigest.digest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement for ${input.expectedComponentId} does not match the proof record digest.`,
                input.proofRecordDigest,
            ),
        );
    }

    return refusedObjects;
};

export {
    collectBallotProofStructuralRefusals,
    collectSuppliedComponentProofStatementRefusals,
};
