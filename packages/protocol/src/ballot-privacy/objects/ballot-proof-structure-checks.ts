import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    BallotPrivacyRosterProfileEvidence,
    BallotProofComponentId,
    BallotProofComponentProofRecord,
    BallotProofRecord,
    BallotProofStatement,
    ProtocolHash,
    RefusalRecord,
} from '@sealed-lattice/types';

import { createRefusal } from '../../common/verification-helpers.js';
import { getBallotPrivacyEncodedShareVectorWidth } from '../protocol-parameters.js';
import { collectBallotPrivacyDimensionRefusals } from '../supported-dimensions.js';

import type {
    BallotProofComponentProofVerificationInput,
    UnknownObject,
} from './object-contracts.js';
import {
    allowedBallotProofComponentStatementFormats,
    collectReceiverReferenceRefusals,
    componentProofBytesAvailabilityIsExpected,
    componentProofStatementFormatIsExpected,
    deriveBallotProofChallengeHash,
    deriveBallotProofRecordHash,
    deriveBallotProofStatementHash,
    deriveProofBytesHash,
    isUnknownObject,
    omitProperty,
    omitUnknownObjectProperty,
    proofBytesHexPattern,
    protocolHashPattern,
    unsignedDecimalStringPattern,
} from './object-contracts.js';

const collectBallotProofStructuralRefusals = (
    statement: BallotProofStatement,
    ballotProof: BallotProofRecord,
    proofBytesHex?: string,
    options: {
        readonly casualMicroRosterAcknowledged?: boolean;
        readonly claimBearingPackage?: boolean;
        readonly dynamicRosterProfileEvidence?: BallotPrivacyRosterProfileEvidence;
        readonly unsafeSmallRosterAcknowledged?: boolean;
    } = {},
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const statementPayload = omitProperty(
        statement,
        'ballotProofStatementHash',
    );
    const expectedStatementHash =
        deriveBallotProofStatementHash(statementPayload);
    const proofPayload = omitProperty(ballotProof, 'ballotProofRecordHash');
    const expectedProofRecordHash = deriveBallotProofRecordHash(proofPayload);
    const expectedChallengeHash = deriveBallotProofChallengeHash({
        backendStatementHash: ballotProof.backendStatementHash,
        componentBundleStatementHash: ballotProof.componentBundleStatementHash,
        componentProofBundleHash: ballotProof.componentProofBundleHash,
        proofBytesHash: ballotProof.proofBytesHash,
        proofEncodingProfileHash: ballotProof.proofEncodingProfileHash,
        proofParameterSetHash: ballotProof.proofParameterSetHash,
        proofRoot: ballotProof.proofRoot,
        publicRandomnessHash: ballotProof.publicRandomnessHash,
        relationStatementHash: ballotProof.relationStatementHash,
        linearStatementHash: ballotProof.linearStatementHash,
        statementMatrixHash: ballotProof.statementMatrixHash,
        statement,
        targetVectorHash: ballotProof.targetVectorHash,
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
                statement.ballotProofStatementHash,
            ),
        );
    }
    if (statement.ballotProofStatementHash !== expectedStatementHash) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof statement hash does not match its canonical payload.',
                statement.ballotProofStatementHash,
            ),
        );
    }
    refusedObjects.push(
        ...collectBallotPrivacyDimensionRefusals({
            objectHash: statement.ballotProofStatementHash,
            optionCount: statement.optionCount,
            participantCount: statement.receiverPublicKeys.length,
            shareVectorWidth: statement.shareVectorWidth,
            casualMicroRosterAcknowledged:
                options.casualMicroRosterAcknowledged,
            claimBearingPackage: options.claimBearingPackage,
            dynamicRosterProfileEvidence: options.dynamicRosterProfileEvidence,
            thresholdProfileHash: statement.thresholdProfileHash,
            unsafeSmallRosterAcknowledged:
                options.unsafeSmallRosterAcknowledged,
        }),
    );
    refusedObjects.push(
        ...collectReceiverReferenceRefusals({
            label: 'Ballot proof receiver-key references',
            objectHash: statement.ballotProofStatementHash,
            references: statement.receiverPublicKeys,
        }),
        ...collectReceiverReferenceRefusals({
            label: 'Ballot proof receiver-payload references',
            objectHash: statement.ballotProofStatementHash,
            references: statement.receiverPayloads,
        }),
        ...collectReceiverReferenceRefusals({
            label: 'Ballot proof share-commitment references',
            objectHash: statement.ballotProofStatementHash,
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
                statement.ballotProofStatementHash,
            ),
        );
    }
    if (
        ballotProof.objectType !== 'BallotProofRecord' ||
        ballotProof.objectVersion !== 1 ||
        ballotProof.proofBackend !== 'LocalLinearLatticeRelation' ||
        (ballotProof.backendStatementHash !== undefined &&
            !protocolHashPattern.test(ballotProof.backendStatementHash)) ||
        (ballotProof.componentBundleStatementHash !== undefined &&
            !protocolHashPattern.test(
                ballotProof.componentBundleStatementHash,
            )) ||
        (ballotProof.componentProofBundleHash !== undefined &&
            !protocolHashPattern.test(ballotProof.componentProofBundleHash)) ||
        !protocolHashPattern.test(ballotProof.relationStatementHash) ||
        (ballotProof.linearStatementHash !== undefined &&
            !protocolHashPattern.test(ballotProof.linearStatementHash)) ||
        (ballotProof.statementMatrixHash !== undefined &&
            !protocolHashPattern.test(ballotProof.statementMatrixHash)) ||
        (ballotProof.targetVectorHash !== undefined &&
            !protocolHashPattern.test(ballotProof.targetVectorHash)) ||
        !protocolHashPattern.test(ballotProof.proofRoot) ||
        !protocolHashPattern.test(ballotProof.proofBytesHash) ||
        (ballotProof.proofEncodingProfileHash !== undefined &&
            !protocolHashPattern.test(ballotProof.proofEncodingProfileHash)) ||
        (ballotProof.proofParameterSetHash !== undefined &&
            !protocolHashPattern.test(ballotProof.proofParameterSetHash)) ||
        (ballotProof.publicRandomnessHash !== undefined &&
            !protocolHashPattern.test(ballotProof.publicRandomnessHash)) ||
        !Number.isSafeInteger(ballotProof.proofSizeBytes) ||
        ballotProof.proofSizeBytes <= 0
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record has an invalid canonical shape.',
                ballotProof.ballotProofRecordHash,
            ),
        );
    }
    const proofBackendMetadataFieldNames = [
        'backendStatementHash',
        'linearStatementHash',
        'statementMatrixHash',
        'targetVectorHash',
        'proofEncodingProfileHash',
        'proofParameterSetHash',
        'publicRandomnessHash',
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
                ballotProof.ballotProofRecordHash,
            ),
        );
    }
    if (
        ballotProof.ballotProofStatementHash !==
        statement.ballotProofStatementHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record is not bound to the supplied statement.',
                ballotProof.ballotProofRecordHash,
            ),
        );
    }
    if (
        ballotProof.ballotProofProfileHash !== statement.ballotProofProfileHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record is not bound to the statement proof profile.',
                ballotProof.ballotProofRecordHash,
            ),
        );
    }
    if (ballotProof.challengeHash !== expectedChallengeHash) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof challenge hash does not match the statement and proof roots.',
                ballotProof.ballotProofRecordHash,
            ),
        );
    }
    if (ballotProof.ballotProofRecordHash !== expectedProofRecordHash) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record hash does not match its canonical payload.',
                ballotProof.ballotProofRecordHash,
            ),
        );
    }
    if (proofBytesHex !== undefined) {
        if (!proofBytesHexPattern.test(proofBytesHex)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot proof bytes must be non-empty lowercase hexadecimal bytes.',
                    ballotProof.ballotProofRecordHash,
                ),
            );
        } else {
            const proofSizeBytes = proofBytesHex.length / 2;
            const proofBytesHash = deriveProofBytesHash({
                proofBytesHex,
            });
            if (proofSizeBytes !== ballotProof.proofSizeBytes) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Ballot proof byte length does not match the proof record.',
                        ballotProof.ballotProofRecordHash,
                    ),
                );
            }
            if (proofBytesHash !== ballotProof.proofBytesHash) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Ballot proof bytes do not match the proof record hash.',
                        ballotProof.ballotProofRecordHash,
                    ),
                );
            }
        }
    }

    return refusedObjects;
};

const deriveSuppliedComponentProofStatementHash = (input: {
    readonly proofStatement: UnknownObject;
    readonly proofStatementFormat: BallotProofComponentProofVerificationInput['proofStatementFormat'];
}): { readonly hash?: ProtocolHash; readonly hashFieldName?: string } => {
    const objectType = input.proofStatement.objectType;

    if (
        input.proofStatementFormat ===
            'dense-polynomial-matrix-linear-proof-v1' &&
        objectType === 'BallotProofLinearProofStatement'
    ) {
        return {
            hash: deriveProtocolHash('ChallengeDomainHash', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'statementHash',
                ),
                purpose: 'ballot-proof-linear-proof-statement-v1',
            }),
            hashFieldName: 'statementHash',
        };
    }
    if (
        input.proofStatementFormat ===
            'sparse-polynomial-matrix-linear-proof-v1' &&
        objectType === 'BallotProofSparseComponentLinearProofStatement'
    ) {
        return {
            hash: deriveProtocolHash('ChallengeDomainHash', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'statementHash',
                ),
                purpose: 'ballot-proof-sparse-linear-proof-statement-v1',
            }),
            hashFieldName: 'statementHash',
        };
    }
    if (
        input.proofStatementFormat ===
            'structured-module-sis-share-commitment-v1' &&
        objectType === 'BallotProofStructuredShareCommitmentProofStatement'
    ) {
        return {
            hash: deriveProtocolHash('ChallengeDomainHash', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'statementHash',
                ),
                purpose:
                    'ballot-proof-structured-share-commitment-proof-statement-v1',
            }),
            hashFieldName: 'statementHash',
        };
    }
    if (
        input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1' &&
        objectType === 'BallotProofStructuredReceiverEncryptionProofStatement'
    ) {
        return {
            hash: deriveProtocolHash('ChallengeDomainHash', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'statementHash',
                ),
                purpose:
                    'ballot-proof-structured-receiver-encryption-proof-statement-v1',
            }),
            hashFieldName: 'statementHash',
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
            hash: deriveProtocolHash('ChallengeDomainHash', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'componentProofStatementHash',
                ),
                purpose: 'ballot-proof-component-proof-statement-plan-v1',
            }),
            hashFieldName: 'componentProofStatementHash',
        };
    }

    return {};
};

const isProtocolHashValue = (value: unknown): value is ProtocolHash =>
    typeof value === 'string' && protocolHashPattern.test(value);

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

const isProtocolHashArray = (
    value: unknown,
): value is readonly ProtocolHash[] => {
    if (!Array.isArray(value)) {
        return false;
    }

    return value.every((entry: unknown) => isProtocolHashValue(entry));
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
    readonly proofRecordHash: ProtocolHash;
    readonly proofStatement: UnknownObject;
}): readonly RefusalRecord[] => {
    if (
        input.proofStatement.objectType !==
        'BallotProofComponentProofStatementPlan'
    ) {
        return [];
    }

    const rowBatchNames = input.proofStatement.rowBatchNames;
    const rowBatchMatrixHashes = input.proofStatement.rowBatchMatrixHashes;
    const rowBatchTargetVectorHashes =
        input.proofStatement.rowBatchTargetVectorHashes;
    const rowBatchTermCounts = input.proofStatement.rowBatchTermCounts;
    const variableColumnIndices = input.proofStatement.variableColumnIndices;
    const rowBatchCount =
        Array.isArray(rowBatchNames) && rowBatchNames.length > 0
            ? rowBatchNames.length
            : undefined;
    const rowBatchFieldsMatch =
        rowBatchCount !== undefined &&
        Array.isArray(rowBatchMatrixHashes) &&
        rowBatchMatrixHashes.length === rowBatchCount &&
        Array.isArray(rowBatchTargetVectorHashes) &&
        rowBatchTargetVectorHashes.length === rowBatchCount &&
        Array.isArray(rowBatchTermCounts) &&
        rowBatchTermCounts.length === rowBatchCount;
    const commonShapeIsValid =
        input.proofStatement.objectVersion === 1 &&
        input.proofStatement.componentId === input.expectedComponentId &&
        typeof input.proofStatement.proofStatementFormat === 'string' &&
        allowedBallotProofComponentStatementFormats.has(
            input.proofStatement
                .proofStatementFormat as BallotProofComponentProofVerificationInput['proofStatementFormat'],
        ) &&
        componentProofStatementFormatIsExpected(
            input.expectedComponentId,
            input.proofStatement
                .proofStatementFormat as BallotProofComponentProofVerificationInput['proofStatementFormat'],
        ) &&
        typeof input.proofStatement.proofBytesAvailability === 'string' &&
        componentProofBytesAvailabilityIsExpected(
            input.expectedComponentId,
            input.proofStatement
                .proofStatementFormat as BallotProofComponentProofVerificationInput['proofStatementFormat'],
            input.proofStatement.proofBytesAvailability,
        ) &&
        input.proofStatement.proofLoweringStatus === 'explicitRowsAvailable' &&
        input.proofStatement.relation === 'A*w + t = 0' &&
        isUnsignedDecimalString(input.proofStatement.coefficientModulus) &&
        isProtocolHashValue(input.proofStatement.backendStatementHash) &&
        isProtocolHashValue(input.proofStatement.componentProofStatementHash) &&
        isProtocolHashValue(input.proofStatement.componentStatementHash) &&
        isProtocolHashValue(input.proofStatement.matrixHash) &&
        isProtocolHashValue(input.proofStatement.relationStatementHash) &&
        isProtocolHashValue(input.proofStatement.targetVectorHash) &&
        isProtocolHashArray(rowBatchMatrixHashes) &&
        isStringArray(rowBatchNames) &&
        isProtocolHashArray(rowBatchTargetVectorHashes) &&
        Array.isArray(rowBatchTermCounts) &&
        rowBatchTermCounts.every(isUnsignedDecimalString) &&
        rowBatchFieldsMatch &&
        isPositiveSafeInteger(input.proofStatement.rowCount) &&
        isNonNegativeSafeInteger(input.proofStatement.variableColumnCount) &&
        isNonNegativeIntegerArray(variableColumnIndices);

    const componentSpecificShapeIsValid = (() => {
        if (
            input.expectedComponentId === 'receiver-encryption-component' &&
            input.proofStatement.proofStatementFormat ===
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
            input.proofStatement.proofStatementFormat ===
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
                input.proofRecordHash,
            ),
        ];
    }

    return [];
};

const collectSuppliedComponentProofStatementRefusals = (input: {
    readonly componentProof: BallotProofComponentProofRecord;
    readonly expectedComponentId: BallotProofComponentId;
    readonly proofInput: BallotProofComponentProofVerificationInput;
    readonly proofRecordHash: ProtocolHash;
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
                input.proofRecordHash,
            ),
        ];
    }

    const refusedObjects: RefusalRecord[] = [];
    refusedObjects.push(
        ...collectComponentProofStatementPlanShapeRefusals({
            expectedComponentId: input.expectedComponentId,
            proofRecordHash: input.proofRecordHash,
            proofStatement,
        }),
    );
    const suppliedFormat = proofStatement.proofStatementFormat;
    const suppliedComponentId = proofStatement.componentId;
    const suppliedComponentStatementHash =
        proofStatement.componentStatementHash;
    const suppliedStatementHash = proofStatement.statementHash;
    const suppliedComponentProofStatementHash =
        proofStatement.componentProofStatementHash;
    const derivedStatementHash = deriveSuppliedComponentProofStatementHash({
        proofStatement,
        proofStatementFormat: input.proofInput.proofStatementFormat,
    });

    if (derivedStatementHash.hash === undefined) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement object for ${input.expectedComponentId} does not match its declared statement format.`,
                input.proofRecordHash,
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
                input.proofRecordHash,
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
                input.proofRecordHash,
            ),
        );
    }
    if (
        suppliedComponentStatementHash !== undefined &&
        suppliedComponentStatementHash !==
            input.componentProof.componentStatementHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement for ${input.expectedComponentId} is not bound to the component statement.`,
                input.proofRecordHash,
            ),
        );
    }
    if (
        derivedStatementHash.hashFieldName === 'statementHash' &&
        suppliedStatementHash !== derivedStatementHash.hash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement hash for ${input.expectedComponentId} does not match its canonical payload.`,
                input.proofRecordHash,
            ),
        );
    }
    if (
        derivedStatementHash.hashFieldName === 'componentProofStatementHash' &&
        suppliedComponentProofStatementHash !== derivedStatementHash.hash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement hash for ${input.expectedComponentId} does not match its canonical payload.`,
                input.proofRecordHash,
            ),
        );
    }
    if (
        derivedStatementHash.hash !== undefined &&
        input.proofInput.componentProofStatementHash !==
            derivedStatementHash.hash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement for ${input.expectedComponentId} does not match the supplied proof input hash.`,
                input.proofRecordHash,
            ),
        );
    }
    if (
        derivedStatementHash.hash !== undefined &&
        input.componentProof.componentProofStatementHash !==
            derivedStatementHash.hash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement for ${input.expectedComponentId} does not match the proof record hash.`,
                input.proofRecordHash,
            ),
        );
    }

    return refusedObjects;
};

export {
    collectBallotProofStructuralRefusals,
    collectSuppliedComponentProofStatementRefusals,
};
