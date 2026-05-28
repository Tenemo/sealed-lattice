import type {
    BallotProofComponentId,
    BallotProofComponentProofBundle,
    BallotProofRecord,
    BallotProofStatement,
    ReceiverPayload,
    RefusalRecord,
} from '@sealed-lattice/types';

import { createRefusal } from '../../common/verification-helpers.js';

import { collectSuppliedComponentProofStatementRefusals } from './ballot-proof-structure-checks.js';
import type { BallotProofComponentProofVerificationInput } from './object-contracts.js';
import {
    allowedBallotProofComponentStatementFormats,
    componentProofBytesMustBeEmpty,
    componentProofStatementFormatIsExpected,
    deriveBallotProofComponentProofBundleHash,
    deriveBallotProofComponentProofRecordHash,
    deriveBallotProofComponentProofRoot,
    deriveBallotProofEncodingProfileHash,
    deriveBallotProofParameterSetHash,
    deriveBallotProofPublicRandomnessHash,
    deriveProofBytesHash,
    deriveReceiverPayloadCiphertextRoot,
    deriveReceiverPayloadHash,
    hasOwnProperty,
    omitProperty,
    proofBytesHexAllowEmptyPattern,
    proofBytesHexPattern,
    protocolHashPattern,
    requiredBallotProofComponentIds,
    expectedComponentProofStatementFormatLabel,
} from './object-contracts.js';
import { hashForInvalidComponentInput } from './proof-shell-builders.js';

function collectBallotProofComponentProofInputRefusals(input: {
    readonly ballotProof: BallotProofRecord;
    readonly componentProofBundle: BallotProofComponentProofBundle;
    readonly componentProofInputs?: readonly BallotProofComponentProofVerificationInput[];
}): readonly RefusalRecord[] {
    const refusedObjects: RefusalRecord[] = [];
    const proofRecordHash = input.ballotProof.ballotProofRecordHash;

    if (input.componentProofInputs === undefined) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Full encoded-score ballot proof verification requires public proof inputs for every component proof.',
                proofRecordHash,
            ),
        );

        return refusedObjects;
    }
    if (
        input.componentProofInputs.length !==
        requiredBallotProofComponentIds.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof inputs must contain exactly the required components.',
                proofRecordHash,
            ),
        );
    }

    const proofInputsByComponent = new Map<
        BallotProofComponentId,
        BallotProofComponentProofVerificationInput
    >();
    for (const proofInput of input.componentProofInputs) {
        if (proofInputsByComponent.has(proofInput.componentId)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot proof component proof inputs contain a duplicate component.',
                    proofRecordHash,
                ),
            );
        }
        proofInputsByComponent.set(proofInput.componentId, proofInput);
    }

    for (
        let componentIndex = 0;
        componentIndex < requiredBallotProofComponentIds.length;
        componentIndex += 1
    ) {
        const expectedComponentId =
            requiredBallotProofComponentIds[componentIndex];
        const componentProof =
            input.componentProofBundle.componentProofs[componentIndex];
        const proofInput = proofInputsByComponent.get(expectedComponentId);
        if (componentProof === undefined || proofInput === undefined) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} is missing.`,
                    proofRecordHash,
                ),
            );
            continue;
        }
        if (proofInput.componentId !== componentProof.componentId) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} is not bound to the matching proof record.`,
                    proofRecordHash,
                ),
            );
        }
        if (
            !protocolHashPattern.test(
                proofInput.componentProofStatementHash ?? '',
            )
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} must be bound to a component proof statement hash.`,
                    proofRecordHash,
                ),
            );
        }
        if (
            proofInput.componentProofStatementHash !==
            componentProof.componentProofStatementHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof statement for ${expectedComponentId} does not match the proof record.`,
                    proofRecordHash,
                ),
            );
        }
        if (
            !allowedBallotProofComponentStatementFormats.has(
                proofInput.proofStatementFormat,
            )
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof statement format for ${expectedComponentId} is not supported.`,
                    proofRecordHash,
                ),
            );
        }
        if (
            !componentProofStatementFormatIsExpected(
                expectedComponentId,
                proofInput.proofStatementFormat,
            )
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof statement format for ${expectedComponentId} must be ${expectedComponentProofStatementFormatLabel(expectedComponentId)}.`,
                    proofRecordHash,
                ),
            );
        }
        const proofBytesMustBeEmpty =
            componentProofBytesMustBeEmpty(expectedComponentId);
        const proofBytesPattern = proofBytesMustBeEmpty
            ? proofBytesHexAllowEmptyPattern
            : proofBytesHexPattern;
        if (proofBytesMustBeEmpty) {
            if (proofInput.proofBytesHex !== '') {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        `Ballot proof component proof bytes for ${expectedComponentId} must be empty for the public-zero witness binding check.`,
                        proofRecordHash,
                    ),
                );
            }
        } else if (!proofBytesHexPattern.test(proofInput.proofBytesHex)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof bytes for ${expectedComponentId} must be non-empty lowercase hexadecimal bytes.`,
                    proofRecordHash,
                ),
            );
            continue;
        }
        if (!proofBytesPattern.test(proofInput.proofBytesHex)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof bytes for ${expectedComponentId} must be lowercase hexadecimal bytes.`,
                    proofRecordHash,
                ),
            );
            continue;
        }
        const proofBytesHash = deriveProofBytesHash({
            allowEmpty: proofBytesMustBeEmpty,
            proofBytesHex: proofInput.proofBytesHex,
        });
        const proofSizeBytes = proofInput.proofBytesHex.length / 2;
        const proofEncodingProfileHash = deriveBallotProofEncodingProfileHash({
            proofEncoding: proofInput.proofEncoding,
        });
        const proofParameterSetHash = deriveBallotProofParameterSetHash({
            parameterSet: proofInput.proofParameterSet,
        });
        const publicRandomnessHash = (() => {
            try {
                return deriveBallotProofPublicRandomnessHash({
                    publicRandomnessHex: proofInput.publicRandomnessHex,
                });
            } catch {
                return undefined;
            }
        })();

        if (proofSizeBytes !== componentProof.proofSizeBytes) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof byte length for ${expectedComponentId} does not match the proof record.`,
                    proofRecordHash,
                ),
            );
        }
        if (proofBytesHash !== componentProof.proofBytesHash) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof bytes for ${expectedComponentId} do not match the proof record hash.`,
                    proofRecordHash,
                ),
            );
        }
        if (
            proofEncodingProfileHash !== componentProof.proofEncodingProfileHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof encoding for ${expectedComponentId} does not match the proof record.`,
                    proofRecordHash,
                ),
            );
        }
        if (proofParameterSetHash !== componentProof.proofParameterSetHash) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof parameter set for ${expectedComponentId} does not match the proof record.`,
                    proofRecordHash,
                ),
            );
        }
        if (publicRandomnessHash === undefined) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component public randomness for ${expectedComponentId} must be 32 lowercase hexadecimal bytes.`,
                    proofRecordHash,
                ),
            );
        } else if (
            publicRandomnessHash !== componentProof.publicRandomnessHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component public randomness for ${expectedComponentId} does not match the proof record.`,
                    proofRecordHash,
                ),
            );
        }
        if (
            proofInput.statementHash !== componentProof.componentStatementHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} is not bound to the component statement.`,
                    proofRecordHash,
                ),
            );
        }
        if (proofInput.proofStatement === undefined) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} must supply its public proof statement object.`,
                    proofRecordHash,
                ),
            );
        }
        const expectedProofRoot = deriveBallotProofComponentProofRoot({
            componentId: expectedComponentId,
            componentProofStatementHash: protocolHashPattern.test(
                proofInput.componentProofStatementHash ?? '',
            )
                ? proofInput.componentProofStatementHash
                : hashForInvalidComponentInput(),
            componentStatementHash: componentProof.componentStatementHash,
            proofBytesHash,
            proofEncodingProfileHash,
            proofParameterSetHash,
            proofStatementFormat: proofInput.proofStatementFormat,
            publicRandomnessHash:
                publicRandomnessHash ?? hashForInvalidComponentInput(),
            statementHash: proofInput.statementHash,
        });
        if (
            publicRandomnessHash !== undefined &&
            componentProof.proofRoot !== expectedProofRoot
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof root for ${expectedComponentId} does not match the supplied public proof input.`,
                    proofRecordHash,
                ),
            );
        }
        refusedObjects.push(
            ...collectSuppliedComponentProofStatementRefusals({
                componentProof,
                expectedComponentId,
                proofInput,
                proofRecordHash,
            }),
        );
    }

    return refusedObjects;
}

const collectBallotProofComponentProofBundleRefusals = (input: {
    readonly statement: BallotProofStatement;
    readonly ballotProof: BallotProofRecord;
    readonly componentProofBundle?: BallotProofComponentProofBundle;
    readonly componentProofInputs?: readonly BallotProofComponentProofVerificationInput[];
}): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const proofRecordHash = input.ballotProof.ballotProofRecordHash;
    const componentProofBundleHash =
        input.componentProofBundle?.componentProofBundleHash;

    if (
        input.ballotProof.componentProofBundleHash !== undefined &&
        input.componentProofBundle === undefined
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record references a component proof bundle that was not supplied.',
                proofRecordHash,
            ),
        );

        return refusedObjects;
    }
    if (
        input.componentProofBundle !== undefined &&
        input.ballotProof.componentProofBundleHash === undefined
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Supplied component proof bundle is not bound by the ballot proof record.',
                proofRecordHash,
            ),
        );
    }
    if (input.componentProofBundle === undefined) {
        return refusedObjects;
    }
    refusedObjects.push(
        ...collectBallotProofComponentProofInputRefusals({
            ballotProof: input.ballotProof,
            componentProofBundle: input.componentProofBundle,
            componentProofInputs: input.componentProofInputs,
        }),
    );

    const proofBundlePayload = omitProperty(
        input.componentProofBundle,
        'componentProofBundleHash',
    );
    const expectedProofBundleHash =
        deriveBallotProofComponentProofBundleHash(proofBundlePayload);
    const requiredComponentIdsMatch =
        input.componentProofBundle.requiredComponentIds.length ===
            requiredBallotProofComponentIds.length &&
        input.componentProofBundle.requiredComponentIds.every(
            (componentId, componentIndex) =>
                componentId === requiredBallotProofComponentIds[componentIndex],
        );

    if (
        input.componentProofBundle.objectType !==
            'BallotProofComponentProofBundle' ||
        input.componentProofBundle.objectVersion !== 1 ||
        input.componentProofBundle.bundleCoverage !==
            'full-encoded-score-ballot-relation' ||
        !protocolHashPattern.test(
            input.componentProofBundle.componentProofBundleHash,
        ) ||
        !protocolHashPattern.test(
            input.componentProofBundle.componentBundleStatementHash,
        ) ||
        !protocolHashPattern.test(
            input.componentProofBundle.backendStatementHash,
        ) ||
        !protocolHashPattern.test(
            input.componentProofBundle.relationStatementHash,
        ) ||
        !protocolHashPattern.test(
            input.componentProofBundle.ballotProofStatementHash ?? '',
        ) ||
        !requiredComponentIdsMatch
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle has an invalid canonical shape.',
                proofRecordHash,
            ),
        );
    }
    if (componentProofBundleHash !== expectedProofBundleHash) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle hash does not match its canonical payload.',
                proofRecordHash,
            ),
        );
    }
    if (
        input.ballotProof.componentProofBundleHash !== componentProofBundleHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record is not bound to the supplied component proof bundle.',
                proofRecordHash,
            ),
        );
    }
    if (
        input.componentProofBundle.componentBundleStatementHash !==
            input.ballotProof.componentBundleStatementHash ||
        input.componentProofBundle.backendStatementHash !==
            input.ballotProof.backendStatementHash ||
        input.componentProofBundle.relationStatementHash !==
            input.ballotProof.relationStatementHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle is not bound to the supplied proof statement roots.',
                proofRecordHash,
            ),
        );
    }
    if (
        input.componentProofBundle.ballotProofStatementHash !==
        input.statement.ballotProofStatementHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle is not bound to the supplied ballot proof statement.',
                proofRecordHash,
            ),
        );
    }
    if (
        input.componentProofBundle.componentProofs.length !==
        requiredBallotProofComponentIds.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle must contain exactly the required component proofs.',
                proofRecordHash,
            ),
        );
    }

    const seenComponentIds = new Set<string>();
    for (
        let componentIndex = 0;
        componentIndex < requiredBallotProofComponentIds.length;
        componentIndex += 1
    ) {
        const expectedComponentId =
            requiredBallotProofComponentIds[componentIndex];
        const componentProof =
            input.componentProofBundle.componentProofs[componentIndex];
        if (componentProof === undefined) {
            continue;
        }
        if (seenComponentIds.has(componentProof.componentId)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot proof component proof bundle contains a duplicate component proof.',
                    proofRecordHash,
                ),
            );
        }
        seenComponentIds.add(componentProof.componentId);

        const componentProofPayload = omitProperty(
            componentProof,
            'componentProofRecordHash',
        );
        const expectedComponentProofHash =
            deriveBallotProofComponentProofRecordHash(componentProofPayload);
        const proofSizeBytesIsValid =
            Number.isSafeInteger(componentProof.proofSizeBytes) &&
            (componentProofBytesMustBeEmpty(expectedComponentId)
                ? componentProof.proofSizeBytes === 0
                : componentProof.proofSizeBytes > 0);

        if (
            componentProof.objectType !== 'BallotProofComponentProofRecord' ||
            componentProof.objectVersion !== 1 ||
            componentProof.componentId !== expectedComponentId ||
            componentProof.proofBackend !== 'LocalLinearLatticeRelation' ||
            !protocolHashPattern.test(
                componentProof.componentProofRecordHash,
            ) ||
            !protocolHashPattern.test(componentProof.componentStatementHash) ||
            !protocolHashPattern.test(componentProof.backendStatementHash) ||
            !protocolHashPattern.test(componentProof.relationStatementHash) ||
            !protocolHashPattern.test(componentProof.proofRoot) ||
            !protocolHashPattern.test(componentProof.proofBytesHash) ||
            !protocolHashPattern.test(
                componentProof.proofEncodingProfileHash,
            ) ||
            !protocolHashPattern.test(componentProof.proofParameterSetHash) ||
            !protocolHashPattern.test(componentProof.publicRandomnessHash) ||
            !protocolHashPattern.test(
                componentProof.componentProofStatementHash ?? '',
            ) ||
            !protocolHashPattern.test(
                componentProof.ballotProofStatementHash ?? '',
            ) ||
            !proofSizeBytesIsValid
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof for ${expectedComponentId} has an invalid canonical shape.`,
                    proofRecordHash,
                ),
            );
        }
        if (
            componentProof.componentProofRecordHash !==
            expectedComponentProofHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof hash for ${expectedComponentId} does not match its canonical payload.`,
                    proofRecordHash,
                ),
            );
        }
        if (
            componentProof.backendStatementHash !==
                input.componentProofBundle.backendStatementHash ||
            componentProof.relationStatementHash !==
                input.componentProofBundle.relationStatementHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof for ${expectedComponentId} is not bound to the supplied relation and backend statement.`,
                    proofRecordHash,
                ),
            );
        }
        if (
            componentProof.ballotProofStatementHash !==
            input.statement.ballotProofStatementHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof for ${expectedComponentId} is not bound to the supplied ballot proof statement.`,
                    proofRecordHash,
                ),
            );
        }
    }

    return refusedObjects;
};

const collectReceiverPayloadStructuralRefusals = (
    payload: ReceiverPayload,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const payloadWithoutHash = omitProperty(payload, 'receiverPayloadHash');
    const payloadWithoutRoots = omitProperty(
        payloadWithoutHash,
        'receiverPayloadCiphertextRoot',
    );
    const expectedCiphertextRoot = deriveReceiverPayloadCiphertextRoot({
        ceremonyId: payload.ceremonyId,
        ciphertextBodyHash: payload.ciphertextBodyHash,
        manifestHash: payload.manifestHash,
        payloadContextHash: payload.payloadContextHash,
        receiverEncryptionProfileHash: payload.receiverEncryptionProfileHash,
        receiverIdentity: payload.receiverIdentity,
        receiverPublicKeyHash: payload.receiverPublicKeyHash,
        receiverRosterPosition: payload.receiverRosterPosition,
    });
    const expectedPayloadHash = deriveReceiverPayloadHash({
        ...payloadWithoutRoots,
        receiverPayloadCiphertextRoot: payload.receiverPayloadCiphertextRoot,
    });
    const forbiddenWitnessFields = [
        'receiverShareVector',
        'shareCommitmentOpening',
        'receiverEncryptionRandomness',
        'receiverEncryptionNoise',
        'proofWitness',
    ];

    if (
        payload.objectType !== 'ReceiverPayload' ||
        payload.objectVersion !== 1 ||
        payload.receiverPayloadCiphertextRoot !== expectedCiphertextRoot ||
        payload.receiverPayloadHash !== expectedPayloadHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver payload shell hash or shape is invalid.',
                payload.receiverPayloadHash,
            ),
        );
    }
    for (const forbiddenField of forbiddenWitnessFields) {
        if (hasOwnProperty(payload, forbiddenField)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver payload shell must not expose witness material.',
                    payload.receiverPayloadHash,
                ),
            );
            break;
        }
    }

    return refusedObjects;
};

export {
    collectBallotProofComponentProofBundleRefusals,
    collectReceiverPayloadStructuralRefusals,
};
