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
    deriveBallotProofComponentProofBundleDigest,
    deriveBallotProofComponentProofRecordDigest,
    deriveBallotProofComponentProofRoot,
    deriveBallotProofEncodingProfileDigest,
    deriveBallotProofParameterSetDigest,
    deriveBallotProofPublicRandomnessDigest,
    deriveProofBytesDigest,
    deriveReceiverPayloadCiphertextRoot,
    deriveReceiverPayloadDigest,
    hasOwnProperty,
    omitProperty,
    proofBytesHexAllowEmptyPattern,
    proofBytesHexPattern,
    protocolDigestPattern,
    requiredBallotProofComponentIds,
    expectedComponentProofStatementFormatLabel,
} from './object-contracts.js';
import { digestForInvalidComponentInput } from './proof-shell-builders.js';

function collectBallotProofComponentProofInputRefusals(input: {
    readonly ballotProof: BallotProofRecord;
    readonly componentProofBundle: BallotProofComponentProofBundle;
    readonly componentProofInputs?: readonly BallotProofComponentProofVerificationInput[];
}): readonly RefusalRecord[] {
    const refusedObjects: RefusalRecord[] = [];
    const proofRecordDigest = input.ballotProof.ballotProofRecordDigest;

    if (input.componentProofInputs === undefined) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Full encoded-score ballot proof verification requires public proof inputs for every component proof.',
                proofRecordDigest,
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
                proofRecordDigest,
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
                    proofRecordDigest,
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
                    proofRecordDigest,
                ),
            );
            continue;
        }
        if (proofInput.componentId !== componentProof.componentId) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} is not bound to the matching proof record.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            !protocolDigestPattern.test(
                proofInput.componentProofStatementDigest ?? '',
            )
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} must be bound to a component proof statement digest.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            proofInput.componentProofStatementDigest !==
            componentProof.componentProofStatementDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof statement for ${expectedComponentId} does not match the proof record.`,
                    proofRecordDigest,
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
                    proofRecordDigest,
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
                    proofRecordDigest,
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
                        proofRecordDigest,
                    ),
                );
            }
        } else if (!proofBytesHexPattern.test(proofInput.proofBytesHex)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof bytes for ${expectedComponentId} must be non-empty lowercase hexadecimal bytes.`,
                    proofRecordDigest,
                ),
            );
            continue;
        }
        if (!proofBytesPattern.test(proofInput.proofBytesHex)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof bytes for ${expectedComponentId} must be lowercase hexadecimal bytes.`,
                    proofRecordDigest,
                ),
            );
            continue;
        }
        const proofBytesDigest = deriveProofBytesDigest({
            allowEmpty: proofBytesMustBeEmpty,
            proofBytesHex: proofInput.proofBytesHex,
        });
        const proofSizeBytes = proofInput.proofBytesHex.length / 2;
        const proofEncodingProfileDigest =
            deriveBallotProofEncodingProfileDigest({
                proofEncoding: proofInput.proofEncoding,
            });
        const proofParameterSetDigest = deriveBallotProofParameterSetDigest({
            parameterSet: proofInput.proofParameterSet,
        });
        const publicRandomnessDigest = (() => {
            try {
                return deriveBallotProofPublicRandomnessDigest({
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
                    proofRecordDigest,
                ),
            );
        }
        if (proofBytesDigest !== componentProof.proofBytesDigest) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof bytes for ${expectedComponentId} do not match the proof record digest.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            proofEncodingProfileDigest !==
            componentProof.proofEncodingProfileDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof encoding for ${expectedComponentId} does not match the proof record.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            proofParameterSetDigest !== componentProof.proofParameterSetDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof parameter set for ${expectedComponentId} does not match the proof record.`,
                    proofRecordDigest,
                ),
            );
        }
        if (publicRandomnessDigest === undefined) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component public randomness for ${expectedComponentId} must be 32 lowercase hexadecimal bytes.`,
                    proofRecordDigest,
                ),
            );
        } else if (
            publicRandomnessDigest !== componentProof.publicRandomnessDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component public randomness for ${expectedComponentId} does not match the proof record.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            proofInput.statementDigest !==
            componentProof.componentStatementDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} is not bound to the component statement.`,
                    proofRecordDigest,
                ),
            );
        }
        if (proofInput.proofStatement === undefined) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} must supply its public proof statement object.`,
                    proofRecordDigest,
                ),
            );
        }
        const expectedProofRoot = deriveBallotProofComponentProofRoot({
            componentId: expectedComponentId,
            componentProofStatementDigest: protocolDigestPattern.test(
                proofInput.componentProofStatementDigest ?? '',
            )
                ? proofInput.componentProofStatementDigest
                : digestForInvalidComponentInput(),
            componentStatementDigest: componentProof.componentStatementDigest,
            proofBytesDigest,
            proofEncodingProfileDigest,
            proofParameterSetDigest,
            proofStatementFormat: proofInput.proofStatementFormat,
            publicRandomnessDigest:
                publicRandomnessDigest ?? digestForInvalidComponentInput(),
            statementDigest: proofInput.statementDigest,
        });
        if (
            publicRandomnessDigest !== undefined &&
            componentProof.proofRoot !== expectedProofRoot
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof root for ${expectedComponentId} does not match the supplied public proof input.`,
                    proofRecordDigest,
                ),
            );
        }
        refusedObjects.push(
            ...collectSuppliedComponentProofStatementRefusals({
                componentProof,
                expectedComponentId,
                proofInput,
                proofRecordDigest,
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
    const proofRecordDigest = input.ballotProof.ballotProofRecordDigest;
    const componentProofBundleDigest =
        input.componentProofBundle?.componentProofBundleDigest;

    if (
        input.ballotProof.componentProofBundleDigest !== undefined &&
        input.componentProofBundle === undefined
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record references a component proof bundle that was not supplied.',
                proofRecordDigest,
            ),
        );

        return refusedObjects;
    }
    if (
        input.componentProofBundle !== undefined &&
        input.ballotProof.componentProofBundleDigest === undefined
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Supplied component proof bundle is not bound by the ballot proof record.',
                proofRecordDigest,
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
        'componentProofBundleDigest',
    );
    const expectedProofBundleDigest =
        deriveBallotProofComponentProofBundleDigest(proofBundlePayload);
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
        !protocolDigestPattern.test(
            input.componentProofBundle.componentProofBundleDigest,
        ) ||
        !protocolDigestPattern.test(
            input.componentProofBundle.componentBundleStatementDigest,
        ) ||
        !protocolDigestPattern.test(
            input.componentProofBundle.backendStatementDigest,
        ) ||
        !protocolDigestPattern.test(
            input.componentProofBundle.relationStatementDigest,
        ) ||
        !protocolDigestPattern.test(
            input.componentProofBundle.ballotProofStatementDigest ?? '',
        ) ||
        !requiredComponentIdsMatch
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle has an invalid canonical shape.',
                proofRecordDigest,
            ),
        );
    }
    if (componentProofBundleDigest !== expectedProofBundleDigest) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle digest does not match its canonical payload.',
                proofRecordDigest,
            ),
        );
    }
    if (
        input.ballotProof.componentProofBundleDigest !==
        componentProofBundleDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record is not bound to the supplied component proof bundle.',
                proofRecordDigest,
            ),
        );
    }
    if (
        input.componentProofBundle.componentBundleStatementDigest !==
            input.ballotProof.componentBundleStatementDigest ||
        input.componentProofBundle.backendStatementDigest !==
            input.ballotProof.backendStatementDigest ||
        input.componentProofBundle.relationStatementDigest !==
            input.ballotProof.relationStatementDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle is not bound to the supplied proof statement roots.',
                proofRecordDigest,
            ),
        );
    }
    if (
        input.componentProofBundle.ballotProofStatementDigest !==
        input.statement.ballotProofStatementDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle is not bound to the supplied ballot proof statement.',
                proofRecordDigest,
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
                proofRecordDigest,
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
                    proofRecordDigest,
                ),
            );
        }
        seenComponentIds.add(componentProof.componentId);

        const componentProofPayload = omitProperty(
            componentProof,
            'componentProofRecordDigest',
        );
        const expectedComponentProofDigest =
            deriveBallotProofComponentProofRecordDigest(componentProofPayload);
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
            !protocolDigestPattern.test(
                componentProof.componentProofRecordDigest,
            ) ||
            !protocolDigestPattern.test(
                componentProof.componentStatementDigest,
            ) ||
            !protocolDigestPattern.test(
                componentProof.backendStatementDigest,
            ) ||
            !protocolDigestPattern.test(
                componentProof.relationStatementDigest,
            ) ||
            !protocolDigestPattern.test(componentProof.proofRoot) ||
            !protocolDigestPattern.test(componentProof.proofBytesDigest) ||
            !protocolDigestPattern.test(
                componentProof.proofEncodingProfileDigest,
            ) ||
            !protocolDigestPattern.test(
                componentProof.proofParameterSetDigest,
            ) ||
            !protocolDigestPattern.test(
                componentProof.publicRandomnessDigest,
            ) ||
            !protocolDigestPattern.test(
                componentProof.componentProofStatementDigest ?? '',
            ) ||
            !protocolDigestPattern.test(
                componentProof.ballotProofStatementDigest ?? '',
            ) ||
            !proofSizeBytesIsValid
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof for ${expectedComponentId} has an invalid canonical shape.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            componentProof.componentProofRecordDigest !==
            expectedComponentProofDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof digest for ${expectedComponentId} does not match its canonical payload.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            componentProof.backendStatementDigest !==
                input.componentProofBundle.backendStatementDigest ||
            componentProof.relationStatementDigest !==
                input.componentProofBundle.relationStatementDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof for ${expectedComponentId} is not bound to the supplied relation and backend statement.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            componentProof.ballotProofStatementDigest !==
            input.statement.ballotProofStatementDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof for ${expectedComponentId} is not bound to the supplied ballot proof statement.`,
                    proofRecordDigest,
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
    const payloadWithoutDigest = omitProperty(payload, 'receiverPayloadDigest');
    const payloadWithoutRoots = omitProperty(
        payloadWithoutDigest,
        'receiverPayloadCiphertextRoot',
    );
    const expectedCiphertextRoot = deriveReceiverPayloadCiphertextRoot({
        ceremonyId: payload.ceremonyId,
        ciphertextBodyDigest: payload.ciphertextBodyDigest,
        manifestDigest: payload.manifestDigest,
        payloadContextDigest: payload.payloadContextDigest,
        receiverEncryptionProfileDigest:
            payload.receiverEncryptionProfileDigest,
        receiverIdentity: payload.receiverIdentity,
        receiverPublicKeyDigest: payload.receiverPublicKeyDigest,
        receiverRosterPosition: payload.receiverRosterPosition,
    });
    const expectedPayloadDigest = deriveReceiverPayloadDigest({
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
        payload.receiverPayloadDigest !== expectedPayloadDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver payload shell digest or shape is invalid.',
                payload.receiverPayloadDigest,
            ),
        );
    }
    for (const forbiddenField of forbiddenWitnessFields) {
        if (hasOwnProperty(payload, forbiddenField)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver payload shell must not expose witness material.',
                    payload.receiverPayloadDigest,
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
