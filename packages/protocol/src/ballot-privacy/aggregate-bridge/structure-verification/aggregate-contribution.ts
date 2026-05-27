import { verifySignedObjectSignature } from '@sealed-lattice/crypto';
import {
    encryptedAggregateBridgeProfileId,
    type ActionContext,
    type AggregateContribution,
    type AggregateContributionVerification,
    type BridgeProofRecord,
    type ProtocolSignatureEnvelope,
    type RefusalRecord,
} from '@sealed-lattice/types';

import { signedObjectRootByteLength } from '../../../common/verification-helpers.js';
import {
    createAggregateRefusal,
    protocolDigestPattern,
} from '../../aggregate-derivation/constants.js';
import {
    deriveAggregateContributionDigest,
    deriveBridgeProofProfileDigest,
    deriveBridgeProofRecordDigest,
} from '../digests.js';

import {
    bridgeDigestFieldNames,
    collectDigestShapeRefusals,
    collectForbiddenWitnessFieldRefusals,
    contributionDigestFieldNames,
    type AggregateContributionFromBridgeProofRecordInput,
} from './shared.js';

const bridgeProofPublicFieldsMatchContribution = (
    contribution: AggregateContribution,
): boolean => {
    const proofRecord = contribution.bridgeProofRecord;

    return (
        proofRecord.aggregateDerivationComponentDigest ===
            contribution.aggregateDerivationComponentDigest &&
        proofRecord.aggregateShareCommitmentDigest ===
            contribution.aggregateShareCommitmentDigest &&
        proofRecord.shareCommitmentMessageBoundCertDigest ===
            contribution.shareCommitmentMessageBoundCertDigest &&
        proofRecord.encryptedAggregateBridgeDigest ===
            contribution.encryptedAggregateBridgeDigest &&
        proofRecord.encryptedAggregateTargetBasisDataRoot ===
            contribution.encryptedAggregateTargetBasisDataRoot &&
        proofRecord.encryptedAggregateInputRoot ===
            contribution.encryptedAggregateInputRoot &&
        proofRecord.encryptedAggregateShareCiphertextRoot ===
            contribution.encryptedAggregateShareCiphertextRoot &&
        proofRecord.encryptedAggregateReconstructionDigest ===
            contribution.encryptedAggregateReconstructionDigest &&
        proofRecord.bridgeProofProfileDigest ===
            contribution.bridgeProofProfileDigest &&
        proofRecord.bridgeWitnessPrivacyProfileDigest ===
            contribution.bridgeWitnessPrivacyProfileDigest &&
        proofRecord.bgvBatchEncoderDigest ===
            contribution.bgvBatchEncoderDigest &&
        proofRecord.bridgeLayoutDigest === contribution.bridgeLayoutDigest &&
        proofRecord.ballotScoreEncodingProfileDigest ===
            contribution.ballotScoreEncodingProfileDigest &&
        proofRecord.ballotShareLayoutProfileDigest ===
            contribution.ballotShareLayoutProfileDigest &&
        proofRecord.aggregateInputEncodingProfileDigest ===
            contribution.aggregateInputEncodingProfileDigest &&
        proofRecord.encodedShareVectorLayoutDigest ===
            contribution.encodedShareVectorLayoutDigest &&
        proofRecord.encodedAggregateLayoutDigest ===
            contribution.encodedAggregateLayoutDigest &&
        proofRecord.encryptedAggregateInputLayoutDigest ===
            contribution.encryptedAggregateInputLayoutDigest &&
        proofRecord.topKEvaluatorInputLayoutDigest ===
            contribution.topKEvaluatorInputLayoutDigest &&
        proofRecord.heParamDigest === contribution.heParamDigest &&
        proofRecord.bgvProfileDigest === contribution.bgvProfileDigest &&
        proofRecord.rustBgvBackendProfileDigest ===
            contribution.rustBgvBackendProfileDigest &&
        proofRecord.canonicalCiphertextConventionDigest ===
            contribution.canonicalCiphertextConventionDigest &&
        proofRecord.bgvPublicKeyRoot === contribution.bgvPublicKeyRoot &&
        proofRecord.collectivePublicKeyRoot ===
            contribution.collectivePublicKeyRoot &&
        proofRecord.aggregateSelectionPolicyDigest ===
            contribution.aggregateSelectionPolicyDigest &&
        proofRecord.postVotingClosedContextDigest ===
            contribution.postVotingClosedContextDigest &&
        proofRecord.ceremonyId === contribution.ceremonyId &&
        proofRecord.manifestDigest === contribution.manifestDigest &&
        proofRecord.rosterDigest === contribution.rosterDigest &&
        proofRecord.pollSpecDigest === contribution.pollSpecDigest &&
        proofRecord.thresholdProfileDigest ===
            contribution.thresholdProfileDigest &&
        proofRecord.setupPackageDigest === contribution.setupPackageDigest &&
        proofRecord.participantCount === contribution.participantCount &&
        proofRecord.optionCount === contribution.optionCount &&
        proofRecord.shareVectorWidth === contribution.shareVectorWidth &&
        proofRecord.ballotSetDigest === contribution.ballotSetDigest &&
        proofRecord.votingClosedBoardHeadDigest ===
            contribution.votingClosedBoardHeadDigest &&
        proofRecord.contributorIdentity === contribution.contributorIdentity &&
        proofRecord.contributorRosterPosition ===
            contribution.contributorRosterPosition &&
        proofRecord.contributorRosterExternalAcceptanceDigest ===
            contribution.contributorRosterExternalAcceptanceDigest
    );
};

const actionContextMatchesContribution = (
    contribution: AggregateContribution,
): boolean =>
    protocolDigestPattern.test(
        contribution.actionContext.actionContextDigest,
    ) &&
    contribution.actionContext.actionContextDigest ===
        contribution.bridgeProofRecord.contributorActionContextDigest &&
    contribution.actionContext.ceremonyId === contribution.ceremonyId &&
    contribution.actionContext.electionManifestDigest ===
        contribution.manifestDigest &&
    contribution.actionContext.signerIdentity ===
        contribution.contributorIdentity &&
    contribution.actionContext.boardHeadDigest ===
        contribution.votingClosedBoardHeadDigest &&
    contribution.actionContext.boardSequence === contribution.boardSequence &&
    contribution.actionContext.recoveryEpoch === contribution.recoveryEpoch &&
    contribution.actionContext.deviceEpoch === contribution.deviceEpoch &&
    contribution.actionContext.actionSequence === contribution.actionSequence &&
    contribution.actionContext.rosterExternalAcceptanceDigest ===
        contribution.contributorRosterExternalAcceptanceDigest &&
    contribution.actionContext.contextDigest ===
        contribution.postVotingClosedContextDigest;

const collectBridgeProofRecordRefusals = (
    proofRecord: BridgeProofRecord,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [
        ...collectDigestShapeRefusals(
            proofRecord as unknown as Record<string, unknown>,
            bridgeDigestFieldNames,
            proofRecord.bridgeProofRecordDigest,
        ),
    ];
    const expectedBridgeProofProfileDigest = deriveBridgeProofProfileDigest({
        bgvEncryptionProofSubrelation:
            proofRecord.bgvEncryptionProofSubrelation,
        bridgeProofProfileId: proofRecord.bridgeProofProfileId,
        proofBackend: proofRecord.proofBackend,
    });
    const { bridgeProofRecordDigest, ...proofRecordWithoutDigest } =
        proofRecord;
    void bridgeProofRecordDigest;
    const expectedBridgeProofRecordDigest = deriveBridgeProofRecordDigest(
        proofRecordWithoutDigest,
    );

    if (
        proofRecord.objectType !== 'BridgeProofRecord' ||
        proofRecord.objectVersion !== 1 ||
        proofRecord.bridgeProofProfileId !==
            encryptedAggregateBridgeProfileId ||
        proofRecord.bridgeProofProfileDigest !==
            expectedBridgeProofProfileDigest ||
        proofRecord.proofBackend !== 'SealedLatticeBridgeRelation' ||
        !['BridgeProofBackendPending', 'BridgeProofRelationChecked'].includes(
            proofRecord.bridgeProofVerificationStatus,
        ) ||
        proofRecord.bridgeProofRecordDigest !== expectedBridgeProofRecordDigest
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Bridge proof record digest, profile, or backend status is invalid.',
                proofRecord.bridgeProofRecordDigest,
            ),
        );
    }
    if (
        !Number.isSafeInteger(proofRecord.contributorRosterPosition) ||
        proofRecord.contributorRosterPosition <= 0 ||
        !Number.isSafeInteger(proofRecord.participantCount) ||
        proofRecord.participantCount <= 0 ||
        !Number.isSafeInteger(proofRecord.optionCount) ||
        proofRecord.optionCount <= 0 ||
        !Number.isSafeInteger(proofRecord.shareVectorWidth) ||
        proofRecord.shareVectorWidth !== proofRecord.optionCount * 11 ||
        !Number.isSafeInteger(proofRecord.proofSizeBytes) ||
        proofRecord.proofSizeBytes < 0
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Bridge proof record contributor position, variant dimensions, and proof size must be canonical.',
                proofRecord.bridgeProofRecordDigest,
            ),
        );
    }

    return refusedObjects;
};

const requireCheckedBridgeProofRecord = (
    proofRecord: BridgeProofRecord,
): void => {
    const refusedObjects = collectBridgeProofRecordRefusals(proofRecord);
    if (refusedObjects.length > 0) {
        throw new RangeError(
            `Aggregate contribution requires a structurally valid bridge proof record: ${refusedObjects[0]?.message ?? 'invalid bridge proof record'}`,
        );
    }
    if (
        proofRecord.bridgeProofVerificationStatus !==
        'BridgeProofRelationChecked'
    ) {
        throw new RangeError(
            'Aggregate contribution requires a proof-checked bridge proof record.',
        );
    }
};

const actionContextMatchesBridgeProofRecord = (
    actionContext: ActionContext,
    proofRecord: BridgeProofRecord,
): boolean =>
    protocolDigestPattern.test(actionContext.actionContextDigest) &&
    actionContext.ceremonyId === proofRecord.ceremonyId &&
    actionContext.electionManifestDigest === proofRecord.manifestDigest &&
    actionContext.signerIdentity === proofRecord.contributorIdentity &&
    actionContext.boardHeadDigest === proofRecord.votingClosedBoardHeadDigest &&
    actionContext.contextDigest === proofRecord.postVotingClosedContextDigest &&
    actionContext.actionContextDigest ===
        proofRecord.contributorActionContextDigest &&
    actionContext.rosterExternalAcceptanceDigest ===
        proofRecord.contributorRosterExternalAcceptanceDigest &&
    Number.isSafeInteger(actionContext.boardSequence) &&
    actionContext.boardSequence >= 0 &&
    Number.isSafeInteger(actionContext.recoveryEpoch) &&
    actionContext.recoveryEpoch >= 0 &&
    Number.isSafeInteger(actionContext.deviceEpoch) &&
    actionContext.deviceEpoch >= 0 &&
    Number.isSafeInteger(actionContext.actionSequence) &&
    actionContext.actionSequence >= 0;

const signatureEnvelopeMatchesContributionContext = (
    signature: ProtocolSignatureEnvelope,
    contributionPayload: Omit<
        AggregateContribution,
        'aggregateContributionDigest'
    >,
    aggregateContributionDigest: string,
): boolean =>
    signature.signedRoot.objectType === 'AggregateContribution' &&
    signature.signedRoot.objectVersion === 1 &&
    signature.signedRoot.objectRoot === aggregateContributionDigest &&
    signature.signedRoot.chunkMerkleRoot === null &&
    signature.signedRoot.byteLength === signedObjectRootByteLength &&
    signature.signedRoot.ceremonyId === contributionPayload.ceremonyId &&
    signature.signedRoot.manifestDigest ===
        contributionPayload.manifestDigest &&
    signature.signedRoot.boardHeadDigest ===
        contributionPayload.votingClosedBoardHeadDigest &&
    signature.signedRoot.signerRole === 'Trustee' &&
    signature.signedRoot.signerIdentity ===
        contributionPayload.contributorIdentity &&
    signature.signedRoot.recoveryEpoch === contributionPayload.recoveryEpoch &&
    signature.signedRoot.deviceEpoch === contributionPayload.deviceEpoch &&
    signature.signedRoot.contextDigest ===
        contributionPayload.postVotingClosedContextDigest;

const verifyAggregateContributionSignature = (
    contribution: AggregateContribution,
    expectedAggregateContributionDigest: string,
): readonly RefusalRecord[] =>
    verifySignedObjectSignature(contribution.signature, {
        objectType: 'AggregateContribution',
        objectVersion: 1,
        signerRole: 'Trustee',
        signerIdentity: contribution.contributorIdentity,
        ceremonyId: contribution.ceremonyId,
        publicKeyDigest: contribution.signature.publicKeyDigest,
        manifestDigest: contribution.manifestDigest,
        objectRoot: expectedAggregateContributionDigest,
        chunkMerkleRoot: null,
        boardHeadDigest: contribution.votingClosedBoardHeadDigest,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: contribution.recoveryEpoch,
        deviceEpoch: contribution.deviceEpoch,
        contextDigest: contribution.postVotingClosedContextDigest,
    }).refusedObjects;

export function verifyAggregateContributionStructure(
    contribution: AggregateContribution,
): AggregateContributionVerification {
    const contributionDigest = contribution.aggregateContributionDigest;
    const { aggregateContributionDigest, ...contributionWithoutDigest } =
        contribution;
    void aggregateContributionDigest;
    let expectedContributionDigest: string | undefined;
    const refusedObjects: RefusalRecord[] = [
        ...collectForbiddenWitnessFieldRefusals(
            contribution,
            contributionDigest,
            'contribution',
        ),
        ...collectDigestShapeRefusals(
            contribution as unknown as Record<string, unknown>,
            contributionDigestFieldNames,
            contributionDigest,
        ),
        ...collectBridgeProofRecordRefusals(contribution.bridgeProofRecord),
    ];
    try {
        expectedContributionDigest = deriveAggregateContributionDigest(
            contributionWithoutDigest,
        );
        refusedObjects.push(
            ...verifyAggregateContributionSignature(
                contribution,
                expectedContributionDigest,
            ),
        );
    } catch (error) {
        refusedObjects.push(
            createAggregateRefusal(
                `Aggregate contribution digest could not be canonicalized: ${
                    error instanceof Error ? error.message : String(error)
                }.`,
                contributionDigest,
            ),
        );
    }

    if (
        contribution.objectType !== 'AggregateContribution' ||
        contribution.objectVersion !== 1 ||
        expectedContributionDigest === undefined ||
        contribution.aggregateContributionDigest !==
            expectedContributionDigest ||
        contribution.bridgeProofRecordDigest !==
            contribution.bridgeProofRecord.bridgeProofRecordDigest ||
        !bridgeProofPublicFieldsMatchContribution(contribution) ||
        !actionContextMatchesContribution(contribution) ||
        !Number.isSafeInteger(contribution.contributorRosterPosition) ||
        contribution.contributorRosterPosition <= 0 ||
        !Number.isSafeInteger(contribution.participantCount) ||
        contribution.participantCount <= 0 ||
        !Number.isSafeInteger(contribution.optionCount) ||
        contribution.optionCount <= 0 ||
        !Number.isSafeInteger(contribution.shareVectorWidth) ||
        contribution.shareVectorWidth !== contribution.optionCount * 11 ||
        !Number.isSafeInteger(contribution.boardSequence) ||
        contribution.boardSequence < 0 ||
        !Number.isSafeInteger(contribution.boardPosition) ||
        contribution.boardPosition < 0 ||
        !Number.isSafeInteger(contribution.recoveryEpoch) ||
        contribution.recoveryEpoch < 0 ||
        !Number.isSafeInteger(contribution.deviceEpoch) ||
        contribution.deviceEpoch < 0 ||
        !Number.isSafeInteger(contribution.actionSequence) ||
        contribution.actionSequence < 0
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate contribution digest, proof binding, action context, or sequence metadata is invalid.',
                contributionDigest,
            ),
        );
    }

    if (refusedObjects.length > 0) {
        return {
            acceptedDigests: [],
            aggregateContributionDigest: contributionDigest,
            backendAvailable: false,
            bridgeProofRecordDigest:
                contribution.bridgeProofRecord.bridgeProofRecordDigest,
            ok: false,
            refusedObjects,
            statusLabels: [],
            unresolvedReason:
                refusedObjects[0]?.code ?? 'AggregateShareInvalid',
        };
    }

    const bridgeProofRelationChecked =
        contribution.bridgeProofRecord.bridgeProofVerificationStatus ===
        'BridgeProofRelationChecked';

    return {
        acceptedDigests: [
            contribution.bridgeProofRecord.bridgeProofRecordDigest,
            contribution.aggregateContributionDigest,
        ],
        aggregateContributionDigest: contributionDigest,
        backendAvailable: bridgeProofRelationChecked,
        bridgeProofRecordDigest:
            contribution.bridgeProofRecord.bridgeProofRecordDigest,
        ok: true,
        refusedObjects: [],
        statusLabels: bridgeProofRelationChecked ? [] : ['pending'],
        unresolvedReason: bridgeProofRelationChecked
            ? null
            : 'OperationUnavailable',
    };
}

export const createAggregateContributionFromBridgeProofRecord = (
    input: AggregateContributionFromBridgeProofRecordInput,
): AggregateContribution => {
    requireCheckedBridgeProofRecord(input.bridgeProofRecord);
    if (!protocolDigestPattern.test(input.closeRecordDigest)) {
        throw new RangeError(
            'Aggregate contribution close-record digest must be a protocol digest.',
        );
    }
    if (!Number.isSafeInteger(input.boardPosition) || input.boardPosition < 0) {
        throw new RangeError(
            'Aggregate contribution board position must be a non-negative safe integer.',
        );
    }
    if (
        !actionContextMatchesBridgeProofRecord(
            input.actionContext,
            input.bridgeProofRecord,
        )
    ) {
        throw new RangeError(
            'Aggregate contribution action context does not match the bridge proof record.',
        );
    }

    const proofRecord = input.bridgeProofRecord;
    const unsignedContributionPayload: Omit<
        AggregateContribution,
        'aggregateContributionDigest' | 'signature'
    > = {
        actionContext: input.actionContext,
        actionSequence: input.actionContext.actionSequence,
        aggregateDerivationComponentDigest:
            proofRecord.aggregateDerivationComponentDigest,
        aggregateSelectionPolicyDigest:
            proofRecord.aggregateSelectionPolicyDigest,
        aggregateShareCommitmentDigest:
            proofRecord.aggregateShareCommitmentDigest,
        aggregateInputEncodingProfileDigest:
            proofRecord.aggregateInputEncodingProfileDigest,
        ballotScoreEncodingProfileDigest:
            proofRecord.ballotScoreEncodingProfileDigest,
        ballotSetDigest: proofRecord.ballotSetDigest,
        ballotShareLayoutProfileDigest:
            proofRecord.ballotShareLayoutProfileDigest,
        bgvBatchEncoderDigest: proofRecord.bgvBatchEncoderDigest,
        bgvProfileDigest: proofRecord.bgvProfileDigest,
        bgvPublicKeyRoot: proofRecord.bgvPublicKeyRoot,
        boardPosition: input.boardPosition,
        boardSequence: input.actionContext.boardSequence,
        bridgeLayoutDigest: proofRecord.bridgeLayoutDigest,
        bridgeProofProfileDigest: proofRecord.bridgeProofProfileDigest,
        bridgeProofRecord: proofRecord,
        bridgeProofRecordDigest: proofRecord.bridgeProofRecordDigest,
        bridgeWitnessPrivacyProfileDigest:
            proofRecord.bridgeWitnessPrivacyProfileDigest,
        canonicalCiphertextConventionDigest:
            proofRecord.canonicalCiphertextConventionDigest,
        ceremonyId: proofRecord.ceremonyId,
        closeRecordDigest: input.closeRecordDigest,
        collectivePublicKeyRoot: proofRecord.collectivePublicKeyRoot,
        contributorIdentity: proofRecord.contributorIdentity,
        contributorRosterExternalAcceptanceDigest:
            proofRecord.contributorRosterExternalAcceptanceDigest,
        contributorRosterPosition: proofRecord.contributorRosterPosition,
        deviceEpoch: input.actionContext.deviceEpoch,
        encodedAggregateLayoutDigest: proofRecord.encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            proofRecord.encodedShareVectorLayoutDigest,
        encryptedAggregateBridgeDigest:
            proofRecord.encryptedAggregateBridgeDigest,
        encryptedAggregateInputLayoutDigest:
            proofRecord.encryptedAggregateInputLayoutDigest,
        encryptedAggregateReconstructionDigest:
            proofRecord.encryptedAggregateReconstructionDigest,
        encryptedAggregateInputRoot: proofRecord.encryptedAggregateInputRoot,
        encryptedAggregateShareCiphertextRoot:
            proofRecord.encryptedAggregateShareCiphertextRoot,
        encryptedAggregateTargetBasisDataRoot:
            proofRecord.encryptedAggregateTargetBasisDataRoot,
        heParamDigest: proofRecord.heParamDigest,
        manifestDigest: proofRecord.manifestDigest,
        objectType: 'AggregateContribution',
        objectVersion: 1,
        optionCount: proofRecord.optionCount,
        participantCount: proofRecord.participantCount,
        pollSpecDigest: proofRecord.pollSpecDigest,
        postVotingClosedContextDigest:
            proofRecord.postVotingClosedContextDigest,
        recoveryEpoch: input.actionContext.recoveryEpoch,
        rosterDigest: proofRecord.rosterDigest,
        rustBgvBackendProfileDigest: proofRecord.rustBgvBackendProfileDigest,
        setupPackageDigest: proofRecord.setupPackageDigest,
        shareCommitmentMessageBoundCertDigest:
            proofRecord.shareCommitmentMessageBoundCertDigest,
        shareVectorWidth: proofRecord.shareVectorWidth,
        thresholdProfileDigest: proofRecord.thresholdProfileDigest,
        topKEvaluatorInputLayoutDigest:
            proofRecord.topKEvaluatorInputLayoutDigest,
        votingClosedBoardHeadDigest: proofRecord.votingClosedBoardHeadDigest,
    };
    const aggregateContributionDigest = deriveAggregateContributionDigest(
        unsignedContributionPayload,
    );
    const signature =
        typeof input.signature === 'function'
            ? input.signature({ aggregateContributionDigest })
            : input.signature;
    const contributionPayload: Omit<
        AggregateContribution,
        'aggregateContributionDigest'
    > = {
        ...unsignedContributionPayload,
        signature,
    };

    if (
        !signatureEnvelopeMatchesContributionContext(
            signature,
            contributionPayload,
            aggregateContributionDigest,
        )
    ) {
        throw new RangeError(
            'Aggregate contribution signature envelope does not match the contribution context.',
        );
    }

    const contribution = {
        ...contributionPayload,
        aggregateContributionDigest,
    };
    const verification = verifyAggregateContributionStructure(contribution);
    if (!verification.ok || !verification.backendAvailable) {
        throw new RangeError(
            `Aggregate contribution assembled from a checked bridge proof did not verify: ${verification.unresolvedReason ?? 'unknown refusal'}`,
        );
    }

    return contribution;
};
