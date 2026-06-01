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

import {
    createAggregateRefusal,
    protocolHashPattern,
} from '../../aggregate-derivation/constants.js';
import { signedObjectRootByteLength } from '../../verification-helpers.js';
import {
    deriveAggregateContributionHash,
    deriveBridgeProofProfileHash,
    deriveBridgeProofRecordHash,
} from '../hashes.js';

import {
    bridgeHashFieldNames,
    collectHashShapeRefusals,
    collectForbiddenWitnessFieldRefusals,
    contributionHashFieldNames,
    type AggregateContributionFromBridgeProofRecordInput,
} from './shared.js';

const bridgeProofPublicFieldsMatchContribution = (
    contribution: AggregateContribution,
): boolean => {
    const proofRecord = contribution.bridgeProofRecord;

    return (
        proofRecord.aggregateDerivationComponentHash ===
            contribution.aggregateDerivationComponentHash &&
        proofRecord.aggregateShareCommitmentHash ===
            contribution.aggregateShareCommitmentHash &&
        proofRecord.shareCommitmentMessageBoundCertHash ===
            contribution.shareCommitmentMessageBoundCertHash &&
        proofRecord.encryptedAggregateBridgeHash ===
            contribution.encryptedAggregateBridgeHash &&
        proofRecord.encryptedAggregateTargetBasisRoot ===
            contribution.encryptedAggregateTargetBasisRoot &&
        proofRecord.encryptedAggregateInputRoot ===
            contribution.encryptedAggregateInputRoot &&
        proofRecord.encryptedAggregateShareCiphertextRoot ===
            contribution.encryptedAggregateShareCiphertextRoot &&
        proofRecord.encryptedAggregateReconstructionHash ===
            contribution.encryptedAggregateReconstructionHash &&
        proofRecord.bridgeProofProfileHash ===
            contribution.bridgeProofProfileHash &&
        proofRecord.bridgeWitnessPrivacyProfileHash ===
            contribution.bridgeWitnessPrivacyProfileHash &&
        proofRecord.bgvBatchEncoderHash === contribution.bgvBatchEncoderHash &&
        proofRecord.bridgeLayoutHash === contribution.bridgeLayoutHash &&
        proofRecord.ballotScoreEncodingProfileHash ===
            contribution.ballotScoreEncodingProfileHash &&
        proofRecord.ballotShareLayoutProfileHash ===
            contribution.ballotShareLayoutProfileHash &&
        proofRecord.aggregateInputEncodingProfileHash ===
            contribution.aggregateInputEncodingProfileHash &&
        proofRecord.encodedShareVectorLayoutHash ===
            contribution.encodedShareVectorLayoutHash &&
        proofRecord.encodedAggregateLayoutHash ===
            contribution.encodedAggregateLayoutHash &&
        proofRecord.encryptedAggregateInputLayoutHash ===
            contribution.encryptedAggregateInputLayoutHash &&
        proofRecord.topKEvaluatorInputLayoutHash ===
            contribution.topKEvaluatorInputLayoutHash &&
        proofRecord.heParamHash === contribution.heParamHash &&
        proofRecord.bgvProfileHash === contribution.bgvProfileHash &&
        proofRecord.rustBgvBackendProfileHash ===
            contribution.rustBgvBackendProfileHash &&
        proofRecord.canonicalCiphertextConventionHash ===
            contribution.canonicalCiphertextConventionHash &&
        proofRecord.bgvPublicKeyRoot === contribution.bgvPublicKeyRoot &&
        proofRecord.collectivePublicKeyRoot ===
            contribution.collectivePublicKeyRoot &&
        proofRecord.collectivePublicKeyCoefficientRoot ===
            contribution.collectivePublicKeyCoefficientRoot &&
        proofRecord.aggregateSelectionPolicyHash ===
            contribution.aggregateSelectionPolicyHash &&
        proofRecord.postVotingClosedContextHash ===
            contribution.postVotingClosedContextHash &&
        proofRecord.ceremonyId === contribution.ceremonyId &&
        proofRecord.manifestHash === contribution.manifestHash &&
        proofRecord.rosterHash === contribution.rosterHash &&
        proofRecord.pollSpecHash === contribution.pollSpecHash &&
        proofRecord.thresholdProfileHash ===
            contribution.thresholdProfileHash &&
        proofRecord.setupPackageHash === contribution.setupPackageHash &&
        proofRecord.participantCount === contribution.participantCount &&
        proofRecord.optionCount === contribution.optionCount &&
        proofRecord.shareVectorWidth === contribution.shareVectorWidth &&
        proofRecord.ballotSetHash === contribution.ballotSetHash &&
        proofRecord.votingClosedBoardHeadHash ===
            contribution.votingClosedBoardHeadHash &&
        proofRecord.contributorIdentity === contribution.contributorIdentity &&
        proofRecord.contributorRosterPosition ===
            contribution.contributorRosterPosition &&
        proofRecord.contributorRosterExternalAcceptanceHash ===
            contribution.contributorRosterExternalAcceptanceHash
    );
};

const actionContextMatchesContribution = (
    contribution: AggregateContribution,
): boolean =>
    protocolHashPattern.test(contribution.actionContext.actionContextHash) &&
    contribution.actionContext.actionContextHash ===
        contribution.bridgeProofRecord.contributorActionContextHash &&
    contribution.actionContext.ceremonyId === contribution.ceremonyId &&
    contribution.actionContext.electionManifestHash ===
        contribution.manifestHash &&
    contribution.actionContext.signerIdentity ===
        contribution.contributorIdentity &&
    contribution.actionContext.boardHeadHash ===
        contribution.votingClosedBoardHeadHash &&
    contribution.actionContext.boardSequence === contribution.boardSequence &&
    contribution.actionContext.recoveryEpoch === contribution.recoveryEpoch &&
    contribution.actionContext.deviceEpoch === contribution.deviceEpoch &&
    contribution.actionContext.actionSequence === contribution.actionSequence &&
    contribution.actionContext.rosterExternalAcceptanceHash ===
        contribution.contributorRosterExternalAcceptanceHash &&
    contribution.actionContext.contextHash ===
        contribution.postVotingClosedContextHash;

const collectBridgeProofRecordRefusals = (
    proofRecord: BridgeProofRecord,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [
        ...collectHashShapeRefusals(
            proofRecord,
            bridgeHashFieldNames,
            proofRecord.bridgeProofRecordHash,
        ),
    ];
    const expectedBridgeProofProfileHash = deriveBridgeProofProfileHash({
        bgvEncryptionKeyMaterialKind: proofRecord.bgvEncryptionKeyMaterialKind,
        bgvEncryptionProofSubrelation:
            proofRecord.bgvEncryptionProofSubrelation,
        bridgeProofProfileId: proofRecord.bridgeProofProfileId,
        claimBearingBridgeEncryption: proofRecord.claimBearingBridgeEncryption,
        developmentKeyOnly: proofRecord.developmentKeyOnly,
        proofBackend: proofRecord.proofBackend,
        thresholdDecryptable: proofRecord.thresholdDecryptable,
    });
    const { bridgeProofRecordHash, ...proofRecordWithoutHash } = proofRecord;
    void bridgeProofRecordHash;
    const expectedBridgeProofRecordHash = deriveBridgeProofRecordHash(
        proofRecordWithoutHash,
    );
    const expectedBridgeClaimVerificationStatus =
        proofRecord.claimBearingBridgeEncryption
            ? 'BridgeProofClaimClosureVerified'
            : 'BridgeProofClaimClosureMissing';
    const bridgeClaimStatusIsConsistent =
        proofRecord.bridgeClaimClosureVerified ===
            proofRecord.claimBearingBridgeEncryption &&
        proofRecord.bridgeClaimVerificationStatus ===
            expectedBridgeClaimVerificationStatus;

    if (
        proofRecord.objectType !== 'BridgeProofRecord' ||
        proofRecord.objectVersion !== 1 ||
        proofRecord.bridgeProofProfileId !==
            encryptedAggregateBridgeProfileId ||
        proofRecord.bridgeProofProfileHash !== expectedBridgeProofProfileHash ||
        proofRecord.proofBackend !== 'SealedLatticeBridgeRelation' ||
        proofRecord.bgvEncryptionKeyMaterialKind !==
            'passive-transcript-derived-collective-public-key' ||
        proofRecord.developmentKeyOnly !== false ||
        proofRecord.thresholdDecryptable !== true ||
        !bridgeClaimStatusIsConsistent ||
        !['BridgeProofBackendPending', 'BridgeProofRelationChecked'].includes(
            proofRecord.bridgeProofVerificationStatus,
        ) ||
        proofRecord.bridgeProofRecordHash !== expectedBridgeProofRecordHash
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Bridge proof record hash, profile, or backend status is invalid.',
                proofRecord.bridgeProofRecordHash,
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
                proofRecord.bridgeProofRecordHash,
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
    protocolHashPattern.test(actionContext.actionContextHash) &&
    actionContext.ceremonyId === proofRecord.ceremonyId &&
    actionContext.electionManifestHash === proofRecord.manifestHash &&
    actionContext.signerIdentity === proofRecord.contributorIdentity &&
    actionContext.boardHeadHash === proofRecord.votingClosedBoardHeadHash &&
    actionContext.contextHash === proofRecord.postVotingClosedContextHash &&
    actionContext.actionContextHash ===
        proofRecord.contributorActionContextHash &&
    actionContext.rosterExternalAcceptanceHash ===
        proofRecord.contributorRosterExternalAcceptanceHash &&
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
        'aggregateContributionHash'
    >,
    aggregateContributionHash: string,
): boolean =>
    signature.signedRoot.objectType === 'AggregateContribution' &&
    signature.signedRoot.objectVersion === 1 &&
    signature.signedRoot.objectRoot === aggregateContributionHash &&
    signature.signedRoot.chunkMerkleRoot === null &&
    signature.signedRoot.byteLength === signedObjectRootByteLength &&
    signature.signedRoot.ceremonyId === contributionPayload.ceremonyId &&
    signature.signedRoot.manifestHash === contributionPayload.manifestHash &&
    signature.signedRoot.boardHeadHash ===
        contributionPayload.votingClosedBoardHeadHash &&
    signature.signedRoot.signerRole === 'Trustee' &&
    signature.signedRoot.signerIdentity ===
        contributionPayload.contributorIdentity &&
    signature.signedRoot.recoveryEpoch === contributionPayload.recoveryEpoch &&
    signature.signedRoot.deviceEpoch === contributionPayload.deviceEpoch &&
    signature.signedRoot.contextHash ===
        contributionPayload.postVotingClosedContextHash;

const verifyAggregateContributionSignature = (
    contribution: AggregateContribution,
    expectedAggregateContributionHash: string,
): readonly RefusalRecord[] =>
    verifySignedObjectSignature(contribution.signature, {
        objectType: 'AggregateContribution',
        objectVersion: 1,
        signerRole: 'Trustee',
        signerIdentity: contribution.contributorIdentity,
        ceremonyId: contribution.ceremonyId,
        publicKeyHash: contribution.signature.publicKeyHash,
        manifestHash: contribution.manifestHash,
        objectRoot: expectedAggregateContributionHash,
        chunkMerkleRoot: null,
        boardHeadHash: contribution.votingClosedBoardHeadHash,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: contribution.recoveryEpoch,
        deviceEpoch: contribution.deviceEpoch,
        contextHash: contribution.postVotingClosedContextHash,
    }).refusedObjects;

export function verifyAggregateContributionStructure(
    contribution: AggregateContribution,
): AggregateContributionVerification {
    const contributionHash = contribution.aggregateContributionHash;
    const { aggregateContributionHash, ...contributionWithoutHash } =
        contribution;
    void aggregateContributionHash;
    let expectedContributionHash: string | undefined;
    const refusedObjects: RefusalRecord[] = [
        ...collectForbiddenWitnessFieldRefusals(
            contribution,
            contributionHash,
            'contribution',
        ),
        ...collectHashShapeRefusals(
            contribution,
            contributionHashFieldNames,
            contributionHash,
        ),
        ...collectBridgeProofRecordRefusals(contribution.bridgeProofRecord),
    ];
    try {
        expectedContributionHash = deriveAggregateContributionHash(
            contributionWithoutHash,
        );
        refusedObjects.push(
            ...verifyAggregateContributionSignature(
                contribution,
                expectedContributionHash,
            ),
        );
    } catch (error) {
        refusedObjects.push(
            createAggregateRefusal(
                `Aggregate contribution hash could not be canonicalized: ${
                    error instanceof Error ? error.message : String(error)
                }.`,
                contributionHash,
            ),
        );
    }

    if (
        contribution.objectType !== 'AggregateContribution' ||
        contribution.objectVersion !== 1 ||
        expectedContributionHash === undefined ||
        contribution.aggregateContributionHash !== expectedContributionHash ||
        contribution.bridgeProofRecordHash !==
            contribution.bridgeProofRecord.bridgeProofRecordHash ||
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
                'Aggregate contribution hash, proof binding, action context, or sequence metadata is invalid.',
                contributionHash,
            ),
        );
    }

    if (refusedObjects.length > 0) {
        return {
            acceptedHashes: [],
            aggregateContributionHash: contributionHash,
            backendAvailable: false,
            bridgeProofRecordHash:
                contribution.bridgeProofRecord.bridgeProofRecordHash,
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
        acceptedHashes: [
            contribution.bridgeProofRecord.bridgeProofRecordHash,
            contribution.aggregateContributionHash,
        ],
        aggregateContributionHash: contributionHash,
        backendAvailable: bridgeProofRelationChecked,
        bridgeProofRecordHash:
            contribution.bridgeProofRecord.bridgeProofRecordHash,
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
    if (!protocolHashPattern.test(input.closeRecordHash)) {
        throw new RangeError(
            'Aggregate contribution close-record hash must be a protocol hash.',
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
        'aggregateContributionHash' | 'signature'
    > = {
        actionContext: input.actionContext,
        actionSequence: input.actionContext.actionSequence,
        aggregateDerivationComponentHash:
            proofRecord.aggregateDerivationComponentHash,
        aggregateSelectionPolicyHash: proofRecord.aggregateSelectionPolicyHash,
        aggregateShareCommitmentHash: proofRecord.aggregateShareCommitmentHash,
        aggregateInputEncodingProfileHash:
            proofRecord.aggregateInputEncodingProfileHash,
        ballotScoreEncodingProfileHash:
            proofRecord.ballotScoreEncodingProfileHash,
        ballotSetHash: proofRecord.ballotSetHash,
        ballotShareLayoutProfileHash: proofRecord.ballotShareLayoutProfileHash,
        bgvBatchEncoderHash: proofRecord.bgvBatchEncoderHash,
        bgvProfileHash: proofRecord.bgvProfileHash,
        bgvPublicKeyRoot: proofRecord.bgvPublicKeyRoot,
        boardPosition: input.boardPosition,
        boardSequence: input.actionContext.boardSequence,
        bridgeLayoutHash: proofRecord.bridgeLayoutHash,
        bridgeProofProfileHash: proofRecord.bridgeProofProfileHash,
        bridgeProofRecord: proofRecord,
        bridgeProofRecordHash: proofRecord.bridgeProofRecordHash,
        bridgeWitnessPrivacyProfileHash:
            proofRecord.bridgeWitnessPrivacyProfileHash,
        canonicalCiphertextConventionHash:
            proofRecord.canonicalCiphertextConventionHash,
        ceremonyId: proofRecord.ceremonyId,
        closeRecordHash: input.closeRecordHash,
        collectivePublicKeyRoot: proofRecord.collectivePublicKeyRoot,
        collectivePublicKeyCoefficientRoot:
            proofRecord.collectivePublicKeyCoefficientRoot,
        contributorIdentity: proofRecord.contributorIdentity,
        contributorRosterExternalAcceptanceHash:
            proofRecord.contributorRosterExternalAcceptanceHash,
        contributorRosterPosition: proofRecord.contributorRosterPosition,
        deviceEpoch: input.actionContext.deviceEpoch,
        encodedAggregateLayoutHash: proofRecord.encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash: proofRecord.encodedShareVectorLayoutHash,
        encryptedAggregateBridgeHash: proofRecord.encryptedAggregateBridgeHash,
        encryptedAggregateInputLayoutHash:
            proofRecord.encryptedAggregateInputLayoutHash,
        encryptedAggregateReconstructionHash:
            proofRecord.encryptedAggregateReconstructionHash,
        encryptedAggregateInputRoot: proofRecord.encryptedAggregateInputRoot,
        encryptedAggregateShareCiphertextRoot:
            proofRecord.encryptedAggregateShareCiphertextRoot,
        encryptedAggregateTargetBasisRoot:
            proofRecord.encryptedAggregateTargetBasisRoot,
        heParamHash: proofRecord.heParamHash,
        manifestHash: proofRecord.manifestHash,
        objectType: 'AggregateContribution',
        objectVersion: 1,
        optionCount: proofRecord.optionCount,
        participantCount: proofRecord.participantCount,
        pollSpecHash: proofRecord.pollSpecHash,
        postVotingClosedContextHash: proofRecord.postVotingClosedContextHash,
        recoveryEpoch: input.actionContext.recoveryEpoch,
        rosterHash: proofRecord.rosterHash,
        rustBgvBackendProfileHash: proofRecord.rustBgvBackendProfileHash,
        setupPackageHash: proofRecord.setupPackageHash,
        shareCommitmentMessageBoundCertHash:
            proofRecord.shareCommitmentMessageBoundCertHash,
        shareVectorWidth: proofRecord.shareVectorWidth,
        thresholdProfileHash: proofRecord.thresholdProfileHash,
        topKEvaluatorInputLayoutHash: proofRecord.topKEvaluatorInputLayoutHash,
        votingClosedBoardHeadHash: proofRecord.votingClosedBoardHeadHash,
    };
    const aggregateContributionHash = deriveAggregateContributionHash(
        unsignedContributionPayload,
    );
    const signature =
        typeof input.signature === 'function'
            ? input.signature({ aggregateContributionHash })
            : input.signature;
    const contributionPayload: Omit<
        AggregateContribution,
        'aggregateContributionHash'
    > = {
        ...unsignedContributionPayload,
        signature,
    };

    if (
        !signatureEnvelopeMatchesContributionContext(
            signature,
            contributionPayload,
            aggregateContributionHash,
        )
    ) {
        throw new RangeError(
            'Aggregate contribution signature envelope does not match the contribution context.',
        );
    }

    const contribution = {
        ...contributionPayload,
        aggregateContributionHash,
    };
    const verification = verifyAggregateContributionStructure(contribution);
    if (!verification.ok || !verification.backendAvailable) {
        throw new RangeError(
            `Aggregate contribution assembled from a checked bridge proof did not verify: ${verification.unresolvedReason ?? 'unknown refusal'}`,
        );
    }

    return contribution;
};
