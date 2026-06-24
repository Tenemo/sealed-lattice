import { verifySignedObjectSignature } from '@sealed-lattice/crypto';
import type {
    ConflictingHeadEvidence,
    RefusalRecord,
    TargetFinalityRecord,
    TargetFinalityVerification,
    TargetFinalityVerificationInput,
    WitnessCheckpoint,
} from '@sealed-lattice/types';

import {
    collectBoardInclusionEvidence,
    type BoardEvidence,
    verifyBoardInclusionProof,
} from '../board/shell-evidence.js';
import {
    createRefusal,
    defaultSignedRootContextHash,
    isProtocolHashString,
    signedObjectRootByteLength,
    uniqueStrings,
    verificationExceptionMessage,
} from '../common/verification-helpers.js';

import {
    deriveTargetFinalityCheckpointHash,
    deriveTargetFinalityPolicyHash,
    deriveTargetFinalityRecordHash,
    deriveTargetProposalHash,
    deriveWitnessCheckpointHash,
    deriveWitnessEquivocationEvidenceHash,
    deriveWitnessPolicyHash,
} from './hashes.js';
export {
    deriveTargetFinalityCheckpointHash,
    deriveTargetFinalityPolicyHash,
    deriveTargetFinalityRecordHash,
    deriveTargetProposalHash,
    deriveWitnessCheckpointHash,
    deriveWitnessPolicyHash,
} from './hashes.js';

const verifyTargetRecordShape = (
    input: TargetFinalityVerificationInput,
    record: TargetFinalityRecord = input.record,
): readonly RefusalRecord[] => {
    const { targetFinalityPolicy, witnessPolicy } = input;
    const checkpoint = record.targetFinalityCheckpoint;
    const refusedObjects: RefusalRecord[] = [];
    const expectedRecordHash = deriveTargetFinalityRecordHash({
        ceremonyId: record.ceremonyId,
        inclusionProof: record.inclusionProof,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        targetFinalityCheckpoint: checkpoint,
        targetFinalityPolicyHash: record.targetFinalityPolicyHash,
        targetFinalityScope: record.targetFinalityScope,
        targetProposalHash: record.targetProposalHash,
        witnessCheckpoints: record.witnessCheckpoints,
        witnessPolicyHash: record.witnessPolicyHash,
    });
    const expectedProposalHash = deriveTargetProposalHash({
        ceremonyId: checkpoint.ceremonyId,
        electionManifestHash: checkpoint.electionManifestHash,
        encryptedBallotAggregateHash: checkpoint.encryptedBallotAggregateHash,
        evaluatorReplayContextHash: checkpoint.evaluatorReplayContextHash,
        evaluatorReplayParametersHash: checkpoint.evaluatorReplayParametersHash,
        evaluatorReplayRecordHash: checkpoint.evaluatorReplayRecordHash,
        targetCiphertextHash: checkpoint.targetCiphertextHash,
        targetFinalityPolicyHash: checkpoint.targetFinalityPolicyHash,
        targetLayoutHash: checkpoint.targetLayoutHash,
        thresholdParametersHash: checkpoint.thresholdParametersHash,
        tiePolicyHash: checkpoint.tiePolicyHash,
        topOptionCount: checkpoint.topOptionCount,
    });
    const expectedCheckpointHash = deriveTargetFinalityCheckpointHash({
        boardPolicyHash: checkpoint.boardPolicyHash,
        ceremonyId: checkpoint.ceremonyId,
        electionManifestHash: checkpoint.electionManifestHash,
        encryptedBallotAggregateHash: checkpoint.encryptedBallotAggregateHash,
        evaluatorReplayContextHash: checkpoint.evaluatorReplayContextHash,
        evaluatorReplayParametersHash: checkpoint.evaluatorReplayParametersHash,
        evaluatorReplayRecordHash: checkpoint.evaluatorReplayRecordHash,
        finalizedBoardHeadHash: checkpoint.finalizedBoardHeadHash,
        objectType: checkpoint.objectType,
        objectVersion: checkpoint.objectVersion,
        targetCiphertextHash: checkpoint.targetCiphertextHash,
        targetFinalityPolicyHash: checkpoint.targetFinalityPolicyHash,
        targetLayoutHash: checkpoint.targetLayoutHash,
        targetProposalHash: checkpoint.targetProposalHash,
        thresholdParametersHash: checkpoint.thresholdParametersHash,
        tiePolicyHash: checkpoint.tiePolicyHash,
        topOptionCount: checkpoint.topOptionCount,
        witnessPolicyHash: checkpoint.witnessPolicyHash,
    });

    if (record.targetFinalityRecordHash !== expectedRecordHash) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target finality record hash does not match its canonical payload.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        record.objectType !== 'TargetFinalityRecord' ||
        record.objectVersion !== 1 ||
        checkpoint.objectType !== 'TargetFinalityCheckpoint' ||
        checkpoint.objectVersion !== 1
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target finality record object shape is not canonical.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }
    if (record.ceremonyId !== input.boardEvidence.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Target finality record ceremony does not match the board evidence.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        checkpoint.targetProposalHash !== expectedProposalHash ||
        record.targetProposalHash !== expectedProposalHash
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target finality must bind the exact target proposal hash.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }
    if (checkpoint.targetFinalityCheckpointHash !== expectedCheckpointHash) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target finality checkpoint hash does not match its canonical payload.',
                checkpoint.targetFinalityCheckpointHash,
                'TargetFinalityCheckpoint',
            ),
        );
    }
    if (
        checkpoint.ceremonyId !== record.ceremonyId ||
        checkpoint.boardPolicyHash !== input.boardEvidence.boardPolicyHash
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target finality checkpoint does not bind the ceremony and board policy.',
                checkpoint.targetFinalityCheckpointHash,
                'TargetFinalityCheckpoint',
            ),
        );
    }
    if (
        record.targetFinalityPolicyHash !==
            targetFinalityPolicy.targetFinalityPolicyHash ||
        record.targetFinalityScope !==
            targetFinalityPolicy.targetFinalityScope ||
        checkpoint.targetFinalityPolicyHash !==
            targetFinalityPolicy.targetFinalityPolicyHash
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target finality record does not match the target-finality policy.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        record.witnessPolicyHash !== witnessPolicy.witnessPolicyHash ||
        checkpoint.witnessPolicyHash !== witnessPolicy.witnessPolicyHash
    ) {
        refusedObjects.push(
            createRefusal(
                'WitnessPolicyMismatch',
                'Target finality record does not match the witness policy.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        witnessPolicy.witnessPolicyHash !==
        deriveWitnessPolicyHash({
            totalWitnesses: witnessPolicy.totalWitnesses,
            witnessIdentities: witnessPolicy.witnessIdentities,
            witnessQuorum: witnessPolicy.witnessQuorum,
        })
    ) {
        refusedObjects.push(
            createRefusal(
                'WitnessPolicyMismatch',
                'Witness policy hash does not match its canonical payload.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        targetFinalityPolicy.targetFinalityPolicyHash !==
        deriveTargetFinalityPolicyHash({
            targetFinalityScope: targetFinalityPolicy.targetFinalityScope,
            totalWitnesses: targetFinalityPolicy.totalWitnesses,
            witnessQuorum: targetFinalityPolicy.witnessQuorum,
        })
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target-finality policy hash does not match its canonical payload.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }
    // Target finality fixes a 5-of-7 witness threshold. Both the witness policy
    // and the target-finality policy must declare exactly 7 total / 5 quorum;
    // any other witness policy is rejected.
    if (
        witnessPolicy.totalWitnesses !== 7 ||
        witnessPolicy.witnessQuorum !== 5 ||
        targetFinalityPolicy.totalWitnesses !== 7 ||
        targetFinalityPolicy.witnessQuorum !== 5
    ) {
        refusedObjects.push(
            createRefusal(
                'WitnessPolicyMismatch',
                'Target finality requires the mandatory 5-of-7 witness policy.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        witnessPolicy.witnessIdentities.length !== 7 ||
        new Set(witnessPolicy.witnessIdentities).size !== 7
    ) {
        refusedObjects.push(
            createRefusal(
                'WitnessPolicyMismatch',
                'Target finality requires seven distinct witness identities.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }
    const witnessPublicKeyHashes = witnessPolicy.witnessIdentities.map(
        (witnessIdentity) => input.witnessPublicKeyHashes[witnessIdentity],
    );
    if (
        witnessPublicKeyHashes.some(
            (publicKeyHash) => !isProtocolHashString(publicKeyHash),
        ) ||
        new Set(witnessPublicKeyHashes).size !==
            witnessPolicy.witnessIdentities.length
    ) {
        refusedObjects.push(
            createRefusal(
                'WitnessPolicyMismatch',
                'Target finality requires seven distinct canonical witness public-key Hashes.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }
    if (
        record.inclusionProof.boardHeadHash !==
            checkpoint.finalizedBoardHeadHash ||
        record.inclusionProof.includedObjectType !== 'EvaluatorReplayRecord' ||
        record.inclusionProof.includedObjectHash !==
            checkpoint.evaluatorReplayRecordHash
    ) {
        refusedObjects.push(
            createRefusal(
                'EvaluatorReplayRecordNotIncluded',
                'Target finality must finalize a board head containing the evaluator replay record hash.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }

    return refusedObjects;
};

const verifyWitnessCheckpoint = (
    input: TargetFinalityVerificationInput,
    record: TargetFinalityRecord,
    checkpoint: WitnessCheckpoint,
): readonly RefusalRecord[] => {
    const { targetFinalityPolicy, witnessPolicy } = input;
    const finalityCheckpoint = record.targetFinalityCheckpoint;
    const refusedObjects: RefusalRecord[] = [];
    const expectedCheckpointHash = deriveWitnessCheckpointHash({
        ceremonyId: checkpoint.ceremonyId,
        objectType: checkpoint.objectType,
        objectVersion: checkpoint.objectVersion,
        targetFinalityCheckpointHash: checkpoint.targetFinalityCheckpointHash,
        targetFinalityPolicyHash: checkpoint.targetFinalityPolicyHash,
        targetFinalityScope: checkpoint.targetFinalityScope,
        targetProposalHash: checkpoint.targetProposalHash,
        witnessIdentity: checkpoint.witnessIdentity,
        witnessPolicyHash: checkpoint.witnessPolicyHash,
    });
    const expectedPublicKeyHash =
        input.witnessPublicKeyHashes[checkpoint.witnessIdentity];

    if (checkpoint.checkpointHash !== expectedCheckpointHash) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Witness checkpoint hash does not match its canonical payload.',
                checkpoint.checkpointHash,
                'WitnessCheckpoint',
            ),
        );
    }
    if (!witnessPolicy.witnessIdentities.includes(checkpoint.witnessIdentity)) {
        refusedObjects.push(
            createRefusal(
                'UnknownWitness',
                'Witness checkpoint signer is not in the witness policy.',
                checkpoint.checkpointHash,
                'WitnessCheckpoint',
            ),
        );
    }
    if (
        checkpoint.objectType !== 'WitnessCheckpoint' ||
        checkpoint.objectVersion !== 1
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Witness checkpoint object shape is not canonical.',
                checkpoint.checkpointHash,
                'WitnessCheckpoint',
            ),
        );
    }
    if (expectedPublicKeyHash === undefined) {
        refusedObjects.push(
            createRefusal(
                'UnknownWitness',
                'Witness checkpoint signer has no known public key.',
                checkpoint.checkpointHash,
                'WitnessCheckpoint',
            ),
        );
    }
    if (
        checkpoint.ceremonyId !== record.ceremonyId ||
        checkpoint.targetProposalHash !== record.targetProposalHash ||
        checkpoint.targetFinalityCheckpointHash !==
            finalityCheckpoint.targetFinalityCheckpointHash ||
        checkpoint.witnessPolicyHash !== witnessPolicy.witnessPolicyHash ||
        checkpoint.targetFinalityPolicyHash !==
            targetFinalityPolicy.targetFinalityPolicyHash ||
        checkpoint.targetFinalityScope !== record.targetFinalityScope
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Witness checkpoint does not bind the exact finalized head and policies.',
                checkpoint.checkpointHash,
                'WitnessCheckpoint',
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(checkpoint.signature, {
        objectType: 'WitnessCheckpoint',
        objectVersion: 1,
        signerRole: 'Witness',
        signerIdentity: checkpoint.witnessIdentity,
        ceremonyId: record.ceremonyId,
        publicKeyHash: expectedPublicKeyHash,
        manifestHash: finalityCheckpoint.electionManifestHash,
        objectRoot: checkpoint.checkpointHash,
        boardHeadHash: finalityCheckpoint.finalizedBoardHeadHash,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: 0,
        deviceEpoch: 0,
        contextHash: defaultSignedRootContextHash,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

const collectValidWitnessIdentitiesForRecord = (
    input: TargetFinalityVerificationInput,
    record: TargetFinalityRecord,
    boardEvidence: BoardEvidence,
): readonly string[] | undefined => {
    const refusedObjects: RefusalRecord[] = [
        ...verifyTargetRecordShape(input, record),
        ...verifyBoardInclusionProof(boardEvidence, record.inclusionProof),
    ];
    const validWitnessIdentities: string[] = [];
    const seenWitnessIdentities = new Set<string>();

    for (const checkpoint of record.witnessCheckpoints) {
        if (seenWitnessIdentities.has(checkpoint.witnessIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'DuplicateWitness',
                    'Duplicate witness signatures do not count twice.',
                    record.targetFinalityRecordHash,
                    'TargetFinalityRecord',
                ),
            );
            continue;
        }
        seenWitnessIdentities.add(checkpoint.witnessIdentity);

        const checkpointRefusals = verifyWitnessCheckpoint(
            input,
            record,
            checkpoint,
        );
        refusedObjects.push(...checkpointRefusals);
        if (checkpointRefusals.length === 0) {
            validWitnessIdentities.push(checkpoint.witnessIdentity);
        }
    }

    if (validWitnessIdentities.length < input.witnessPolicy.witnessQuorum) {
        refusedObjects.push(
            createRefusal(
                'WitnessQuorumNotReached',
                'Target finality requires five distinct valid witness checkpoints.',
                record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }

    return refusedObjects.length === 0 ? validWitnessIdentities : undefined;
};

const findFinalityForkEvidence = (
    input: TargetFinalityVerificationInput,
    validWitnessIdentities: readonly string[],
    boardEvidence: BoardEvidence,
): ConflictingHeadEvidence | undefined => {
    for (const conflictingRecord of input.conflictingRecords ?? []) {
        if (
            conflictingRecord.ceremonyId !== input.record.ceremonyId ||
            conflictingRecord.targetFinalityScope !==
                input.record.targetFinalityScope ||
            conflictingRecord.targetProposalHash ===
                input.record.targetProposalHash
        ) {
            continue;
        }

        const validConflictingWitnessIdentities =
            collectValidWitnessIdentitiesForRecord(
                input,
                conflictingRecord,
                boardEvidence,
            );
        if (validConflictingWitnessIdentities === undefined) {
            continue;
        }
        const conflictingWitnesses = new Set(validConflictingWitnessIdentities);
        const equivocatingWitnessIdentities = validWitnessIdentities.filter(
            (witnessIdentity) => conflictingWitnesses.has(witnessIdentity),
        );
        // Two 5-of-7 quorums must overlap in at least 2*quorum - total =
        // 2*5 - 7 = 3 witnesses. So >=3 shared valid signers across two
        // conflicting finalized heads proves witness equivocation; fewer is
        // not conclusive and is skipped.
        if (
            equivocatingWitnessIdentities.length <
            2 * input.witnessPolicy.witnessQuorum -
                input.witnessPolicy.totalWitnesses
        ) {
            continue;
        }
        const evidence = {
            ceremonyId: input.record.ceremonyId,
            boardPolicyHash: input.boardEvidence.boardPolicyHash,
            leftBoardHeadHash:
                input.record.targetFinalityCheckpoint.finalizedBoardHeadHash,
            rightBoardHeadHash:
                conflictingRecord.targetFinalityCheckpoint
                    .finalizedBoardHeadHash,
            targetFinalityScope: input.record.targetFinalityScope,
            equivocatingWitnessIdentities,
        };

        return {
            ...evidence,
            evidenceHash: deriveWitnessEquivocationEvidenceHash(evidence),
        };
    }

    return undefined;
};

const verifyTargetFinalityUnchecked = (
    input: TargetFinalityVerificationInput,
): TargetFinalityVerification => {
    const boardEvidence = collectBoardInclusionEvidence({
        boardEvidence: input.boardEvidence,
        inclusionProof: input.record.inclusionProof,
        objectRefusals: verifyTargetRecordShape(input, input.record),
    });
    const { boardResult } = boardEvidence;
    const refusedObjects: RefusalRecord[] = [...boardEvidence.refusedObjects];
    const validWitnessIdentities: string[] = [];
    const duplicateWitnessIdentities = new Set<string>();
    const seenWitnessIdentities = new Set<string>();

    for (const checkpoint of input.record.witnessCheckpoints) {
        if (seenWitnessIdentities.has(checkpoint.witnessIdentity)) {
            duplicateWitnessIdentities.add(checkpoint.witnessIdentity);
        }
        seenWitnessIdentities.add(checkpoint.witnessIdentity);

        const checkpointRefusals = verifyWitnessCheckpoint(
            input,
            input.record,
            checkpoint,
        );
        refusedObjects.push(...checkpointRefusals);
        if (
            checkpointRefusals.length === 0 &&
            !validWitnessIdentities.includes(checkpoint.witnessIdentity)
        ) {
            validWitnessIdentities.push(checkpoint.witnessIdentity);
        }
    }

    // A witness that signed twice is dropped from the valid set entirely (not
    // merely de-duplicated), so it cannot be counted toward the quorum at all.
    for (const witnessIdentity of duplicateWitnessIdentities) {
        refusedObjects.push(
            createRefusal(
                'DuplicateWitness',
                'Duplicate witness signatures do not count twice.',
                input.record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
        const duplicateIndex = validWitnessIdentities.indexOf(witnessIdentity);
        if (duplicateIndex >= 0) {
            validWitnessIdentities.splice(duplicateIndex, 1);
        }
    }

    if (validWitnessIdentities.length < input.witnessPolicy.witnessQuorum) {
        refusedObjects.push(
            createRefusal(
                'WitnessQuorumNotReached',
                'Target finality requires five distinct valid witness checkpoints.',
                input.record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }

    const finalityForkEvidence = findFinalityForkEvidence(
        input,
        validWitnessIdentities,
        boardEvidence,
    );
    const forkEvidence = finalityForkEvidence ?? boardResult.forkEvidence;
    const equivocatingWitnessIdentities =
        forkEvidence?.equivocatingWitnessIdentities ?? [];
    const acceptedHashes = uniqueStrings([
        ...boardResult.acceptedHashes,
        input.record.targetFinalityRecordHash,
        ...input.record.witnessCheckpoints.map(
            (checkpoint) => checkpoint.checkpointHash,
        ),
    ]);
    const finalityAccepted =
        refusedObjects.length === 0 && forkEvidence === undefined;

    return {
        ok: finalityAccepted,
        acceptedHashes: finalityAccepted ? acceptedHashes : [],
        refusedObjects:
            forkEvidence === undefined
                ? refusedObjects
                : [
                      ...refusedObjects,
                      createRefusal(
                          'BoardForkDetected',
                          'Supplied target-finality evidence contains conflicting finalized heads.',
                          forkEvidence.evidenceHash,
                      ),
                  ],
        forkEvidence,
        targetFinalityRecordHash:
            refusedObjects.length === 0 && forkEvidence === undefined
                ? input.record.targetFinalityRecordHash
                : undefined,
        targetProposalHash:
            refusedObjects.length === 0 && forkEvidence === undefined
                ? input.record.targetProposalHash
                : undefined,
        targetFinalityCheckpointHash:
            refusedObjects.length === 0 && forkEvidence === undefined
                ? input.record.targetFinalityCheckpoint
                      .targetFinalityCheckpointHash
                : undefined,
        validWitnessIdentities,
        equivocatingWitnessIdentities,
    };
};

export const verifyTargetFinality = (
    input: TargetFinalityVerificationInput,
): TargetFinalityVerification => {
    try {
        return verifyTargetFinalityUnchecked(input);
    } catch (error) {
        return {
            ok: false,
            acceptedHashes: [],
            refusedObjects: [
                createRefusal(
                    'TargetFinalityPolicyMismatch',
                    verificationExceptionMessage(
                        'Target finality evidence could not be canonicalized or validated.',
                        error,
                    ),
                    undefined,
                    'TargetFinalityRecord',
                ),
            ],
            validWitnessIdentities: [],
            equivocatingWitnessIdentities: [],
        };
    }
};
