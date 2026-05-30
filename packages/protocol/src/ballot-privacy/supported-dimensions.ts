import type {
    BallotPrivacyRosterProfileEvidence,
    ProtocolHash,
    RefusalRecord,
} from '@sealed-lattice/types';

import { deriveBallotPrivacyRosterProfileEvidenceHash } from './objects/object-contracts.js';
import {
    ballotPrivacyMaximumOptionCount,
    ballotPrivacyMaximumParticipantCount,
    ballotPrivacyMandatoryReceiverCount,
    ballotPrivacyMinimumOptionCount,
    ballotPrivacyMinimumSafeClaimBearingParticipantCount,
    ballotPrivacyMinimumSafeParticipantCount,
    ballotPrivacyMinimumUnsafeParticipantCount,
    getBallotPrivacyEncodedShareVectorWidth,
} from './protocol-parameters.js';
import { createRefusal } from './verification-helpers.js';

const isPositiveSafeInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && value > 0 && !Object.is(value, -0);

const participantCountIsInSupportedRange = (
    participantCount: number,
): boolean =>
    isPositiveSafeInteger(participantCount) &&
    participantCount >= ballotPrivacyMinimumUnsafeParticipantCount &&
    participantCount <= ballotPrivacyMaximumParticipantCount;

const optionCountIsInSupportedRange = (optionCount: number): boolean =>
    isPositiveSafeInteger(optionCount) &&
    optionCount >= ballotPrivacyMinimumOptionCount &&
    optionCount <= ballotPrivacyMaximumOptionCount;

const approvedDynamicRosterProfileCertificateHashes = new Set<ProtocolHash>();

export const collectBallotPrivacyDimensionRefusals = (input: {
    readonly objectHash?: ProtocolHash;
    readonly optionCount: number;
    readonly participantCount: number;
    readonly shareVectorWidth: number;
    readonly thresholdProfileHash?: ProtocolHash;
    readonly dynamicRosterProfileEvidence?: BallotPrivacyRosterProfileEvidence;
    readonly claimBearingPackage?: boolean;
    readonly casualMicroRosterAcknowledged?: boolean;
}): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];

    if (!optionCountIsInSupportedRange(input.optionCount)) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot privacy statements support ${ballotPrivacyMinimumOptionCount} to ${ballotPrivacyMaximumOptionCount} options.`,
                input.objectHash,
            ),
        );
    }
    if (
        optionCountIsInSupportedRange(input.optionCount) &&
        input.shareVectorWidth !==
            getBallotPrivacyEncodedShareVectorWidth(input.optionCount)
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot privacy statement shareVectorWidth must equal 11 * optionCount.',
                input.objectHash,
            ),
        );
    }
    if (!participantCountIsInSupportedRange(input.participantCount)) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot privacy statements support ${ballotPrivacyMinimumUnsafeParticipantCount} to ${ballotPrivacyMaximumParticipantCount} participants.`,
                input.objectHash,
            ),
        );
        // Three security tiers by participant count: 3-9 needs an explicit
        // casualMicroRosterAcknowledged (or refuses if claim-bearing); >=10 is the
        // claim-bearing safe tier; exactly 20 (mandatory profile) skips dynamic-roster
        // evidence, while any other >=10 count requires roster-profile certificate evidence.
    } else if (
        input.participantCount < ballotPrivacyMinimumSafeParticipantCount
    ) {
        const casualMicroRosterAcknowledged =
            input.casualMicroRosterAcknowledged === true;
        if (input.claimBearingPackage === true) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Claim-bearing ballot privacy verification requires at least ${ballotPrivacyMinimumSafeClaimBearingParticipantCount} frozen participants.`,
                    input.objectHash,
                ),
            );
        } else if (!casualMicroRosterAcknowledged) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot privacy verification for ${ballotPrivacyMinimumUnsafeParticipantCount} to ${
                        ballotPrivacyMinimumSafeParticipantCount - 1
                    } participants requires explicit casual micro-roster acknowledgement.`,
                    input.objectHash,
                ),
            );
        }
    } else if (
        input.participantCount !== ballotPrivacyMandatoryReceiverCount &&
        input.dynamicRosterProfileEvidence === undefined
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Dynamic ballot privacy verification requires roster profile parameter certificate evidence for the frozen receiver count.',
                input.objectHash,
            ),
        );
    }
    if (input.dynamicRosterProfileEvidence !== undefined) {
        const evidence = input.dynamicRosterProfileEvidence;
        const evidencePayload = {
            objectType: evidence.objectType,
            objectVersion: evidence.objectVersion,
            profileFamily: evidence.profileFamily,
            frozenRosterSize: evidence.frozenRosterSize,
            optionCount: evidence.optionCount,
            thresholdProfileHash: evidence.thresholdProfileHash,
            dynamicRosterProfileCertificateHash:
                evidence.dynamicRosterProfileCertificateHash,
            receiverCoverageProfile: evidence.receiverCoverageProfile,
            proofStatementShape: evidence.proofStatementShape,
        };
        const expectedEvidenceHash =
            deriveBallotPrivacyRosterProfileEvidenceHash(evidencePayload);
        if (
            evidence.objectType !== 'BallotPrivacyRosterProfileEvidence' ||
            evidence.objectVersion !== 1 ||
            evidence.profileFamily !== 'BalancedDefault' ||
            evidence.receiverCoverageProfile !== 'AllFrozenRosterReceivers' ||
            evidence.proofStatementShape !== 'EncodedScoreBallotProof-v1' ||
            evidence.frozenRosterSize !== input.participantCount ||
            evidence.optionCount !== input.optionCount ||
            evidence.thresholdProfileHash !== input.thresholdProfileHash ||
            evidence.rosterProfileEvidenceHash !== expectedEvidenceHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Dynamic roster profile evidence is not bound to the ballot proof statement dimensions and threshold profile.',
                    input.objectHash,
                ),
            );
        }
        if (
            !approvedDynamicRosterProfileCertificateHashes.has(
                evidence.dynamicRosterProfileCertificateHash,
            )
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Dynamic roster profile evidence must reference an approved roster profile parameter certificate.',
                    input.objectHash,
                ),
            );
        }
    }

    return refusedObjects;
};

export {
    ballotPrivacyMaximumOptionCount,
    ballotPrivacyMaximumParticipantCount,
    ballotPrivacyMinimumOptionCount,
    ballotPrivacyMinimumUnsafeParticipantCount,
};
