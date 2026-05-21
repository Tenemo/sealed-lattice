import type {
    BallotPrivacyRosterProfileEvidence,
    ProtocolDigest,
    RefusalRecord,
} from '@sealed-lattice/types';

import { createRefusal } from '../common/verification-helpers.js';

import { deriveBallotPrivacyRosterProfileEvidenceDigest } from './objects/object-contracts.js';
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

export const collectBallotPrivacyDimensionRefusals = (input: {
    readonly objectDigest?: ProtocolDigest;
    readonly optionCount: number;
    readonly participantCount: number;
    readonly shareVectorWidth: number;
    readonly thresholdProfileDigest?: ProtocolDigest;
    readonly dynamicRosterProfileEvidence?: BallotPrivacyRosterProfileEvidence;
    readonly claimBearingPackage?: boolean;
    readonly casualMicroRosterAcknowledged?: boolean;
    readonly unsafeSmallRosterAcknowledged?: boolean;
}): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];

    if (!optionCountIsInSupportedRange(input.optionCount)) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot privacy statements support ${ballotPrivacyMinimumOptionCount} to ${ballotPrivacyMaximumOptionCount} options.`,
                input.objectDigest,
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
                input.objectDigest,
            ),
        );
    }
    if (!participantCountIsInSupportedRange(input.participantCount)) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot privacy statements support ${ballotPrivacyMinimumUnsafeParticipantCount} to ${ballotPrivacyMaximumParticipantCount} participants.`,
                input.objectDigest,
            ),
        );
    } else if (
        input.participantCount < ballotPrivacyMinimumSafeParticipantCount
    ) {
        const casualMicroRosterAcknowledged =
            input.casualMicroRosterAcknowledged === true ||
            input.unsafeSmallRosterAcknowledged === true;
        if (input.claimBearingPackage === true) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Claim-bearing ballot privacy verification requires at least ${ballotPrivacyMinimumSafeClaimBearingParticipantCount} frozen participants.`,
                    input.objectDigest,
                ),
            );
        } else if (!casualMicroRosterAcknowledged) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot privacy verification for ${ballotPrivacyMinimumUnsafeParticipantCount} to ${
                        ballotPrivacyMinimumSafeParticipantCount - 1
                    } participants requires explicit casual micro-roster acknowledgement.`,
                    input.objectDigest,
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
                'Dynamic claim-bearing ballot privacy verification requires roster profile certificate or workbook evidence for the frozen receiver count.',
                input.objectDigest,
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
            thresholdProfileDigest: evidence.thresholdProfileDigest,
            dynamicRosterProfileCertificateDigest:
                evidence.dynamicRosterProfileCertificateDigest,
            receiverCoverageProfile: evidence.receiverCoverageProfile,
            proofStatementShape: evidence.proofStatementShape,
        };
        const expectedEvidenceDigest =
            deriveBallotPrivacyRosterProfileEvidenceDigest(evidencePayload);
        if (
            evidence.objectType !== 'BallotPrivacyRosterProfileEvidence' ||
            evidence.objectVersion !== 1 ||
            evidence.profileFamily !== 'BalancedDefault' ||
            evidence.receiverCoverageProfile !== 'AllFrozenRosterReceivers' ||
            evidence.proofStatementShape !== 'M5EncodedScoreBallotProof-v1' ||
            evidence.frozenRosterSize !== input.participantCount ||
            evidence.optionCount !== input.optionCount ||
            evidence.thresholdProfileDigest !== input.thresholdProfileDigest ||
            evidence.rosterProfileEvidenceDigest !== expectedEvidenceDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Dynamic roster profile evidence is not bound to the ballot proof statement dimensions and threshold profile.',
                    input.objectDigest,
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
