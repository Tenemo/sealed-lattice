import assert from 'node:assert/strict';

import type {
    ParticipantLimits,
    ParticipantProfile,
} from '#packages/sdk/src/participant/worker/bounds.js';
import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import { compileContributionAuthenticationCensus } from '#tests/contribution-authentication-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileFullWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { compileParticipantCloseCustody } from '#tests/participant-close-custody-model.js';
import { compileParticipantCustodyCensus } from '#tests/participant-custody-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-contribution-relation-model.js';
import {
    ballotScoreRange,
    deriveSupportedProfile,
    supportedProfileRanges,
} from '#tests/supported-profile-model.js';
import { compileTargetSigningStateCensus } from '#tests/target-signing-state-model.js';

const number = (value: bigint) => {
    const converted = Number(value);
    assert.ok(Number.isSafeInteger(converted) && BigInt(converted) === value);
    return converted;
};

// Every bound the participant worker enforces for one profile, derived
// independently from the profile's owning models.
export const compileParticipantRuntimeProfile = (
    participantCount: number,
    optionCount: number,
): ParticipantProfile => {
    const profile = deriveSupportedProfile(participantCount, optionCount);
    const key = compileRegistrationKeyRelationCensus();
    const enrollment = compileRegistrationEnrollmentCensus();
    const custody = compileParticipantCustodyCensus(profile);
    const body = compileContributionBodyCensus(profile);
    const checkpoint = compileFirstOracleCheckpointCensus(profile);
    const relation = compileSetupContributionRelationCensus(profile);
    const authentication =
        compileContributionAuthenticationCensus(participantCount);
    const ballotBody = compileBallotBodyCensus(profile);
    const ballotCustody = compileParticipantBallotCustody(profile);
    const closeWire = compileCloseWireCensus(profile);
    const closeCustody = compileParticipantCloseCustody(profile);
    const targetState = compileTargetSigningStateCensus();
    const releaseCustody = compileParticipantReleaseCustody(profile);
    return {
        participantCount,
        optionCount,
        setupContributorCount: profile.setupContributorCount,
        proposalBytes: number(
            compileRosterProposalCensus(participantCount).proposalBytes,
        ),
        registration: {
            publicKeyBytes: number(key.publicKeyBytes),
            maximumProofBytes: number(key.maximumProofBytes),
            maximumHeaderBytes: number(enrollment.maximumHeaderBytes),
            maximumPollDefinitionBytes: number(
                enrollment.maximumPollDefinitionBytes,
            ),
            maximumUsernameIngressBytes: number(
                enrollment.maximumUsernameIngressBytes,
            ),
            signatureBytes: number(enrollment.signatureBytes),
            recipientCapsuleBytes: number(enrollment.recipientCapsuleBytes),
            signingCapsuleBytes: number(enrollment.signingCapsuleBytes),
            maximumSourceCapsuleBytes: number(
                enrollment.maximumSourceCapsuleBytes,
            ),
            maximumProposalBytes: number(enrollment.maximumProposalBytes),
            retainedRegistrationBytes: number(
                enrollment.retainedRegistrationBytes,
            ),
        },
        root: {
            maximumRecords: number(custody.maximumRootRecords),
            maximumRootBytes: number(custody.maximumRootBytes),
            setupReferenceBytes: number(custody.setupReferenceBytes),
            setupInventoryBytes: number(custody.setupInventoryBytes),
            retainedRosterBytes: number(
                compileRosterProposalCensus(participantCount)
                    .retainedRosterBytes,
            ),
        },
        contribution: {
            expandedPolynomials: number(
                relation.expandedStatementPolynomialCount,
            ),
            firstOracleColumns: relation.wordColumns + relation.booleanColumns,
            statementBytes: number(relation.expandedStatementByteLength),
            saltBytes: number(body.saltBytes),
            bodyHeaderBytes: number(body.headerBytes),
            proofHeaderBytes: number(
                compileFullWordProofLayout(profile).headerBytes,
            ),
            minimumProofBytes: number(body.minimumProofBytes),
            maximumProofBytes: number(body.maximumProofBytes),
            maximumStateBytes: number(custody.maximumMetadataBytes),
            maximumCheckpointHeaderBytes: number(checkpoint.maximumHeaderBytes),
            confirmationBodyBytes: number(authentication.confirmationBodyBytes),
            openingBodyBytes: number(authentication.openingBodyBytes),
            confirmationPacketBytes: number(
                authentication.confirmationPacketBytes,
            ),
            requiredStorageBytes: number(custody.maximumRetainedPayloadBytes),
            polynomials: body.polynomials.map((polynomial) => ({
                expandedIndex: polynomial.expandedIndex,
                bytes: number(polynomial.bytes),
                coefficients: number(polynomial.coefficients),
            })),
            publicRecords: custody.publicRecords.map((record) => ({
                object: record.object,
                offset: number(record.offset),
                length: number(record.length),
            })),
            checkpointLengths: custody.checkpointLengths.map(number),
        },
        ballot: {
            minimumScore: ballotScoreRange.minimum,
            maximumScore: ballotScoreRange.maximum,
            recordBytes: number(ballotCustody.recordBytes),
            maximumStateBytes: number(ballotCustody.maximumStateBytes),
            headerBytes: number(ballotBody.headerBytes),
            minimumBodyBytes: number(
                ballotBody.headerBytes +
                    ballotBody.ciphertextBytes +
                    ballotBody.minimumProofBytes,
            ),
            maximumBodyBytes: number(ballotBody.maximumBodyBytes),
            envelopeBytes: number(ballotBody.envelopeBytes),
            requiredStorageBytes: number(
                ballotCustody.maximumEncryptedBodyBytes +
                    ballotCustody.maximumStateBytes +
                    custody.maximumRootBytes,
            ),
        },
        close: {
            quorum: number(closeWire.closeQuorum),
            submissionBytes: number(closeWire.submissionBytes),
            intentBodyBytes: number(closeWire.intentBodyBytes),
            minimumResponseBodyBytes: number(
                closeWire.minimumResponseBodyBytes,
            ),
            maximumResponseBodyBytes: number(
                closeWire.maximumResponseBodyBytes,
            ),
            proposalBodyBytes: number(closeWire.proposalBodyBytes),
            maximumResponseRecordBytes: number(
                closeWire.maximumResponsePacketBytes +
                    closeWire.maximumResponseEntries *
                        closeWire.submissionBytes,
            ),
            maximumEvents: number(closeCustody.maximumEvents),
            maximumRecords: number(closeCustody.maximumRecords),
            maximumStateBytes: number(closeCustody.maximumStateBytes),
        },
        target: {
            maximumBodyBytes: number(targetState.maximumBodyBytes),
            votePacketBytes: number(targetState.packetBytes),
            maximumStateBytes: number(targetState.maximumStateBytes),
        },
        release: {
            recordBytes: number(releaseCustody.recordBytes),
            bodyHeaderBytes: number(releaseCustody.bodyHeaderBytes),
            minimumBodyBytes: number(releaseCustody.minimumBodyBytes),
            maximumBodyBytes: number(releaseCustody.maximumBodyBytes),
            envelopeBytes: number(releaseCustody.envelopeBytes),
            maximumStateBytes: number(releaseCustody.maximumStateBytes),
        },
        evaluation: {
            polynomialDegree: number(fixedModulusBfvInputs.polynomialDegree),
            // Whole 64-bit words of the ciphertext modulus's bit length.
            storedCoefficientBytes:
                8 *
                Math.ceil(profile.ciphertext.modulus.toString(2).length / 64),
        },
    };
};

// The bounds every profile shares. Before the roster names a profile, a root
// and its setup reference are bounded by the largest supported profile's;
// the bounds test checks that no supported profile exceeds them.
export const compileParticipantRuntimeLimits = (): ParticipantLimits => {
    const ranges = supportedProfileRanges();
    const largest = compileParticipantRuntimeProfile(
        ranges.participants.maximum,
        ranges.options.maximum,
    );
    return {
        participants: ranges.participants,
        options: ranges.options,
        registration: largest.registration,
        root: {
            maximumRecords: largest.root.maximumRecords,
            maximumEnrollmentRootBytes: number(
                compileRegistrationEnrollmentCensus().maximumRootBytes,
            ),
            maximumRootBytes: largest.root.maximumRootBytes,
            maximumSetupReferenceBytes: largest.root.setupReferenceBytes,
            maximumSetupInventoryBytes: largest.root.setupInventoryBytes,
            maximumRetainedRosterBytes: largest.root.retainedRosterBytes,
        },
    };
};
