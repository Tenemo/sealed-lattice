import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import {
    aggregateDerivationProofEncodingProfileId,
    aggregateDerivationProofParameterProfileId,
    aggregateDerivationProofProfileId,
    type AggregateDerivationComponent,
    type AggregateDerivationPackageReference,
    type AggregateDerivationProofRecord,
    type AggregateDerivationProofVerificationInput,
    type AggregateDerivationStatement,
    type AggregateShareCommitment,
    type ClaimBearingBallotPackage,
    type ProtocolDigest,
    type ShareCommitment,
    type ShareCommitmentMessageBoundCert,
} from '@sealed-lattice/types';

import { aggregateDerivationComponentId } from './aggregate-derivation/constants.js';
import {
    deriveAggregateCommitmentBodyDigest,
    deriveAggregateDerivationBallotSetDigest,
    deriveAggregateDerivationComponentDigest,
    deriveAggregateDerivationProofRecordDigest,
    deriveAggregateDerivationProofRoot,
    deriveAggregateDerivationStatementDigest,
    deriveAggregateShareCommitmentDigest,
} from './aggregate-derivation/digests.js';
import { modBigInt } from './lattice-primitives/primitive-contracts.js';
import {
    deriveProofBytesDigest,
    deriveBallotProofEncodingProfileDigest,
    deriveBallotProofParameterSetDigest,
    deriveBallotProofPublicRandomnessDigest,
    verifyClaimBearingBallotPackage,
} from './objects.js';
import {
    ballotPrivacyMinimumSafeParticipantCount,
    shareCommitmentModulus,
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
} from './protocol-parameters.js';

export { verifyAggregateDerivationComponentStructure } from './aggregate-derivation/structure-verification.js';
export { buildAggregateDerivationProofInput } from './aggregate-derivation/proof-input.js';
export {
    aggregateWitnessFromReceiverPlaintext,
    sumAggregateDerivationWitnesses,
} from './aggregate-derivation/witnesses.js';
export type { AggregateDerivationWitnessInput } from './aggregate-derivation/types.js';

const zeroCommitmentPolynomialVector = (): readonly (readonly string[])[] =>
    Array.from({ length: shareCommitmentModuleRank }, () =>
        Array.from({ length: shareCommitmentModuleDegree }, () => '0'),
    );

const addCommitmentPolynomialVectors = (
    leftVector: readonly (readonly string[])[],
    rightVector: readonly (readonly string[])[],
): readonly (readonly string[])[] => {
    if (
        leftVector.length !== shareCommitmentModuleRank ||
        rightVector.length !== shareCommitmentModuleRank
    ) {
        throw new RangeError(
            'Aggregate share commitments require canonical rank-four commitment vectors.',
        );
    }

    return leftVector.map((leftPolynomial, polynomialIndex) => {
        const rightPolynomial = rightVector[polynomialIndex];
        if (
            leftPolynomial.length !== shareCommitmentModuleDegree ||
            rightPolynomial?.length !== shareCommitmentModuleDegree
        ) {
            throw new RangeError(
                'Aggregate share commitments require degree-256 commitment polynomials.',
            );
        }

        return leftPolynomial.map((leftCoefficient, coefficientIndex) =>
            modBigInt(
                BigInt(leftCoefficient) +
                    BigInt(rightPolynomial[coefficientIndex] ?? '0'),
                shareCommitmentModulus,
            ).toString(),
        );
    });
};

const packageReferenceForContributor = (input: {
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly contributorIdentity: string;
    readonly contributorRosterPosition: number;
}): AggregateDerivationPackageReference => {
    const payloadReference =
        input.ballotPackage.ballotProofStatement.receiverPayloads.find(
            (reference) =>
                reference.receiverIdentity === input.contributorIdentity &&
                reference.receiverRosterPosition ===
                    input.contributorRosterPosition,
        );
    const commitmentReference =
        input.ballotPackage.ballotProofStatement.shareCommitments.find(
            (reference) =>
                reference.receiverIdentity === input.contributorIdentity &&
                reference.receiverRosterPosition ===
                    input.contributorRosterPosition,
        );
    if (payloadReference === undefined || commitmentReference === undefined) {
        throw new RangeError(
            'Aggregate derivation requires each counted ballot package to address the contributor.',
        );
    }

    return {
        ballotPackageDigest: input.ballotPackage.ballotPackageDigest,
        ballotProofStatementDigest:
            input.ballotPackage.ballotProofStatement.ballotProofStatementDigest,
        receiverPayloadCiphertextRoot:
            payloadReference.receiverPayloadCiphertextRoot,
        receiverPayloadDigest: payloadReference.receiverPayloadDigest,
        shareCommitmentDigest: commitmentReference.shareCommitmentDigest,
    };
};

const shareCommitmentForContributor = (input: {
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly contributorIdentity: string;
    readonly contributorRosterPosition: number;
}): ShareCommitment => {
    const shareCommitment = input.ballotPackage.shareCommitments.find(
        (commitment) =>
            commitment.receiverIdentity === input.contributorIdentity &&
            commitment.receiverRosterPosition ===
                input.contributorRosterPosition,
    );
    if (shareCommitment?.commitmentPolynomialVector === undefined) {
        throw new RangeError(
            'Aggregate derivation requires explicit public share commitment polynomials.',
        );
    }

    return shareCommitment;
};

const createAggregateShareCommitment = (input: {
    readonly ballotSetDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly contributorIdentity: string;
    readonly contributorRosterPosition: number;
    readonly manifestDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly shareCommitments: readonly ShareCommitment[];
    readonly shareCommitmentProfileDigest: ProtocolDigest;
    readonly shareVectorWidth: number;
}): AggregateShareCommitment => {
    let commitmentPolynomialVector = zeroCommitmentPolynomialVector();

    for (const shareCommitment of input.shareCommitments) {
        if (
            shareCommitment.receiverIdentity !== input.contributorIdentity ||
            shareCommitment.receiverRosterPosition !==
                input.contributorRosterPosition ||
            shareCommitment.shareCommitmentProfileDigest !==
                input.shareCommitmentProfileDigest ||
            shareCommitment.shareVectorWidth !== input.shareVectorWidth ||
            shareCommitment.commitmentPolynomialVector === undefined
        ) {
            throw new RangeError(
                'Aggregate share commitment inputs must target the same contributor and profile.',
            );
        }
        commitmentPolynomialVector = addCommitmentPolynomialVectors(
            commitmentPolynomialVector,
            shareCommitment.commitmentPolynomialVector,
        );
    }

    const commitmentBodyDigest = deriveAggregateCommitmentBodyDigest({
        commitmentPolynomialVector,
        shareCommitmentProfileDigest: input.shareCommitmentProfileDigest,
    });
    const aggregateCommitmentPayload: Omit<
        AggregateShareCommitment,
        'aggregateShareCommitmentDigest'
    > = {
        objectType: 'AggregateShareCommitment',
        objectVersion: 1,
        ballotSetDigest: input.ballotSetDigest,
        ceremonyId: input.ceremonyId,
        commitmentBodyDigest,
        commitmentPolynomialVector,
        contributorIdentity: input.contributorIdentity,
        contributorRosterPosition: input.contributorRosterPosition,
        manifestDigest: input.manifestDigest,
        pollSpecDigest: input.pollSpecDigest,
        rosterDigest: input.rosterDigest,
        shareCommitmentProfileDigest: input.shareCommitmentProfileDigest,
        shareVectorWidth: input.shareVectorWidth,
    };

    return {
        ...aggregateCommitmentPayload,
        aggregateShareCommitmentDigest: deriveAggregateShareCommitmentDigest(
            aggregateCommitmentPayload,
        ),
    };
};

const requireProofBearingPackageShell = (input: {
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly unsafeSmallRosterAcknowledged?: boolean;
}): void => {
    const missingFieldNames = [
        input.ballotPackage.proofBytesHex === undefined
            ? 'proofBytesHex'
            : undefined,
        input.ballotPackage.linearStatement === undefined
            ? 'linearStatement'
            : undefined,
        input.ballotPackage.parameterSet === undefined
            ? 'parameterSet'
            : undefined,
        input.ballotPackage.proofEncoding === undefined
            ? 'proofEncoding'
            : undefined,
        input.ballotPackage.publicRandomnessHex === undefined
            ? 'publicRandomnessHex'
            : undefined,
        input.ballotPackage.componentBundleStatement === undefined
            ? 'componentBundleStatement'
            : undefined,
        input.ballotPackage.componentProofBundle === undefined
            ? 'componentProofBundle'
            : undefined,
        input.ballotPackage.componentProofInputs === undefined
            ? 'componentProofInputs'
            : undefined,
    ].flatMap((fieldName) => (fieldName === undefined ? [] : [fieldName]));

    if (missingFieldNames.length > 0) {
        throw new RangeError(
            `Aggregate derivation counted ballot packages must carry proof-byte-bearing M5 verifier inputs; missing ${missingFieldNames.join(', ')}.`,
        );
    }

    const verification = verifyClaimBearingBallotPackage({
        ballotPackage: input.ballotPackage,
        unsafeSmallRosterAcknowledged: input.unsafeSmallRosterAcknowledged,
    });
    if (verification.unresolvedReason !== 'OperationUnavailable') {
        const refusalSummary = verification.refusedObjects
            .map((refusal) => refusal.message)
            .join(' ');
        throw new RangeError(
            `Aggregate derivation counted ballot package shell is invalid. ${refusalSummary}`,
        );
    }
};

const orderedBallotPackagesByDigest = (
    ballotPackages: readonly ClaimBearingBallotPackage[],
): readonly ClaimBearingBallotPackage[] =>
    [...ballotPackages].sort((leftPackage, rightPackage) =>
        leftPackage.ballotPackageDigest.localeCompare(
            rightPackage.ballotPackageDigest,
        ),
    );

export const buildAggregateDerivationStatement = (input: {
    readonly ballotPackages: readonly ClaimBearingBallotPackage[];
    readonly closeRecordDigest: ProtocolDigest;
    readonly contributorActionContextDigest: ProtocolDigest;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceDigest: ProtocolDigest;
    readonly contributorRosterPosition: number;
    readonly postVotingClosedContextDigest: ProtocolDigest;
    readonly unsafeSmallRosterAcknowledged?: boolean;
    readonly votingClosedBoardHeadDigest: ProtocolDigest;
}): {
    readonly aggregateCommitment: AggregateShareCommitment;
    readonly statement: AggregateDerivationStatement;
} => {
    if (input.ballotPackages.length === 0) {
        throw new RangeError(
            'Aggregate derivation requires at least one counted ballot package.',
        );
    }
    for (const ballotPackage of input.ballotPackages) {
        requireProofBearingPackageShell({
            ballotPackage,
            unsafeSmallRosterAcknowledged: input.unsafeSmallRosterAcknowledged,
        });
    }
    const orderedBallotPackages = orderedBallotPackagesByDigest(
        input.ballotPackages,
    );
    const firstStatement = orderedBallotPackages[0].ballotProofStatement;
    const ballotPackageDigests = orderedBallotPackages.map(
        (ballotPackage) => ballotPackage.ballotPackageDigest,
    );
    const uniquePackageDigests = new Set(ballotPackageDigests);
    if (uniquePackageDigests.size !== ballotPackageDigests.length) {
        throw new RangeError(
            'Aggregate derivation counted ballot packages must not contain duplicates.',
        );
    }
    for (const ballotPackage of orderedBallotPackages) {
        const statement = ballotPackage.ballotProofStatement;
        if (
            statement.ceremonyId !== firstStatement.ceremonyId ||
            statement.manifestDigest !== firstStatement.manifestDigest ||
            statement.rosterDigest !== firstStatement.rosterDigest ||
            statement.pollSpecDigest !== firstStatement.pollSpecDigest ||
            statement.thresholdProfileDigest !==
                firstStatement.thresholdProfileDigest ||
            statement.optionCount !== firstStatement.optionCount ||
            statement.shareVectorWidth !== firstStatement.shareVectorWidth ||
            statement.shareCommitmentProfileDigest !==
                firstStatement.shareCommitmentProfileDigest
        ) {
            throw new RangeError(
                'Aggregate derivation counted ballot packages must share one canonical context.',
            );
        }
    }

    const ballotSetDigest = deriveAggregateDerivationBallotSetDigest({
        ballotPackageDigests,
        closeRecordDigest: input.closeRecordDigest,
        manifestDigest: firstStatement.manifestDigest,
        pollSpecDigest: firstStatement.pollSpecDigest,
        postVotingClosedContextDigest: input.postVotingClosedContextDigest,
        rosterDigest: firstStatement.rosterDigest,
        thresholdProfileDigest: firstStatement.thresholdProfileDigest,
        votingClosedBoardHeadDigest: input.votingClosedBoardHeadDigest,
    });
    const shareCommitments = orderedBallotPackages.map((ballotPackage) =>
        shareCommitmentForContributor({
            ballotPackage,
            contributorIdentity: input.contributorIdentity,
            contributorRosterPosition: input.contributorRosterPosition,
        }),
    );
    const aggregateCommitment = createAggregateShareCommitment({
        ballotSetDigest,
        ceremonyId: firstStatement.ceremonyId,
        contributorIdentity: input.contributorIdentity,
        contributorRosterPosition: input.contributorRosterPosition,
        manifestDigest: firstStatement.manifestDigest,
        pollSpecDigest: firstStatement.pollSpecDigest,
        rosterDigest: firstStatement.rosterDigest,
        shareCommitments,
        shareCommitmentProfileDigest:
            firstStatement.shareCommitmentProfileDigest,
        shareVectorWidth: firstStatement.shareVectorWidth,
    });
    const challengeDomainDigest = deriveProtocolDigest(
        'ChallengeDomainDigest',
        {
            aggregateDerivationProofEncodingProfileId,
            aggregateDerivationProofParameterProfileId,
            aggregateDerivationProofProfileId,
            aggregateShareCommitmentDigest:
                aggregateCommitment.aggregateShareCommitmentDigest,
            ballotSetDigest,
            purpose: 'aggregate-derivation-proof-challenge-v1',
            shareCommitmentMessageBoundCertDigest:
                firstStatement.shareCommitmentMessageBoundCertDigest,
        },
    );
    const participantCount = firstStatement.receiverPublicKeys.length;
    if (
        participantCount < ballotPrivacyMinimumSafeParticipantCount &&
        input.unsafeSmallRosterAcknowledged !== true
    ) {
        throw new RangeError(
            'Aggregate derivation micro-roster participants require explicit casual acknowledgement.',
        );
    }
    if (
        participantCount >= ballotPrivacyMinimumSafeParticipantCount &&
        input.unsafeSmallRosterAcknowledged === true
    ) {
        throw new RangeError(
            'Aggregate derivation casual micro-roster acknowledgement is only valid for participants below the dynamic roster range.',
        );
    }
    const statementPayload: Omit<
        AggregateDerivationStatement,
        'aggregateDerivationStatementDigest'
    > = {
        objectType: 'AggregateDerivationStatement',
        objectVersion: 1,
        aggregateCommitmentDigest:
            aggregateCommitment.aggregateShareCommitmentDigest,
        aggregateInputEncodingProfileDigest:
            firstStatement.aggregateInputEncodingProfileDigest,
        aggregateShareCommitmentDigest:
            aggregateCommitment.aggregateShareCommitmentDigest,
        ballotScoreEncodingProfileDigest:
            firstStatement.ballotScoreEncodingProfileDigest,
        ballotSetDigest,
        ballotShareLayoutProfileDigest:
            firstStatement.ballotShareLayoutProfileDigest,
        canonicalTurnout: orderedBallotPackages.length,
        ceremonyId: firstStatement.ceremonyId,
        challengeDomainDigest,
        closeRecordDigest: input.closeRecordDigest,
        contributorActionContextDigest: input.contributorActionContextDigest,
        contributorIdentity: input.contributorIdentity,
        contributorRosterExternalAcceptanceDigest:
            input.contributorRosterExternalAcceptanceDigest,
        contributorRosterPosition: input.contributorRosterPosition,
        encodedAggregateLayoutDigest:
            firstStatement.encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            firstStatement.encodedShareVectorLayoutDigest,
        manifestDigest: firstStatement.manifestDigest,
        optionCount: firstStatement.optionCount,
        participantCount,
        packageReferences: orderedBallotPackages.map((ballotPackage) =>
            packageReferenceForContributor({
                ballotPackage,
                contributorIdentity: input.contributorIdentity,
                contributorRosterPosition: input.contributorRosterPosition,
            }),
        ),
        pollSpecDigest: firstStatement.pollSpecDigest,
        postVotingClosedContextDigest: input.postVotingClosedContextDigest,
        proofEncodingProfileId: aggregateDerivationProofEncodingProfileId,
        proofParameterProfileId: aggregateDerivationProofParameterProfileId,
        proofProfileId: aggregateDerivationProofProfileId,
        receiverEncryptionProfileDigest:
            firstStatement.receiverEncryptionProfileDigest,
        rosterDigest: firstStatement.rosterDigest,
        shareCommitmentMessageBoundCertDigest:
            firstStatement.shareCommitmentMessageBoundCertDigest,
        shareCommitmentProfileDigest:
            firstStatement.shareCommitmentProfileDigest,
        shareVectorWidth: firstStatement.shareVectorWidth,
        thresholdProfileDigest: firstStatement.thresholdProfileDigest,
        ...(input.unsafeSmallRosterAcknowledged === true
            ? { unsafeSmallRosterAcknowledged: true as const }
            : {}),
        votingClosedBoardHeadDigest: input.votingClosedBoardHeadDigest,
    };

    return {
        aggregateCommitment,
        statement: {
            ...statementPayload,
            aggregateDerivationStatementDigest:
                deriveAggregateDerivationStatementDigest(statementPayload),
        },
    };
};

const createAggregateDerivationProofRecord = (input: {
    readonly proofBytesHex: string;
    readonly proofInput: Omit<
        AggregateDerivationProofVerificationInput,
        'proofBytesHex'
    >;
    readonly statement: AggregateDerivationStatement;
}): AggregateDerivationProofRecord => {
    const proofBytesDigest = deriveProofBytesDigest({
        proofBytesHex: input.proofBytesHex,
    });
    const proofEncodingProfileDigest = deriveBallotProofEncodingProfileDigest({
        proofEncoding: input.proofInput.proofEncoding,
    });
    const proofParameterSetDigest = deriveBallotProofParameterSetDigest({
        parameterSet: input.proofInput.proofParameterSet,
    });
    const publicRandomnessDigest = deriveBallotProofPublicRandomnessDigest({
        publicRandomnessHex: input.proofInput.publicRandomnessHex,
    });
    const proofRoot = deriveAggregateDerivationProofRoot({
        componentProofStatementDigest:
            input.proofInput.componentProofStatementDigest,
        proofBytesDigest,
        proofEncodingProfileDigest,
        proofParameterSetDigest,
        publicRandomnessDigest,
        statementDigest: input.statement.aggregateDerivationStatementDigest,
    });
    const proofRecordPayload: Omit<
        AggregateDerivationProofRecord,
        'aggregateDerivationProofRecordDigest'
    > = {
        objectType: 'AggregateDerivationProofRecord',
        objectVersion: 1,
        aggregateDerivationStatementDigest:
            input.statement.aggregateDerivationStatementDigest,
        aggregateShareCommitmentDigest:
            input.statement.aggregateShareCommitmentDigest,
        componentId: aggregateDerivationComponentId,
        componentProofStatementDigest:
            input.proofInput.componentProofStatementDigest,
        proofBackend: 'LocalLinearLatticeRelation',
        proofBytesDigest,
        proofEncodingProfileDigest,
        proofParameterSetDigest,
        proofRoot,
        proofSizeBytes: input.proofBytesHex.length / 2,
        publicRandomnessDigest,
    };

    return {
        ...proofRecordPayload,
        aggregateDerivationProofRecordDigest:
            deriveAggregateDerivationProofRecordDigest(proofRecordPayload),
    };
};

export const createAggregateDerivationComponent = (input: {
    readonly aggregateCommitment: AggregateShareCommitment;
    readonly proofBytesHex: string;
    readonly proofInput: Omit<
        AggregateDerivationProofVerificationInput,
        'proofBytesHex'
    >;
    readonly shareCommitmentMessageBoundCert: ShareCommitmentMessageBoundCert;
    readonly statement: AggregateDerivationStatement;
}): AggregateDerivationComponent => {
    const proofRecord = createAggregateDerivationProofRecord({
        proofBytesHex: input.proofBytesHex,
        proofInput: input.proofInput,
        statement: input.statement,
    });
    const componentPayload: Omit<
        AggregateDerivationComponent,
        'aggregateDerivationComponentDigest'
    > = {
        objectType: 'AggregateDerivationComponent',
        objectVersion: 1,
        aggregateCommitment: input.aggregateCommitment,
        proofInput: {
            ...input.proofInput,
            proofBytesHex: input.proofBytesHex,
        },
        proofRecord,
        shareCommitmentMessageBoundCert: input.shareCommitmentMessageBoundCert,
        statement: input.statement,
    };

    return {
        ...componentPayload,
        aggregateDerivationComponentDigest:
            deriveAggregateDerivationComponentDigest(componentPayload),
    };
};
