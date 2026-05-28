import { deriveProtocolHash } from '@sealed-lattice/crypto';
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
    type ProtocolHash,
    type ShareCommitment,
    type ShareCommitmentMessageBoundCert,
} from '@sealed-lattice/types';

import { aggregateDerivationComponentId } from './aggregate-derivation/constants.js';
import {
    deriveAggregateCommitmentBodyHash,
    deriveAggregateDerivationBallotSetHash,
    deriveAggregateDerivationComponentHash,
    deriveAggregateDerivationProofRecordHash,
    deriveAggregateDerivationProofRoot,
    deriveAggregateDerivationStatementHash,
    deriveAggregateShareCommitmentHash,
} from './aggregate-derivation/hashes.js';
import { modBigInt } from './lattice-primitives/primitive-contracts.js';
import {
    deriveProofBytesHash,
    deriveBallotProofEncodingProfileHash,
    deriveBallotProofParameterSetHash,
    deriveBallotProofPublicRandomnessHash,
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
        ballotPackageHash: input.ballotPackage.ballotPackageHash,
        ballotProofStatementHash:
            input.ballotPackage.ballotProofStatement.ballotProofStatementHash,
        receiverPayloadCiphertextRoot:
            payloadReference.receiverPayloadCiphertextRoot,
        receiverPayloadHash: payloadReference.receiverPayloadHash,
        shareCommitmentHash: commitmentReference.shareCommitmentHash,
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
    readonly ballotSetHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly contributorIdentity: string;
    readonly contributorRosterPosition: number;
    readonly manifestHash: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly shareCommitments: readonly ShareCommitment[];
    readonly shareCommitmentProfileHash: ProtocolHash;
    readonly shareVectorWidth: number;
}): AggregateShareCommitment => {
    let commitmentPolynomialVector = zeroCommitmentPolynomialVector();

    for (const shareCommitment of input.shareCommitments) {
        if (
            shareCommitment.receiverIdentity !== input.contributorIdentity ||
            shareCommitment.receiverRosterPosition !==
                input.contributorRosterPosition ||
            shareCommitment.shareCommitmentProfileHash !==
                input.shareCommitmentProfileHash ||
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

    const commitmentBodyHash = deriveAggregateCommitmentBodyHash({
        commitmentPolynomialVector,
        shareCommitmentProfileHash: input.shareCommitmentProfileHash,
    });
    const aggregateCommitmentPayload: Omit<
        AggregateShareCommitment,
        'aggregateShareCommitmentHash'
    > = {
        objectType: 'AggregateShareCommitment',
        objectVersion: 1,
        ballotSetHash: input.ballotSetHash,
        ceremonyId: input.ceremonyId,
        commitmentBodyHash,
        commitmentPolynomialVector,
        contributorIdentity: input.contributorIdentity,
        contributorRosterPosition: input.contributorRosterPosition,
        manifestHash: input.manifestHash,
        pollSpecHash: input.pollSpecHash,
        rosterHash: input.rosterHash,
        shareCommitmentProfileHash: input.shareCommitmentProfileHash,
        shareVectorWidth: input.shareVectorWidth,
    };

    return {
        ...aggregateCommitmentPayload,
        aggregateShareCommitmentHash: deriveAggregateShareCommitmentHash(
            aggregateCommitmentPayload,
        ),
    };
};

const requireProofBearingPackageShell = (input: {
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly casualMicroRosterAcknowledged?: boolean;
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
        casualMicroRosterAcknowledged: input.casualMicroRosterAcknowledged,
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

const orderedBallotPackagesByHash = (
    ballotPackages: readonly ClaimBearingBallotPackage[],
): readonly ClaimBearingBallotPackage[] =>
    [...ballotPackages].sort((leftPackage, rightPackage) =>
        leftPackage.ballotPackageHash.localeCompare(
            rightPackage.ballotPackageHash,
        ),
    );

export const buildAggregateDerivationStatement = (input: {
    readonly ballotPackages: readonly ClaimBearingBallotPackage[];
    readonly closeRecordHash: ProtocolHash;
    readonly contributorActionContextHash: ProtocolHash;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceHash: ProtocolHash;
    readonly contributorRosterPosition: number;
    readonly postVotingClosedContextHash: ProtocolHash;
    readonly casualMicroRosterAcknowledged?: boolean;
    readonly votingClosedBoardHeadHash: ProtocolHash;
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
            casualMicroRosterAcknowledged: input.casualMicroRosterAcknowledged,
        });
    }
    const orderedBallotPackages = orderedBallotPackagesByHash(
        input.ballotPackages,
    );
    const firstStatement = orderedBallotPackages[0].ballotProofStatement;
    const ballotPackageHashes = orderedBallotPackages.map(
        (ballotPackage) => ballotPackage.ballotPackageHash,
    );
    const uniquePackageHashes = new Set(ballotPackageHashes);
    if (uniquePackageHashes.size !== ballotPackageHashes.length) {
        throw new RangeError(
            'Aggregate derivation counted ballot packages must not contain duplicates.',
        );
    }
    for (const ballotPackage of orderedBallotPackages) {
        const statement = ballotPackage.ballotProofStatement;
        if (
            statement.ceremonyId !== firstStatement.ceremonyId ||
            statement.manifestHash !== firstStatement.manifestHash ||
            statement.rosterHash !== firstStatement.rosterHash ||
            statement.pollSpecHash !== firstStatement.pollSpecHash ||
            statement.thresholdProfileHash !==
                firstStatement.thresholdProfileHash ||
            statement.optionCount !== firstStatement.optionCount ||
            statement.shareVectorWidth !== firstStatement.shareVectorWidth ||
            statement.shareCommitmentProfileHash !==
                firstStatement.shareCommitmentProfileHash
        ) {
            throw new RangeError(
                'Aggregate derivation counted ballot packages must share one canonical context.',
            );
        }
    }

    const ballotSetHash = deriveAggregateDerivationBallotSetHash({
        ballotPackageHashes,
        closeRecordHash: input.closeRecordHash,
        manifestHash: firstStatement.manifestHash,
        pollSpecHash: firstStatement.pollSpecHash,
        postVotingClosedContextHash: input.postVotingClosedContextHash,
        rosterHash: firstStatement.rosterHash,
        thresholdProfileHash: firstStatement.thresholdProfileHash,
        votingClosedBoardHeadHash: input.votingClosedBoardHeadHash,
    });
    const shareCommitments = orderedBallotPackages.map((ballotPackage) =>
        shareCommitmentForContributor({
            ballotPackage,
            contributorIdentity: input.contributorIdentity,
            contributorRosterPosition: input.contributorRosterPosition,
        }),
    );
    const aggregateCommitment = createAggregateShareCommitment({
        ballotSetHash,
        ceremonyId: firstStatement.ceremonyId,
        contributorIdentity: input.contributorIdentity,
        contributorRosterPosition: input.contributorRosterPosition,
        manifestHash: firstStatement.manifestHash,
        pollSpecHash: firstStatement.pollSpecHash,
        rosterHash: firstStatement.rosterHash,
        shareCommitments,
        shareCommitmentProfileHash: firstStatement.shareCommitmentProfileHash,
        shareVectorWidth: firstStatement.shareVectorWidth,
    });
    const challengeDomainHash = deriveProtocolHash('ChallengeDomainHash', {
        aggregateDerivationProofEncodingProfileId,
        aggregateDerivationProofParameterProfileId,
        aggregateDerivationProofProfileId,
        aggregateShareCommitmentHash:
            aggregateCommitment.aggregateShareCommitmentHash,
        ballotSetHash,
        purpose: 'aggregate-derivation-proof-challenge-v1',
        shareCommitmentMessageBoundCertHash:
            firstStatement.shareCommitmentMessageBoundCertHash,
    });
    const participantCount = firstStatement.receiverPublicKeys.length;
    if (
        participantCount < ballotPrivacyMinimumSafeParticipantCount &&
        input.casualMicroRosterAcknowledged !== true
    ) {
        throw new RangeError(
            'Aggregate derivation micro-roster participants require explicit casual acknowledgement.',
        );
    }
    if (
        participantCount >= ballotPrivacyMinimumSafeParticipantCount &&
        input.casualMicroRosterAcknowledged === true
    ) {
        throw new RangeError(
            'Aggregate derivation casual micro-roster acknowledgement is only valid for participants below the dynamic roster range.',
        );
    }
    const statementPayload: Omit<
        AggregateDerivationStatement,
        'aggregateDerivationStatementHash'
    > = {
        objectType: 'AggregateDerivationStatement',
        objectVersion: 1,
        aggregateCommitmentHash:
            aggregateCommitment.aggregateShareCommitmentHash,
        aggregateInputEncodingProfileHash:
            firstStatement.aggregateInputEncodingProfileHash,
        aggregateShareCommitmentHash:
            aggregateCommitment.aggregateShareCommitmentHash,
        ballotScoreEncodingProfileHash:
            firstStatement.ballotScoreEncodingProfileHash,
        ballotSetHash,
        ballotShareLayoutProfileHash:
            firstStatement.ballotShareLayoutProfileHash,
        canonicalTurnout: orderedBallotPackages.length,
        ceremonyId: firstStatement.ceremonyId,
        challengeDomainHash,
        closeRecordHash: input.closeRecordHash,
        contributorActionContextHash: input.contributorActionContextHash,
        contributorIdentity: input.contributorIdentity,
        contributorRosterExternalAcceptanceHash:
            input.contributorRosterExternalAcceptanceHash,
        contributorRosterPosition: input.contributorRosterPosition,
        encodedAggregateLayoutHash: firstStatement.encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash:
            firstStatement.encodedShareVectorLayoutHash,
        manifestHash: firstStatement.manifestHash,
        optionCount: firstStatement.optionCount,
        participantCount,
        packageReferences: orderedBallotPackages.map((ballotPackage) =>
            packageReferenceForContributor({
                ballotPackage,
                contributorIdentity: input.contributorIdentity,
                contributorRosterPosition: input.contributorRosterPosition,
            }),
        ),
        pollSpecHash: firstStatement.pollSpecHash,
        postVotingClosedContextHash: input.postVotingClosedContextHash,
        proofEncodingProfileId: aggregateDerivationProofEncodingProfileId,
        proofParameterProfileId: aggregateDerivationProofParameterProfileId,
        proofProfileId: aggregateDerivationProofProfileId,
        receiverEncryptionProfileHash:
            firstStatement.receiverEncryptionProfileHash,
        rosterHash: firstStatement.rosterHash,
        shareCommitmentMessageBoundCertHash:
            firstStatement.shareCommitmentMessageBoundCertHash,
        shareCommitmentProfileHash: firstStatement.shareCommitmentProfileHash,
        shareVectorWidth: firstStatement.shareVectorWidth,
        thresholdProfileHash: firstStatement.thresholdProfileHash,
        ...(input.casualMicroRosterAcknowledged === true
            ? { casualMicroRosterAcknowledged: true as const }
            : {}),
        votingClosedBoardHeadHash: input.votingClosedBoardHeadHash,
    };

    return {
        aggregateCommitment,
        statement: {
            ...statementPayload,
            aggregateDerivationStatementHash:
                deriveAggregateDerivationStatementHash(statementPayload),
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
    const proofBytesHash = deriveProofBytesHash({
        proofBytesHex: input.proofBytesHex,
    });
    const proofEncodingProfileHash = deriveBallotProofEncodingProfileHash({
        proofEncoding: input.proofInput.proofEncoding,
    });
    const proofParameterSetHash = deriveBallotProofParameterSetHash({
        parameterSet: input.proofInput.proofParameterSet,
    });
    const publicRandomnessHash = deriveBallotProofPublicRandomnessHash({
        publicRandomnessHex: input.proofInput.publicRandomnessHex,
    });
    const proofRoot = deriveAggregateDerivationProofRoot({
        componentProofStatementHash:
            input.proofInput.componentProofStatementHash,
        proofBytesHash,
        proofEncodingProfileHash,
        proofParameterSetHash,
        publicRandomnessHash,
        statementHash: input.statement.aggregateDerivationStatementHash,
    });
    const proofRecordPayload: Omit<
        AggregateDerivationProofRecord,
        'aggregateDerivationProofRecordHash'
    > = {
        objectType: 'AggregateDerivationProofRecord',
        objectVersion: 1,
        aggregateDerivationStatementHash:
            input.statement.aggregateDerivationStatementHash,
        aggregateShareCommitmentHash:
            input.statement.aggregateShareCommitmentHash,
        componentId: aggregateDerivationComponentId,
        componentProofStatementHash:
            input.proofInput.componentProofStatementHash,
        proofBackend: 'LocalLinearLatticeRelation',
        proofBytesHash,
        proofEncodingProfileHash,
        proofParameterSetHash,
        proofRoot,
        proofSizeBytes: input.proofBytesHex.length / 2,
        publicRandomnessHash,
    };

    return {
        ...proofRecordPayload,
        aggregateDerivationProofRecordHash:
            deriveAggregateDerivationProofRecordHash(proofRecordPayload),
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
        'aggregateDerivationComponentHash'
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
        aggregateDerivationComponentHash:
            deriveAggregateDerivationComponentHash(componentPayload),
    };
};
