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
    type AggregateDerivationVerification,
    type AggregateShareCommitment,
    type ClaimBearingBallotPackage,
    type ProtocolDigest,
    type RefusalRecord,
    type ShareCommitment,
    type ShareCommitmentMessageBoundCert,
} from '@sealed-lattice/types';

import { createRefusal } from '../common/verification-helpers.js';

import type {
    DensePolynomial,
    SparseMatrixEntry,
    SparseTargetVectorEntry,
} from './ballot-proof-linear-statement/statement-contracts.js';
import {
    linearProofRelation,
    polynomialCoefficient,
} from './ballot-proof-linear-statement/statement-contracts.js';
import {
    deriveSparseStatementMatrixDigest,
    deriveSparseTargetVectorDigest,
} from './ballot-proof-linear-statement/statement-digests.js';
import {
    deriveShareCommitmentMessageMatrix,
    deriveShareCommitmentRandomnessMatrix,
    modBigInt,
} from './lattice-primitives/primitive-contracts.js';
import {
    deriveProofBytesDigest,
    deriveBallotProofEncodingProfileDigest,
    deriveBallotProofParameterSetDigest,
    deriveBallotProofPublicRandomnessDigest,
    verifyClaimBearingBallotPackage,
} from './objects.js';
import {
    createBallotPrivacyProfileSet,
    verifyShareCommitmentMessageBoundCert,
} from './profiles.js';
import {
    ballotPrivacyEncodedCoordinatesPerOption,
    ballotPrivacyFieldModulus,
    ballotPrivacyMaximumCanonicalFieldElement,
    ballotPrivacyMaximumParticipantCount,
    ballotPrivacyMinimumSafeParticipantCount,
    getBallotPrivacyEncodedShareVectorWidth,
    shareCommitmentModulus,
    shareCommitmentModulusDecimal,
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
    shareCommitmentOpeningDimension,
} from './protocol-parameters.js';
import {
    collectBallotPrivacyDimensionRefusals,
    ballotPrivacyMinimumUnsafeParticipantCount,
} from './supported-dimensions.js';

type AggregateDerivationProofParameterSet = {
    readonly coefficientModulus: string;
    readonly expectedProofSizeBytes?: number;
    readonly profileId: typeof aggregateDerivationProofParameterProfileId;
    readonly proofSystemRingDegree: 64;
    readonly relation: 'A*w + t = 0';
    readonly ringDegree: 256;
    readonly source: string;
    readonly statementColumns: number;
    readonly statementRows: number;
    readonly witnessL2BoundSquared: number;
};

type AggregateDerivationProofEncoding = {
    readonly challengeCoefficientBitLength: 5;
    readonly challengeCoefficientModulus: 17;
    readonly coefficientModulus: string;
    readonly compressedCoefficientBitLength: 35;
    readonly compressedCommitmentVectorLength: 18;
    readonly euclideanResponseLog2StandardDeviation: 14;
    readonly euclideanResponseVectorLength: 4;
    readonly expectedProofSizeBytes?: number;
    readonly fullSizeCoefficientBitLength: 47;
    readonly hashMaskVectorLength: 2;
    readonly hintVectorLength: 18;
    readonly infinityResponseLog2StandardDeviation: 22;
    readonly infinityResponseVectorLength: 4;
    readonly profileId: typeof aggregateDerivationProofEncodingProfileId;
    readonly randomnessResponseLog2StandardDeviation: 12;
    readonly randomnessResponseVectorLength: 41;
    readonly ringDegree: 64;
    readonly shortResponseLog2StandardDeviation: 18;
    readonly shortResponseVectorLength: number;
    readonly source: string;
    readonly targetCommitmentVectorLength: 12;
};

type AggregateDerivationProofStatement = {
    readonly aggregateDerivationStatementDigest: ProtocolDigest;
    readonly aggregateShareCommitmentDigest: ProtocolDigest;
    readonly coefficientModulus: string;
    readonly componentId: typeof aggregateDerivationComponentId;
    readonly matrixCoefficientRepresentation: 'centeredSignedSourceModulus';
    readonly objectType: 'AggregateDerivationSparseLinearProofStatement';
    readonly objectVersion: 1;
    readonly parameterProfileId: typeof aggregateDerivationProofParameterProfileId;
    readonly proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1';
    readonly projectionCoverage: 'aggregate-derivation-full-encoded-layout';
    readonly relation: 'A*w + t = 0';
    readonly sourceRingDegree: 256;
    readonly sparseStatementMatrixDigest: ProtocolDigest;
    readonly sparseStatementMatrixEntries: readonly SparseMatrixEntry[];
    readonly sparseStatementTermCount: string;
    readonly statementColumns: number;
    readonly statementDigest: ProtocolDigest;
    readonly statementRows: number;
    readonly targetCoefficientRepresentation: 'centeredSignedSourceModulus';
    readonly targetVectorDigest: ProtocolDigest;
    readonly targetVectorEntries: readonly SparseTargetVectorEntry[];
    readonly targetVectorEntryCount: string;
    readonly witnessL2BoundSquared: string;
};

export type AggregateDerivationWitnessInput = {
    readonly aggregateIntegerShareVector: readonly number[];
    readonly aggregateOpeningRandomness: readonly number[];
};

type AggregateDerivationProofBuildInput = {
    readonly aggregateCommitment: AggregateShareCommitment;
    readonly statement: AggregateDerivationStatement;
    readonly witness: AggregateDerivationWitnessInput;
};

type AggregateDerivationProofBuildOutput = {
    readonly proofEncoding: AggregateDerivationProofEncoding;
    readonly proofInput: Omit<
        AggregateDerivationProofVerificationInput,
        'proofBytesHex'
    >;
    readonly proofParameterSet: AggregateDerivationProofParameterSet;
    readonly proofStatement: AggregateDerivationProofStatement;
    readonly secretState: {
        readonly sourceWitnessCoefficients: readonly DensePolynomial[];
    };
};

const aggregateDerivationComponentId =
    'aggregate-derivation-component' as const;

const aggregateDerivationSourceRingDegree = 256 as const;

const aggregateDerivationProofSystemRingDegree = 64 as const;

const aggregateDerivationProofCoefficientModulus = '70368744177829' as const;

const aggregateDerivationWitnessL2BoundSquared = 3_000_000_000_000_000 as const;

const protocolDigestPattern = /^[a-f0-9]{128}$/u;

const lowercaseHexBytesPattern = /^(?:[a-f0-9]{2})+$/u;

const forbiddenPublicWitnessFieldNames = new Set([
    'aggregateIntegerShareVector',
    'aggregateOpeningRandomness',
    'aggregateShareVector',
    'bridgeWitness',
    'openingRandomness',
    'plaintext',
    'proofWitness',
    'quotient',
    'receiverPlaintext',
    'receiverSecretState',
    'reducedFieldVector',
    'secretState',
    'sourceWitnessCoefficients',
    'witness',
]);

const createAggregateRefusal = (
    message: string,
    objectDigest?: ProtocolDigest,
): RefusalRecord =>
    createRefusal('BallotPackageInvalid', message, objectDigest);

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

const deriveAggregateCommitmentBodyDigest = (input: {
    readonly commitmentPolynomialVector: readonly (readonly string[])[];
    readonly shareCommitmentProfileDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('AggregateShareCommitmentDigest', {
        commitmentPolynomialVector: input.commitmentPolynomialVector,
        profileDigest: input.shareCommitmentProfileDigest,
        purpose: 'aggregate-share-commitment-body-v1',
    });

const deriveAggregateShareCommitmentDigest = (
    aggregateCommitment: Omit<
        AggregateShareCommitment,
        'aggregateShareCommitmentDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('AggregateShareCommitmentDigest', aggregateCommitment);

const deriveAggregateDerivationStatementDigest = (
    statement: Omit<
        AggregateDerivationStatement,
        'aggregateDerivationStatementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('AggregateDerivationComponentDigest', {
        purpose: 'aggregate-derivation-statement-v1',
        statement,
    });

const deriveAggregateDerivationProofRecordDigest = (
    proofRecord: Omit<
        AggregateDerivationProofRecord,
        'aggregateDerivationProofRecordDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('AggregateDerivationComponentDigest', {
        proofRecord,
        purpose: 'aggregate-derivation-proof-record-v1',
    });

const deriveAggregateDerivationComponentDigest = (
    component: Omit<
        AggregateDerivationComponent,
        'aggregateDerivationComponentDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('AggregateDerivationComponentDigest', {
        component,
        purpose: 'aggregate-derivation-component-v1',
    });

const deriveAggregateSparseLinearStatementDigest = (
    statementPayload: Omit<
        AggregateDerivationProofStatement,
        'statementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'aggregate-derivation-sparse-linear-proof-statement-v1',
    });

const deriveAggregateDerivationProofRoot = (input: {
    readonly componentProofStatementDigest: ProtocolDigest;
    readonly proofBytesDigest: ProtocolDigest;
    readonly proofEncodingProfileDigest: ProtocolDigest;
    readonly proofParameterSetDigest: ProtocolDigest;
    readonly publicRandomnessDigest: ProtocolDigest;
    readonly statementDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        ...input,
        componentId: aggregateDerivationComponentId,
        purpose: 'aggregate-derivation-proof-root-v1',
    });

const deriveAggregateDerivationBallotSetDigest = (input: {
    readonly ballotPackageDigests: readonly ProtocolDigest[];
    readonly closeRecordDigest: ProtocolDigest;
    readonly manifestDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly postVotingClosedContextDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly votingClosedBoardHeadDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('BallotSetDigest', {
        ballotPackageDigests: input.ballotPackageDigests,
        closeRecordDigest: input.closeRecordDigest,
        manifestDigest: input.manifestDigest,
        pollSpecDigest: input.pollSpecDigest,
        postVotingClosedContextDigest: input.postVotingClosedContextDigest,
        purpose: 'm6-post-close-counted-m5-ballot-set-v1',
        rosterDigest: input.rosterDigest,
        thresholdProfileDigest: input.thresholdProfileDigest,
        votingClosedBoardHeadDigest: input.votingClosedBoardHeadDigest,
    });

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

const packageReferencesAreCanonical = (
    packageReferences: readonly AggregateDerivationPackageReference[],
): boolean => {
    const seenPackageDigests = new Set<ProtocolDigest>();
    let previousPackageDigest: ProtocolDigest | undefined;

    for (const packageReference of packageReferences) {
        if (seenPackageDigests.has(packageReference.ballotPackageDigest)) {
            return false;
        }
        if (
            previousPackageDigest !== undefined &&
            previousPackageDigest.localeCompare(
                packageReference.ballotPackageDigest,
            ) > 0
        ) {
            return false;
        }
        previousPackageDigest = packageReference.ballotPackageDigest;
        seenPackageDigests.add(packageReference.ballotPackageDigest);
    }

    return true;
};

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

const sourcePolynomialSplitFactor = (): number =>
    aggregateDerivationSourceRingDegree /
    aggregateDerivationProofSystemRingDegree;

const aggregateStatementRows = (shareVectorWidth: number): number =>
    shareCommitmentModuleRank + shareVectorWidth;

const aggregateStatementColumns = (shareVectorWidth: number): number =>
    3 * shareVectorWidth + shareCommitmentOpeningDimension;

const aggregateShortResponseVectorLength = (statementColumns: number): number =>
    statementColumns * sourcePolynomialSplitFactor() + 1;

const coefficient = (value: bigint): string | number =>
    polynomialCoefficient({
        coefficient: value,
        coefficientModulus: shareCommitmentModulus,
    });

const shareColumnIndex = (coordinateIndex: number): number => coordinateIndex;

const openingColumnIndex = (
    shareVectorWidth: number,
    openingCoordinateIndex: number,
): number => shareVectorWidth + openingCoordinateIndex;

const reducedFieldColumnIndex = (
    shareVectorWidth: number,
    coordinateIndex: number,
): number =>
    shareVectorWidth + shareCommitmentOpeningDimension + coordinateIndex;

const quotientColumnIndex = (
    shareVectorWidth: number,
    coordinateIndex: number,
): number =>
    2 * shareVectorWidth + shareCommitmentOpeningDimension + coordinateIndex;

const shareCommitmentMessageEntryPolynomial = (input: {
    readonly messageMatrixPolynomial: readonly bigint[];
    readonly shareCoordinateIndex: number;
}): readonly bigint[] =>
    Array.from(
        { length: shareCommitmentModuleDegree },
        (_unusedValue, outputCoefficientIndex) => {
            if (outputCoefficientIndex >= input.shareCoordinateIndex) {
                return modBigInt(
                    input.messageMatrixPolynomial[
                        outputCoefficientIndex - input.shareCoordinateIndex
                    ] ?? 0n,
                    shareCommitmentModulus,
                );
            }

            return modBigInt(
                -(
                    input.messageMatrixPolynomial[
                        shareCommitmentModuleDegree +
                            outputCoefficientIndex -
                            input.shareCoordinateIndex
                    ] ?? 0n
                ),
                shareCommitmentModulus,
            );
        },
    );

const sparsePolynomialEntry = (input: {
    readonly columnIndex: number;
    readonly polynomial: readonly bigint[];
    readonly rowIndex: number;
}): SparseMatrixEntry => {
    const nonzeroIndices = input.polynomial.flatMap(
        (entryCoefficient, coefficientIndex) =>
            entryCoefficient === 0n ? [] : [coefficientIndex],
    );
    if (nonzeroIndices.length === 1 && nonzeroIndices[0] === 0) {
        return {
            columnIndex: input.columnIndex,
            constantCoefficient: coefficient(input.polynomial[0] ?? 0n),
            rowIndex: input.rowIndex,
        };
    }

    return {
        columnIndex: input.columnIndex,
        polynomialCoefficients: input.polynomial.map(coefficient),
        rowIndex: input.rowIndex,
    };
};

const sparseTargetEntry = (input: {
    readonly polynomial: readonly bigint[];
    readonly rowIndex: number;
}): SparseTargetVectorEntry => {
    const nonzeroIndices = input.polynomial.flatMap(
        (entryCoefficient, coefficientIndex) =>
            entryCoefficient === 0n ? [] : [coefficientIndex],
    );
    if (nonzeroIndices.length === 1 && nonzeroIndices[0] === 0) {
        return {
            constantCoefficient: coefficient(input.polynomial[0] ?? 0n),
            rowIndex: input.rowIndex,
        };
    }

    return {
        polynomialCoefficients: input.polynomial.map(coefficient),
        rowIndex: input.rowIndex,
    };
};

const validateAggregateWitness = (input: {
    readonly canonicalTurnout: number;
    readonly shareVectorWidth: number;
    readonly witness: AggregateDerivationWitnessInput;
}): void => {
    if (
        input.witness.aggregateIntegerShareVector.length !==
            input.shareVectorWidth ||
        input.witness.aggregateOpeningRandomness.length !==
            shareCommitmentOpeningDimension
    ) {
        throw new RangeError(
            'Aggregate derivation witness shape does not match the statement.',
        );
    }
    const maximumAggregateInteger =
        input.canonicalTurnout * ballotPrivacyMaximumCanonicalFieldElement;
    for (const shareCoordinate of input.witness.aggregateIntegerShareVector) {
        if (
            !Number.isSafeInteger(shareCoordinate) ||
            shareCoordinate < 0 ||
            shareCoordinate > maximumAggregateInteger
        ) {
            throw new RangeError(
                'Aggregate integer share coordinates must satisfy the no-wraparound certificate bound.',
            );
        }
    }
    const maximumOpeningRandomness =
        input.canonicalTurnout *
        createBallotPrivacyProfileSet({
            optionCount:
                input.shareVectorWidth /
                ballotPrivacyEncodedCoordinatesPerOption,
        }).shareCommitmentProfile.openingRandomnessInfinityNormBound;
    for (const openingCoordinate of input.witness.aggregateOpeningRandomness) {
        if (
            !Number.isSafeInteger(openingCoordinate) ||
            Math.abs(openingCoordinate) > maximumOpeningRandomness
        ) {
            throw new RangeError(
                'Aggregate opening randomness exceeds the no-wraparound certificate bound.',
            );
        }
    }
};

const constantWitnessPolynomial = (
    coefficientValue: number,
): DensePolynomial => [
    coefficientValue,
    ...Array.from({ length: aggregateDerivationSourceRingDegree - 1 }, () => 0),
];

export const buildAggregateDerivationProofInput = (
    input: AggregateDerivationProofBuildInput,
): AggregateDerivationProofBuildOutput => {
    const statement = input.statement;
    const shareVectorWidth = statement.shareVectorWidth;
    validateAggregateWitness({
        canonicalTurnout: statement.canonicalTurnout,
        shareVectorWidth,
        witness: input.witness,
    });
    const proofParameterSet: AggregateDerivationProofParameterSet = {
        coefficientModulus: shareCommitmentModulusDecimal,
        profileId: aggregateDerivationProofParameterProfileId,
        proofSystemRingDegree: aggregateDerivationProofSystemRingDegree,
        relation: linearProofRelation,
        ringDegree: aggregateDerivationSourceRingDegree,
        source: 'sealed-lattice/linear-proof/aggregate-derivation-parameters-v1',
        statementColumns: aggregateStatementColumns(shareVectorWidth),
        statementRows: aggregateStatementRows(shareVectorWidth),
        witnessL2BoundSquared: aggregateDerivationWitnessL2BoundSquared,
    };
    const proofEncoding: AggregateDerivationProofEncoding = {
        challengeCoefficientBitLength: 5,
        challengeCoefficientModulus: 17,
        coefficientModulus: aggregateDerivationProofCoefficientModulus,
        compressedCoefficientBitLength: 35,
        compressedCommitmentVectorLength: 18,
        euclideanResponseLog2StandardDeviation: 14,
        euclideanResponseVectorLength: 4,
        fullSizeCoefficientBitLength: 47,
        hashMaskVectorLength: 2,
        hintVectorLength: 18,
        infinityResponseLog2StandardDeviation: 22,
        infinityResponseVectorLength: 4,
        profileId: aggregateDerivationProofEncodingProfileId,
        randomnessResponseLog2StandardDeviation: 12,
        randomnessResponseVectorLength: 41,
        ringDegree: aggregateDerivationProofSystemRingDegree,
        shortResponseLog2StandardDeviation: 18,
        shortResponseVectorLength: aggregateShortResponseVectorLength(
            proofParameterSet.statementColumns,
        ),
        source: 'sealed-lattice/linear-proof/aggregate-derivation-encoding-v1',
        targetCommitmentVectorLength: 12,
    };
    const matrixEntries: SparseMatrixEntry[] = [];
    const targetEntries: SparseTargetVectorEntry[] = [];
    const messageMatrix = deriveShareCommitmentMessageMatrix(
        statement.shareCommitmentProfileDigest,
    );
    const randomnessMatrix = deriveShareCommitmentRandomnessMatrix(
        statement.shareCommitmentProfileDigest,
    );

    for (
        let rowIndex = 0;
        rowIndex < shareCommitmentModuleRank;
        rowIndex += 1
    ) {
        const aggregateCommitmentPolynomial =
            input.aggregateCommitment.commitmentPolynomialVector[rowIndex];
        if (
            aggregateCommitmentPolynomial?.length !==
            shareCommitmentModuleDegree
        ) {
            throw new RangeError(
                'Aggregate commitment polynomial vector has an invalid shape.',
            );
        }
        for (
            let coordinateIndex = 0;
            coordinateIndex < shareVectorWidth;
            coordinateIndex += 1
        ) {
            matrixEntries.push(
                sparsePolynomialEntry({
                    columnIndex: shareColumnIndex(coordinateIndex),
                    polynomial: shareCommitmentMessageEntryPolynomial({
                        messageMatrixPolynomial: messageMatrix[rowIndex] ?? [],
                        shareCoordinateIndex: coordinateIndex,
                    }),
                    rowIndex,
                }),
            );
        }
        for (
            let openingCoordinateIndex = 0;
            openingCoordinateIndex < shareCommitmentOpeningDimension;
            openingCoordinateIndex += 1
        ) {
            matrixEntries.push(
                sparsePolynomialEntry({
                    columnIndex: openingColumnIndex(
                        shareVectorWidth,
                        openingCoordinateIndex,
                    ),
                    polynomial:
                        randomnessMatrix[rowIndex]?.[openingCoordinateIndex] ??
                        [],
                    rowIndex,
                }),
            );
        }
        targetEntries.push(
            sparseTargetEntry({
                polynomial: aggregateCommitmentPolynomial.map((entry) =>
                    modBigInt(-BigInt(entry), shareCommitmentModulus),
                ),
                rowIndex,
            }),
        );
    }

    for (
        let coordinateIndex = 0;
        coordinateIndex < shareVectorWidth;
        coordinateIndex += 1
    ) {
        const rowIndex = shareCommitmentModuleRank + coordinateIndex;
        matrixEntries.push(
            {
                columnIndex: shareColumnIndex(coordinateIndex),
                constantCoefficient: 1,
                rowIndex,
            },
            {
                columnIndex: reducedFieldColumnIndex(
                    shareVectorWidth,
                    coordinateIndex,
                ),
                constantCoefficient: coefficient(-1n),
                rowIndex,
            },
            {
                columnIndex: quotientColumnIndex(
                    shareVectorWidth,
                    coordinateIndex,
                ),
                constantCoefficient: coefficient(
                    -BigInt(ballotPrivacyFieldModulus),
                ),
                rowIndex,
            },
        );
    }

    const sparseStatementMatrixDigest =
        deriveSparseStatementMatrixDigest(matrixEntries);
    const targetVectorDigest = deriveSparseTargetVectorDigest(targetEntries);
    const proofStatementPayload: Omit<
        AggregateDerivationProofStatement,
        'statementDigest'
    > = {
        aggregateDerivationStatementDigest:
            statement.aggregateDerivationStatementDigest,
        aggregateShareCommitmentDigest:
            input.aggregateCommitment.aggregateShareCommitmentDigest,
        coefficientModulus: shareCommitmentModulusDecimal,
        componentId: aggregateDerivationComponentId,
        matrixCoefficientRepresentation: 'centeredSignedSourceModulus',
        objectType: 'AggregateDerivationSparseLinearProofStatement',
        objectVersion: 1,
        parameterProfileId: aggregateDerivationProofParameterProfileId,
        proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
        projectionCoverage: 'aggregate-derivation-full-encoded-layout',
        relation: linearProofRelation,
        sourceRingDegree: aggregateDerivationSourceRingDegree,
        sparseStatementMatrixDigest,
        sparseStatementMatrixEntries: matrixEntries,
        sparseStatementTermCount: String(matrixEntries.length),
        statementColumns: proofParameterSet.statementColumns,
        statementRows: proofParameterSet.statementRows,
        targetCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetVectorDigest,
        targetVectorEntries: targetEntries,
        targetVectorEntryCount: String(targetEntries.length),
        witnessL2BoundSquared: String(aggregateDerivationWitnessL2BoundSquared),
    };
    const proofStatement: AggregateDerivationProofStatement = {
        ...proofStatementPayload,
        statementDigest: deriveAggregateSparseLinearStatementDigest(
            proofStatementPayload,
        ),
    };
    const aggregateIntegerShareVector =
        input.witness.aggregateIntegerShareVector;
    const reducedFieldVector = aggregateIntegerShareVector.map(
        (shareCoordinate) => shareCoordinate % ballotPrivacyFieldModulus,
    );
    const quotientVector = aggregateIntegerShareVector.map(
        (shareCoordinate, coordinateIndex) => {
            const reducedFieldCoordinate =
                reducedFieldVector[coordinateIndex] ?? 0;
            const quotient =
                (shareCoordinate - reducedFieldCoordinate) /
                ballotPrivacyFieldModulus;
            if (
                !Number.isSafeInteger(quotient) ||
                quotient < 0 ||
                quotient > statement.canonicalTurnout
            ) {
                throw new RangeError(
                    'Aggregate derivation quotient exceeds the turnout bound.',
                );
            }

            return quotient;
        },
    );
    const secretState = {
        sourceWitnessCoefficients: [
            ...aggregateIntegerShareVector.map(constantWitnessPolynomial),
            ...input.witness.aggregateOpeningRandomness.map(
                constantWitnessPolynomial,
            ),
            ...reducedFieldVector.map(constantWitnessPolynomial),
            ...quotientVector.map(constantWitnessPolynomial),
        ],
    };
    const proofInput = {
        componentId: aggregateDerivationComponentId,
        componentProofStatementDigest: proofStatement.statementDigest,
        proofEncoding,
        proofParameterSet,
        proofStatement,
        proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
        publicRandomnessHex: statement.challengeDomainDigest.slice(0, 64),
        statementDigest: statement.aggregateDerivationStatementDigest,
    } satisfies Omit<
        AggregateDerivationProofVerificationInput,
        'proofBytesHex'
    >;

    return {
        proofEncoding,
        proofInput,
        proofParameterSet,
        proofStatement,
        secretState,
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

const collectForbiddenWitnessFieldRefusals = (
    value: unknown,
    objectDigest: ProtocolDigest | undefined,
    path: string,
): readonly RefusalRecord[] => {
    if (Array.isArray(value)) {
        return value.flatMap((item, itemIndex) =>
            collectForbiddenWitnessFieldRefusals(
                item,
                objectDigest,
                `${path}[${itemIndex}]`,
            ),
        );
    }
    if (typeof value !== 'object' || value === null) {
        return [];
    }

    const refusedObjects: RefusalRecord[] = [];
    for (const [fieldName, fieldValue] of Object.entries(value)) {
        if (forbiddenPublicWitnessFieldNames.has(fieldName)) {
            refusedObjects.push(
                createAggregateRefusal(
                    `Aggregate derivation public component must not expose witness field ${path}.${fieldName}.`,
                    objectDigest,
                ),
            );
            continue;
        }
        refusedObjects.push(
            ...collectForbiddenWitnessFieldRefusals(
                fieldValue,
                objectDigest,
                `${path}.${fieldName}`,
            ),
        );
    }

    return refusedObjects;
};

const collectAggregateStatementRefusals = (
    statement: AggregateDerivationStatement,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const { aggregateDerivationStatementDigest, ...statementWithoutDigest } =
        statement;
    const expectedStatementDigest = deriveAggregateDerivationStatementDigest(
        statementWithoutDigest,
    );
    refusedObjects.push(
        ...collectBallotPrivacyDimensionRefusals({
            objectDigest: aggregateDerivationStatementDigest,
            optionCount: statement.optionCount,
            participantCount: statement.participantCount,
            shareVectorWidth: statement.shareVectorWidth,
            unsafeSmallRosterAcknowledged:
                statement.unsafeSmallRosterAcknowledged === true,
        }),
    );
    const smallRosterAcknowledgementMatchesPolicy =
        statement.participantCount < ballotPrivacyMinimumSafeParticipantCount
            ? statement.unsafeSmallRosterAcknowledged === true
            : statement.unsafeSmallRosterAcknowledged !== true;
    if (
        statement.objectType !== 'AggregateDerivationStatement' ||
        statement.objectVersion !== 1 ||
        statement.aggregateDerivationStatementDigest !==
            expectedStatementDigest ||
        statement.proofProfileId !== aggregateDerivationProofProfileId ||
        statement.proofParameterProfileId !==
            aggregateDerivationProofParameterProfileId ||
        statement.proofEncodingProfileId !==
            aggregateDerivationProofEncodingProfileId ||
        statement.shareVectorWidth !==
            getBallotPrivacyEncodedShareVectorWidth(statement.optionCount) ||
        statement.participantCount < statement.contributorRosterPosition ||
        statement.canonicalTurnout !== statement.packageReferences.length ||
        !packageReferencesAreCanonical(statement.packageReferences) ||
        !smallRosterAcknowledgementMatchesPolicy
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate derivation statement digest or shape is invalid.',
                aggregateDerivationStatementDigest,
            ),
        );
    }
    return refusedObjects;
};

const collectAggregateCommitmentRefusals = (input: {
    readonly aggregateCommitment: AggregateShareCommitment;
    readonly statement: AggregateDerivationStatement;
}): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedBodyDigest = deriveAggregateCommitmentBodyDigest({
        commitmentPolynomialVector:
            input.aggregateCommitment.commitmentPolynomialVector,
        shareCommitmentProfileDigest:
            input.aggregateCommitment.shareCommitmentProfileDigest,
    });
    const {
        aggregateShareCommitmentDigest,
        ...aggregateCommitmentWithoutDigest
    } = input.aggregateCommitment;
    void aggregateShareCommitmentDigest;
    const expectedCommitmentDigest = deriveAggregateShareCommitmentDigest(
        aggregateCommitmentWithoutDigest,
    );
    const vectorShapeIsValid =
        input.aggregateCommitment.commitmentPolynomialVector.length ===
            shareCommitmentModuleRank &&
        input.aggregateCommitment.commitmentPolynomialVector.every(
            (polynomial) =>
                polynomial.length === shareCommitmentModuleDegree &&
                polynomial.every((entry) => {
                    try {
                        return (
                            /^(?:0|[1-9][0-9]*)$/u.test(entry) &&
                            BigInt(entry) < shareCommitmentModulus
                        );
                    } catch {
                        return false;
                    }
                }),
        );

    if (
        input.aggregateCommitment.objectType !== 'AggregateShareCommitment' ||
        input.aggregateCommitment.objectVersion !== 1 ||
        input.aggregateCommitment.aggregateShareCommitmentDigest !==
            expectedCommitmentDigest ||
        input.aggregateCommitment.commitmentBodyDigest !== expectedBodyDigest ||
        input.aggregateCommitment.aggregateShareCommitmentDigest !==
            input.statement.aggregateShareCommitmentDigest ||
        input.aggregateCommitment.ballotSetDigest !==
            input.statement.ballotSetDigest ||
        input.aggregateCommitment.ceremonyId !== input.statement.ceremonyId ||
        input.aggregateCommitment.manifestDigest !==
            input.statement.manifestDigest ||
        input.aggregateCommitment.rosterDigest !==
            input.statement.rosterDigest ||
        input.aggregateCommitment.pollSpecDigest !==
            input.statement.pollSpecDigest ||
        input.aggregateCommitment.contributorIdentity !==
            input.statement.contributorIdentity ||
        input.aggregateCommitment.contributorRosterPosition !==
            input.statement.contributorRosterPosition ||
        input.aggregateCommitment.shareCommitmentProfileDigest !==
            input.statement.shareCommitmentProfileDigest ||
        input.aggregateCommitment.shareVectorWidth !==
            input.statement.shareVectorWidth ||
        !vectorShapeIsValid
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate share commitment digest, context, or polynomial shape is invalid.',
                input.aggregateCommitment.aggregateShareCommitmentDigest,
            ),
        );
    }

    return refusedObjects;
};

const collectProofRecordRefusals = (
    component: AggregateDerivationComponent,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const proofInput = component.proofInput;
    const proofRecord = component.proofRecord;
    const {
        aggregateDerivationProofRecordDigest,
        ...proofRecordWithoutDigest
    } = proofRecord;
    void aggregateDerivationProofRecordDigest;
    const proofBytesDigest = lowercaseHexBytesPattern.test(
        proofInput.proofBytesHex,
    )
        ? deriveProofBytesDigest({ proofBytesHex: proofInput.proofBytesHex })
        : undefined;
    const expectedProofRecordDigest =
        deriveAggregateDerivationProofRecordDigest(proofRecordWithoutDigest);

    if (
        proofRecord.objectType !== 'AggregateDerivationProofRecord' ||
        proofRecord.objectVersion !== 1 ||
        proofRecord.aggregateDerivationProofRecordDigest !==
            expectedProofRecordDigest ||
        proofRecord.aggregateDerivationStatementDigest !==
            component.statement.aggregateDerivationStatementDigest ||
        proofRecord.aggregateShareCommitmentDigest !==
            component.aggregateCommitment.aggregateShareCommitmentDigest ||
        proofRecord.componentId !== aggregateDerivationComponentId ||
        proofInput.componentId !== aggregateDerivationComponentId ||
        proofInput.proofStatementFormat !==
            'sparse-polynomial-matrix-linear-proof-v1' ||
        proofInput.statementDigest !==
            component.statement.aggregateDerivationStatementDigest ||
        proofInput.componentProofStatementDigest !==
            proofRecord.componentProofStatementDigest ||
        proofBytesDigest === undefined ||
        proofRecord.proofBytesDigest !== proofBytesDigest ||
        proofRecord.proofSizeBytes !== proofInput.proofBytesHex.length / 2 ||
        !protocolDigestPattern.test(proofRecord.proofRoot)
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate derivation proof record or proof input is invalid.',
                proofRecord.aggregateDerivationProofRecordDigest,
            ),
        );
    }

    return refusedObjects;
};

export const verifyAggregateDerivationComponentStructure = (
    component: AggregateDerivationComponent,
): AggregateDerivationVerification => {
    const componentDigest = component.aggregateDerivationComponentDigest;
    const certificateVerification = verifyShareCommitmentMessageBoundCert({
        certificate: component.shareCommitmentMessageBoundCert,
        expectedShareCommitmentProfileDigest:
            component.statement.shareCommitmentProfileDigest,
    });
    const refusedObjects: RefusalRecord[] = [
        ...collectForbiddenWitnessFieldRefusals(
            component,
            componentDigest,
            'component',
        ),
        ...collectAggregateStatementRefusals(component.statement),
        ...collectAggregateCommitmentRefusals({
            aggregateCommitment: component.aggregateCommitment,
            statement: component.statement,
        }),
        ...collectProofRecordRefusals(component),
        ...certificateVerification.refusedObjects,
    ];
    if (
        component.shareCommitmentMessageBoundCert.shareVectorWidth !==
            component.statement.shareVectorWidth ||
        component.shareCommitmentMessageBoundCert
            .shareCommitmentMessageBoundCertDigest !==
            component.statement.shareCommitmentMessageBoundCertDigest ||
        component.shareCommitmentMessageBoundCert.maximumCanonicalTurnout <
            component.statement.canonicalTurnout ||
        component.shareCommitmentMessageBoundCert.maximumCanonicalTurnout >
            ballotPrivacyMaximumParticipantCount
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate derivation no-wraparound certificate is not bound to the statement.',
                component.statement.shareCommitmentMessageBoundCertDigest,
            ),
        );
    }

    const { aggregateDerivationComponentDigest, ...componentWithoutDigest } =
        component;
    if (
        aggregateDerivationComponentDigest !==
        deriveAggregateDerivationComponentDigest(componentWithoutDigest)
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate derivation component digest does not match its canonical payload.',
                componentDigest,
            ),
        );
    }

    const unsafeSmallRosterStatusLabels =
        component.statement.participantCount >=
            ballotPrivacyMinimumUnsafeParticipantCount &&
        component.statement.participantCount <
            ballotPrivacyMinimumSafeParticipantCount
            ? (['CasualMicroRoster'] as const)
            : [];
    if (refusedObjects.length > 0) {
        return {
            ok: false,
            acceptedDigests: [],
            aggregateDerivationComponentDigest: componentDigest,
            backendAvailable: false,
            refusedObjects,
            statusLabels: unsafeSmallRosterStatusLabels,
            unresolvedReason: refusedObjects[0]?.code ?? 'BallotPackageInvalid',
        };
    }

    return {
        ok: true,
        acceptedDigests: [
            component.aggregateCommitment.aggregateShareCommitmentDigest,
            component.proofRecord.aggregateDerivationProofRecordDigest,
            componentDigest,
        ],
        aggregateDerivationComponentDigest: componentDigest,
        backendAvailable: false,
        refusedObjects: [],
        statusLabels: [
            'AggregateDerivationStructureVerified',
            ...unsafeSmallRosterStatusLabels,
        ],
        unresolvedReason: null,
    };
};

export const sumAggregateDerivationWitnesses = (input: {
    readonly witnesses: readonly AggregateDerivationWitnessInput[];
}): AggregateDerivationWitnessInput => {
    if (input.witnesses.length === 0) {
        throw new RangeError('Aggregate derivation requires witness inputs.');
    }
    const shareVectorWidth =
        input.witnesses[0].aggregateIntegerShareVector.length;

    return {
        aggregateIntegerShareVector: Array.from(
            { length: shareVectorWidth },
            (_unusedValue, coordinateIndex) =>
                input.witnesses.reduce(
                    (sum, witness) =>
                        sum +
                        (witness.aggregateIntegerShareVector[coordinateIndex] ??
                            0),
                    0,
                ),
        ),
        aggregateOpeningRandomness: Array.from(
            { length: shareCommitmentOpeningDimension },
            (_unusedValue, openingCoordinateIndex) =>
                input.witnesses.reduce(
                    (sum, witness) =>
                        sum +
                        (witness.aggregateOpeningRandomness[
                            openingCoordinateIndex
                        ] ?? 0),
                    0,
                ),
        ),
    };
};

export const aggregateWitnessFromReceiverPlaintext = (input: {
    readonly openingRandomness: readonly number[];
    readonly receiverShareVector: readonly number[];
}): AggregateDerivationWitnessInput => ({
    aggregateIntegerShareVector: [...input.receiverShareVector],
    aggregateOpeningRandomness: [...input.openingRandomness],
});
