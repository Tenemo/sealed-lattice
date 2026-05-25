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

import {
    aggregateDerivationComponentId,
    aggregateDerivationProofCoefficientModulus,
    aggregateDerivationProofSystemRingDegree,
    aggregateDerivationSourceRingDegree,
    aggregateDerivationWitnessL2BoundSquared,
} from './aggregate-derivation/constants.js';
import {
    deriveAggregateCommitmentBodyDigest,
    deriveAggregateDerivationBallotSetDigest,
    deriveAggregateDerivationComponentDigest,
    deriveAggregateDerivationProofRecordDigest,
    deriveAggregateDerivationProofRoot,
    deriveAggregateDerivationStatementDigest,
    deriveAggregateShareCommitmentDigest,
    deriveAggregateSparseLinearStatementDigest,
} from './aggregate-derivation/digests.js';
import type {
    AggregateDerivationProofBuildInput,
    AggregateDerivationProofBuildOutput,
    AggregateDerivationProofEncoding,
    AggregateDerivationProofParameterSet,
    AggregateDerivationProofStatement,
    AggregateDerivationWitnessInput,
} from './aggregate-derivation/types.js';
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
import { createBallotPrivacyProfileSet } from './profiles.js';
import {
    ballotPrivacyEncodedCoordinatesPerOption,
    ballotPrivacyFieldModulus,
    ballotPrivacyMaximumCanonicalFieldElement,
    ballotPrivacyMinimumSafeParticipantCount,
    shareCommitmentModulus,
    shareCommitmentModulusDecimal,
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
    shareCommitmentOpeningDimension,
} from './protocol-parameters.js';

export { verifyAggregateDerivationComponentStructure } from './aggregate-derivation/structure-verification.js';
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
