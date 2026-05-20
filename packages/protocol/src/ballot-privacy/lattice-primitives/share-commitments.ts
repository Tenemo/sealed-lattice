import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    ProtocolDigest,
    RefusalRecord,
    ShareCommitment,
    ShareCommitmentProfile,
} from '@sealed-lattice/types';

import { createRefusal } from '../../common/verification-helpers.js';
import { createShareCommitmentShell } from '../objects.js';

import type {
    BallotPrivacyRandomnessSource,
    ShareCommitmentMaterial,
    ShareCommitmentOpeningWitness,
} from './primitive-contracts.js';
import {
    addBigIntPolynomials,
    canonicalEqual,
    deriveShareCommitmentMessageMatrix,
    deriveShareCommitmentRandomnessMatrix,
    modBigInt,
    multiplyBigIntPolynomials,
    resolveRandomBytes,
    shareCommitmentModuleDegree,
    shareCommitmentModulus,
    shareCommitmentOpeningDimension,
    validateReceiverShareVector,
} from './primitive-contracts.js';

export function validateShareCommitmentOpening(
    opening: ShareCommitmentOpeningWitness,
    shareCommitmentProfile: ShareCommitmentProfile,
): void {
    if (opening.openingRandomness.length !== shareCommitmentOpeningDimension) {
        throw new RangeError(
            'Share commitment openings must use the frozen dimension.',
        );
    }
    for (const openingCoordinate of opening.openingRandomness) {
        if (
            !Number.isSafeInteger(openingCoordinate) ||
            Math.abs(openingCoordinate) >
                shareCommitmentProfile.openingRandomnessInfinityNormBound
        ) {
            throw new RangeError(
                'Share commitment opening coordinates must satisfy the frozen infinity-norm bound.',
            );
        }
    }
}

const encodeShareVectorAsMessagePolynomial = (
    receiverShareVector: readonly number[],
    shareCommitmentProfile: ShareCommitmentProfile,
    expectedShareVectorWidth: number = shareCommitmentProfile.shareVectorWidth,
): readonly bigint[] => {
    validateReceiverShareVector(
        receiverShareVector,
        shareCommitmentProfile,
        expectedShareVectorWidth,
    );
    const coefficients = Array.from(
        { length: shareCommitmentModuleDegree },
        () => 0n,
    );
    receiverShareVector.forEach((shareRepresentative, coefficientIndex) => {
        coefficients[coefficientIndex] = BigInt(shareRepresentative);
    });

    return coefficients;
};

const sampleShareCommitmentOpening = (
    randomnessSource: BallotPrivacyRandomnessSource,
    shareCommitmentProfile: ShareCommitmentProfile,
    payload: unknown,
): ShareCommitmentOpeningWitness => {
    if (
        shareCommitmentProfile.openingRandomnessDistribution !==
            'UniformCenteredInteger' ||
        shareCommitmentProfile.openingRandomnessSampler !==
            'RejectionSampledLittleEndianUint16' ||
        shareCommitmentProfile.openingRandomnessSamplerWordBits !== 16
    ) {
        throw new RangeError(
            'Share commitment opening randomness profile is not supported.',
        );
    }
    const rangeWidth =
        shareCommitmentProfile.openingRandomnessInfinityNormBound * 2 + 1;
    if (
        shareCommitmentProfile.openingRandomnessRangeWidth !== rangeWidth ||
        rangeWidth <= 0 ||
        rangeWidth > 65_536
    ) {
        throw new RangeError(
            'Share commitment opening randomness range is not canonical.',
        );
    }
    const rejectionLimit = 65_536 - (65_536 % rangeWidth);
    const openingRandomness = Array.from(
        { length: shareCommitmentOpeningDimension },
        (_unusedValue, coordinateIndex) => {
            let rejectionAttemptIndex = 0;
            for (;;) {
                const bytes = resolveRandomBytes(
                    randomnessSource,
                    shareCommitmentProfile.openingRandomnessSamplerDomain,
                    { coordinateIndex, payload, rejectionAttemptIndex },
                    2,
                );
                const unsignedValue = (bytes[0] ?? 0) | ((bytes[1] ?? 0) << 8);

                if (unsignedValue < rejectionLimit) {
                    return (
                        (unsignedValue % rangeWidth) -
                        shareCommitmentProfile.openingRandomnessInfinityNormBound
                    );
                }
                rejectionAttemptIndex += 1;
            }
        },
    );

    return { openingRandomness };
};

const computeShareCommitmentVector = (
    shareVector: readonly number[],
    opening: ShareCommitmentOpeningWitness,
    shareCommitmentProfile: ShareCommitmentProfile,
    expectedShareVectorWidth: number = shareCommitmentProfile.shareVectorWidth,
): readonly (readonly bigint[])[] => {
    validateReceiverShareVector(
        shareVector,
        shareCommitmentProfile,
        expectedShareVectorWidth,
    );
    validateShareCommitmentOpening(opening, shareCommitmentProfile);
    const messagePolynomial = encodeShareVectorAsMessagePolynomial(
        shareVector,
        shareCommitmentProfile,
        expectedShareVectorWidth,
    );
    const messageMatrix = deriveShareCommitmentMessageMatrix(
        shareCommitmentProfile.shareCommitmentProfileDigest,
    );
    const randomnessMatrix = deriveShareCommitmentRandomnessMatrix(
        shareCommitmentProfile.shareCommitmentProfileDigest,
    );

    return messageMatrix.map((messageMatrixPolynomial, rowIndex) => {
        let accumulatedPolynomial = [
            ...multiplyBigIntPolynomials(
                messageMatrixPolynomial,
                messagePolynomial,
                shareCommitmentModulus,
            ),
        ];
        opening.openingRandomness.forEach((openingCoordinate, columnIndex) => {
            const randomnessPolynomial =
                randomnessMatrix[rowIndex]?.[columnIndex] ?? [];
            const openingPolynomial = Array.from(
                { length: shareCommitmentModuleDegree },
                (_unusedValue, coefficientIndex) =>
                    coefficientIndex === 0 ? BigInt(openingCoordinate) : 0n,
            );
            accumulatedPolynomial = [
                ...addBigIntPolynomials(
                    accumulatedPolynomial,
                    multiplyBigIntPolynomials(
                        randomnessPolynomial,
                        openingPolynomial,
                        shareCommitmentModulus,
                    ),
                    shareCommitmentModulus,
                ),
            ];
        });

        return accumulatedPolynomial;
    });
};

const stringifyBigIntPolynomialVector = (
    polynomialVector: readonly (readonly bigint[])[],
): readonly (readonly string[])[] =>
    polynomialVector.map((polynomial) =>
        polynomial.map((coefficient) => coefficient.toString()),
    );

export const deriveShareCommitmentBodyDigest = (input: {
    readonly commitmentPolynomialVector: readonly (readonly string[])[];
    readonly shareCommitmentProfileDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('ShareCommitmentDigest', {
        commitmentPolynomialVector: input.commitmentPolynomialVector,
        profileDigest: input.shareCommitmentProfileDigest,
    });

export const createShareCommitmentPolynomialVector = (input: {
    readonly receiverShareVector: readonly number[];
    readonly shareCommitmentProfile: ShareCommitmentProfile;
    readonly opening: ShareCommitmentOpeningWitness;
    readonly shareVectorWidth: number;
}): readonly (readonly string[])[] =>
    stringifyBigIntPolynomialVector(
        computeShareCommitmentVector(
            input.receiverShareVector,
            input.opening,
            input.shareCommitmentProfile,
            input.shareVectorWidth,
        ),
    );

export const addShareCommitmentPolynomialVectors = (
    leftPolynomialVector: readonly (readonly string[])[],
    rightPolynomialVector: readonly (readonly string[])[],
): readonly (readonly string[])[] => {
    if (leftPolynomialVector.length !== rightPolynomialVector.length) {
        throw new RangeError(
            'Share commitment vectors must have the same rank.',
        );
    }

    return leftPolynomialVector.map((leftPolynomial, vectorIndex) => {
        const rightPolynomial = rightPolynomialVector[vectorIndex];
        if (leftPolynomial.length !== rightPolynomial?.length) {
            throw new RangeError(
                'Share commitment polynomials must have the same degree.',
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

export const addShareCommitmentOpenings = (
    leftOpening: ShareCommitmentOpeningWitness,
    rightOpening: ShareCommitmentOpeningWitness,
): ShareCommitmentOpeningWitness => {
    if (
        leftOpening.openingRandomness.length !==
        rightOpening.openingRandomness.length
    ) {
        throw new RangeError(
            'Share commitment openings must have the same dimension.',
        );
    }

    return {
        openingRandomness: leftOpening.openingRandomness.map(
            (leftCoordinate, coordinateIndex) =>
                leftCoordinate +
                (rightOpening.openingRandomness[coordinateIndex] ?? 0),
        ),
    };
};

export const createShareCommitment = (input: {
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly receiverShareVector: readonly number[];
    readonly shareCommitmentProfile: ShareCommitmentProfile;
    readonly opening?: ShareCommitmentOpeningWitness;
    readonly randomnessSource?: BallotPrivacyRandomnessSource;
}): ShareCommitmentMaterial => {
    const opening =
        input.opening ??
        sampleShareCommitmentOpening(
            input.randomnessSource ?? { kind: 'production' },
            input.shareCommitmentProfile,
            {
                ceremonyId: input.ceremonyId,
                manifestDigest: input.manifestDigest,
                receiverIdentity: input.receiverIdentity,
                receiverRosterPosition: input.receiverRosterPosition,
                rosterDigest: input.rosterDigest,
            },
        );
    const commitmentVector = computeShareCommitmentVector(
        input.receiverShareVector,
        opening,
        input.shareCommitmentProfile,
    );
    const commitmentPolynomialVector =
        stringifyBigIntPolynomialVector(commitmentVector);
    const commitmentBodyDigest = deriveShareCommitmentBodyDigest({
        commitmentPolynomialVector,
        shareCommitmentProfileDigest:
            input.shareCommitmentProfile.shareCommitmentProfileDigest,
    });
    const shareCommitment = createShareCommitmentShell({
        ceremonyId: input.ceremonyId,
        commitmentPolynomialVector,
        manifestDigest: input.manifestDigest,
        rosterDigest: input.rosterDigest,
        receiverIdentity: input.receiverIdentity,
        receiverRosterPosition: input.receiverRosterPosition,
        shareCommitmentProfileDigest:
            input.shareCommitmentProfile.shareCommitmentProfileDigest,
        shareVectorWidth: input.shareCommitmentProfile.shareVectorWidth,
        commitmentBodyDigest,
    });

    return {
        commitmentPolynomialVector,
        opening,
        shareCommitment,
    };
};

export const verifyShareCommitmentWitness = (input: {
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly receiverShareVector: readonly number[];
    readonly shareCommitmentProfile: ShareCommitmentProfile;
    readonly opening: ShareCommitmentOpeningWitness;
    readonly expectedShareCommitment: ShareCommitment;
    readonly expectedCommitmentPolynomialVector?: readonly (readonly string[])[];
}): readonly RefusalRecord[] => {
    const recomputedCommitment = createShareCommitment({
        ceremonyId: input.ceremonyId,
        manifestDigest: input.manifestDigest,
        opening: input.opening,
        receiverIdentity: input.receiverIdentity,
        receiverRosterPosition: input.receiverRosterPosition,
        receiverShareVector: input.receiverShareVector,
        rosterDigest: input.rosterDigest,
        shareCommitmentProfile: input.shareCommitmentProfile,
    });
    const refusedObjects: RefusalRecord[] = [];

    if (
        recomputedCommitment.shareCommitment.shareCommitmentDigest !==
        input.expectedShareCommitment.shareCommitmentDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Share commitment witness does not open the expected commitment digest.',
                input.expectedShareCommitment.shareCommitmentDigest,
            ),
        );
    }
    if (
        input.expectedCommitmentPolynomialVector !== undefined &&
        !canonicalEqual(
            recomputedCommitment.commitmentPolynomialVector,
            input.expectedCommitmentPolynomialVector,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Share commitment witness does not reproduce the expected commitment polynomial vector.',
                input.expectedShareCommitment.shareCommitmentDigest,
            ),
        );
    }

    return refusedObjects;
};
