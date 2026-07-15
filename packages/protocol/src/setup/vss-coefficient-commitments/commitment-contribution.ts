import { deriveCanonicalObjectHash } from "@sealed-lattice/crypto";
import type { ProtocolHash } from "@sealed-lattice/types";

import {
    type SetupCommitmentValue,
    type VssCoefficientOpeningMaterial,
    type VssSourceTrusteeCoefficientCommitmentContributionInput,
    type VssSourceTrusteeCoefficientCommitmentRecord,
    type VssSourceTrusteeOpeningMaterial,
} from "./constants-and-types.js";
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
} from "./encoding.js";
import {
    openingCoordinateKey,
    openingStateByCoordinate,
} from "./opening-state.js";

const validateCommitmentCommonInput = (
    input: VssSourceTrusteeCoefficientCommitmentContributionInput,
): void => {
    assertProtocolHash(input.publicMatrixSeedHash, "publicMatrixSeedHash");
    assertPositiveSafeInteger(input.ringDegree, "ringDegree");
    assertPositiveSafeInteger(
        input.setupContext.participantCount,
        "setupContext.participantCount",
    );
    assertPositiveSafeInteger(input.thresholdDegree, "thresholdDegree");
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
};

export const createVssSourceTrusteeCoefficientCommitmentContribution = (
    input: VssSourceTrusteeCoefficientCommitmentContributionInput,
): VssSourceTrusteeOpeningMaterial => {
    validateCommitmentCommonInput(input);
    const sourceTrusteeState = input.sourceTrusteeOpeningState;
    assertNonEmptyString(
        sourceTrusteeState.sourceTrusteeIdentity,
        "sourceTrusteeIdentity",
    );
    assertNonNegativeSafeInteger(
        sourceTrusteeState.sourceTrusteeRosterPosition,
        "sourceTrusteeRosterPosition",
    );
    if (
        sourceTrusteeState.sourceTrusteeRosterPosition >=
        input.setupContext.participantCount
    ) {
        throw new Error(
            "sourceTrusteeRosterPosition must be inside the accepted participant count.",
        );
    }
    const openingsByCoordinate = openingStateByCoordinate(
        sourceTrusteeState,
        input.qSharePrimes,
        input.ringDegree,
        input.thresholdDegree,
    );
    const coefficientCommitments: SetupCommitmentValue[] = [];
    const coefficientCommitmentRoots: ProtocolHash[] = [];
    const sourceTrusteePrivateOpenings: VssCoefficientOpeningMaterial[] = [];
    input.qSharePrimes.forEach((_rnsPrime, rnsLimbIndex) => {
        for (
            let shamirCoefficientIndex = 0;
            shamirCoefficientIndex < input.thresholdDegree;
            shamirCoefficientIndex += 1
        ) {
            const openingState = openingsByCoordinate.get(
                openingCoordinateKey(rnsLimbIndex, shamirCoefficientIndex),
            );
            if (openingState === undefined) {
                throw new Error(
                    "source trustee coefficientOpenings must cover every declared coordinate.",
                );
            }
            const commitmentComputation =
                input.structuredCommitmentOpenings.computeCommitment({
                    capability: openingState.openingCapability,
                    messageCoefficients: openingState.coefficientMessage,
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                });
            if (
                commitmentComputation.commitment.sourceRnsLimbIndex !==
                    rnsLimbIndex ||
                commitmentComputation.commitment.shamirCoefficientIndex !==
                    shamirCoefficientIndex ||
                commitmentComputation.commitment.ringDegree !== input.ringDegree
            ) {
                throw new Error(
                    "worker-owned opening computation returned a commitment for the wrong coordinate.",
                );
            }
            const commitmentRoot = deriveCanonicalObjectHash(
                commitmentComputation.commitment,
            );
            sourceTrusteePrivateOpenings.push({
                ...openingState,
                commitmentRoot,
            });
            coefficientCommitmentRoots.push(commitmentRoot);
            coefficientCommitments.push(commitmentComputation.commitment);
        }
    });
    const sourceTrusteeRecord = {
        objectType: "VssSourceTrusteeCoefficientCommitments",
        sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
        coefficientCommitmentRoots,
    } as const satisfies VssSourceTrusteeCoefficientCommitmentRecord;

    return {
        sourceTrusteeCoefficientCommitmentRecord: sourceTrusteeRecord,
        coefficientCommitments,
        coefficientOpenings: sourceTrusteePrivateOpenings,
    };
};
