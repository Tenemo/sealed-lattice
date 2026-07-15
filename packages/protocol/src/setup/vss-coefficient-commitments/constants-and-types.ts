import type { ProtocolHash } from "@sealed-lattice/types";
import type {
    ClosedWorkerStructuredCommitmentOpeningCapability,
    ClosedWorkerStructuredCommitmentOpeningOperations,
} from "@sealed-lattice/wasm";

import type { CollectiveBgvSetupContext } from "../vss-share-verification-records.js";

const setupCommitmentModuleRank = 1;

export const setupCommitmentHidingSecretDistributionPurpose = 11;
export const setupCommitmentHidingErrorDistributionPurpose = 12;
export const setupCommitmentHidingSecretWidth = setupCommitmentModuleRank + 1;
export const setupCommitmentHidingErrorWidth = setupCommitmentModuleRank;
export const setupCommitmentRandomnessWidth =
    setupCommitmentHidingSecretWidth + setupCommitmentHidingErrorWidth;
export const setupCommitmentModulusLimbCount = 3;
export const setupCommitmentHidingSecretCoefficientBound = 1;
export const setupCommitmentHidingErrorCoefficientBound = 1;

export const setupCommitmentRandomnessCoefficientBound = (
    randomnessColumnIndex: number,
): number | undefined => {
    if (
        Number.isSafeInteger(randomnessColumnIndex) &&
        randomnessColumnIndex >= 0 &&
        randomnessColumnIndex < setupCommitmentHidingSecretWidth
    ) {
        return setupCommitmentHidingSecretCoefficientBound;
    }
    if (
        Number.isSafeInteger(randomnessColumnIndex) &&
        randomnessColumnIndex < setupCommitmentRandomnessWidth
    ) {
        return setupCommitmentHidingErrorCoefficientBound;
    }

    return undefined;
};

type SetupCommitmentLimbValue = {
    readonly rows: readonly (readonly number[])[];
};

export type SetupCommitmentValue = {
    readonly objectType: "SetupCommitment";
    readonly sourceRnsLimbIndex: number;
    readonly shamirCoefficientIndex: number;
    readonly ringDegree: number;
    readonly commitmentLimbs: readonly SetupCommitmentLimbValue[];
};

export type VssCoefficientOpeningInput = {
    readonly rnsLimbIndex: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientMessage: readonly number[];
    readonly openingCapability: ClosedWorkerStructuredCommitmentOpeningCapability;
};

export type VssCoefficientOpeningMaterial = Readonly<
    VssCoefficientOpeningInput & {
        readonly commitmentRoot: ProtocolHash;
    }
>;

export type VssSourceTrusteeCoefficientOpeningState = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly coefficientOpenings: readonly VssCoefficientOpeningInput[];
};

export type VssSourceTrusteeCoefficientOpeningStateGenerationInput = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly sourceSetupIntentObjectHash: ProtocolHash;
    readonly structuredCommitmentOpenings: ClosedWorkerStructuredCommitmentOpeningOperations;
    readonly thresholdDegree: number;
};

export type VssSourceTrusteeCoefficientCommitmentRecord = Readonly<{
    readonly objectType: "VssSourceTrusteeCoefficientCommitments";
    readonly sourceTrusteeIdentity: string;
    readonly coefficientCommitmentRoots: readonly ProtocolHash[];
}>;

export type VssCoefficientCommitmentSet = Readonly<{
    readonly objectType: "VssCoefficientCommitmentSet";
    readonly setupContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeRecords: readonly VssSourceTrusteeCoefficientCommitmentRecord[];
}>;

export type VssSourceTrusteeOpeningMaterial = Readonly<{
    readonly sourceTrusteeCoefficientCommitmentRecord: VssSourceTrusteeCoefficientCommitmentRecord;
    readonly coefficientCommitments: readonly SetupCommitmentValue[];
    readonly coefficientOpenings: readonly VssCoefficientOpeningMaterial[];
}>;

export type VssSourceTrusteeCoefficientCommitmentContributionInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly structuredCommitmentOpenings: ClosedWorkerStructuredCommitmentOpeningOperations;
    readonly thresholdDegree: number;
    readonly sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState;
};
