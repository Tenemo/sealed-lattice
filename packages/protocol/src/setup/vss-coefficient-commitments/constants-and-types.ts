import type { ProtocolHash } from '@sealed-lattice/types';

import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

const setupCommitmentModuleRank = 2;

export const setupCommitmentRandomnessWidth = 2 * setupCommitmentModuleRank + 1;

type SetupCommitmentLimbValue = {
    readonly commitmentModulusIndex: number;
    readonly modulus: number;
    readonly rows: readonly (readonly number[])[];
};

export type SetupCommitmentValue = {
    readonly objectType: 'SetupCommitment';
    readonly sourceRnsLimbIndex: number;
    readonly shamirCoefficientIndex: number;
    readonly ringDegree: number;
    readonly commitmentLimbs: readonly SetupCommitmentLimbValue[];
};

export type VssCoefficientOpeningInput = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientMessage: readonly number[];
    readonly randomnessByColumn: readonly (readonly number[])[];
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
    readonly thresholdDegree: number;
};

export type VssSourceTrusteeCoefficientCommitmentRecord = Readonly<{
    readonly objectType: 'VssSourceTrusteeCoefficientCommitments';
    readonly sourceTrusteeIdentity: string;
    readonly coefficientCommitmentRoots: readonly ProtocolHash[];
}>;

export type VssCoefficientCommitmentSet = Readonly<{
    readonly objectType: 'VssCoefficientCommitmentSet';
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
    readonly thresholdDegree: number;
    readonly sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState;
    readonly setupCommitmentComputer: SetupCommitmentOpeningComputer;
};

type SetupCommitmentOpeningComputation = Readonly<{
    readonly commitment: SetupCommitmentValue;
}>;

type SetupCommitmentOpeningComputer = (
    input: Readonly<{
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceRnsLimbIndex: number;
        readonly shamirCoefficientIndex: number;
        readonly messageCoefficients: readonly number[];
        readonly randomnessByColumn: readonly (readonly number[])[];
        readonly ringDegree: number;
    }>,
) => SetupCommitmentOpeningComputation;
