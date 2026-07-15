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
    readonly sourceMessageModulus: number;
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

export type VssSourceTrusteeCoefficientOpeningStateReference = Readonly<{
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
}>;

export type VssSourceTrusteeCoefficientOpeningStateProvider = Readonly<{
    readonly sourceTrusteeReferences: readonly VssSourceTrusteeCoefficientOpeningStateReference[];
    readonly loadSourceTrusteeOpeningState: (
        sourceTrusteeReference: VssSourceTrusteeCoefficientOpeningStateReference,
    ) => VssSourceTrusteeCoefficientOpeningState;
}>;

export type VssOpeningRandomByteSource = (byteLength: number) => Uint8Array;

export type VssSourceTrusteeCoefficientOpeningStateGenerationInput = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly randomBytes?: VssOpeningRandomByteSource;
};

export type VssSourceTrusteeCoefficientOpeningStateProviderInput = Readonly<{
    readonly sourceTrustees: readonly VssSourceTrusteeCoefficientOpeningStateReference[];
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly randomBytesForSourceTrustee: (
        sourceTrusteeReference: VssSourceTrusteeCoefficientOpeningStateReference,
    ) => VssOpeningRandomByteSource;
}>;

export type VssCoefficientCommitmentRecord = Readonly<{
    readonly objectType: 'VssCoefficientCommitment';
    readonly commitmentRoot: ProtocolHash;
}>;

export type VssSourceTrusteeCoefficientCommitmentRecord = Readonly<{
    readonly objectType: 'VssSourceTrusteeCoefficientCommitments';
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly coefficientCommitments: readonly VssCoefficientCommitmentRecord[];
}>;

export type VssCoefficientCommitmentMaterialRecord = Readonly<{
    readonly objectType: 'VssCoefficientCommitmentMaterial';
    readonly commitment: SetupCommitmentValue;
}>;

export type VssCoefficientCommitmentSet = Readonly<{
    readonly objectType: 'VssCoefficientCommitmentSet';
    readonly setupContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeRecords: readonly VssSourceTrusteeCoefficientCommitmentRecord[];
}>;

export type VssSourceTrusteeOpeningMaterial = Readonly<{
    readonly sourceTrusteeCoefficientCommitmentRecord: VssSourceTrusteeCoefficientCommitmentRecord;
    readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly VssCoefficientCommitmentMaterialRecord[];
    readonly coefficientOpenings: readonly VssCoefficientOpeningMaterial[];
}>;

export type VssCoefficientCommitmentBundle = Readonly<{
    readonly commitmentSet: VssCoefficientCommitmentSet;
    readonly privateOpeningMaterialBySourceTrustee: readonly VssSourceTrusteeOpeningMaterial[];
}>;

export type VssCoefficientCommitmentBundleInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly sourceTrusteeOpeningStates?: readonly VssSourceTrusteeCoefficientOpeningState[];
    readonly sourceTrusteeOpeningStateProvider?: VssSourceTrusteeCoefficientOpeningStateProvider;
    readonly setupCommitmentComputer: SetupCommitmentOpeningComputer;
};

export type VssSourceTrusteeCoefficientCommitmentContributionInput = Omit<
    VssCoefficientCommitmentBundleInput,
    'sourceTrusteeOpeningStateProvider' | 'sourceTrusteeOpeningStates'
> & {
    readonly sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState;
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
