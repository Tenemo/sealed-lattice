import type { ProtocolHash } from '@sealed-lattice/types';

import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

export type JsonRecord = Record<string, unknown>;

const setupCommitmentModuleRank = 2;

export const setupCommitmentRandomnessWidth = 2 * setupCommitmentModuleRank + 1;

export const acceptedBgvSetupQSharePrimes = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
    140_737_485_864_961, 140_737_484_685_313, 140_737_483_898_881,
    140_737_482_981_377, 140_737_481_801_729, 140_737_481_342_977,
    140_737_480_949_761, 140_737_480_359_937, 140_737_479_639_041,
    140_737_476_100_097, 140_737_472_299_009, 140_737_471_971_329,
    140_737_471_774_721, 140_737_471_578_113,
] as const;

export type SetupCommitmentLimbValue = {
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

export type VssCoefficientCommitmentRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'VssCoefficientCommitment';
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly shamirCoefficientIndex: number;
        readonly commitmentRoot: ProtocolHash;
    }
>;

export type VssSourceTrusteeCoefficientCommitmentRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'VssSourceTrusteeCoefficientCommitments';
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly coefficientCommitments: readonly VssCoefficientCommitmentRecord[];
        readonly sourceTrusteeCommitmentRoot: ProtocolHash;
    }
>;

export type VssCoefficientCommitmentMaterialRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'VssCoefficientCommitmentMaterial';
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly shamirCoefficientIndex: number;
        readonly commitmentRoot: ProtocolHash;
        readonly commitment: SetupCommitmentValue;
    }
>;

export type VssCoefficientCommitmentSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssCoefficientCommitmentSet';
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceTrusteeRecords: readonly VssSourceTrusteeCoefficientCommitmentRecord[];
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
    }
>;

export type VssCoefficientCommitmentMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssCoefficientCommitmentMaterialSet';
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly participantCount: number;
        readonly thresholdDegree: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly coefficientCommitments: readonly VssCoefficientCommitmentMaterialRecord[];
        readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
    }
>;

export type VssSourceTrusteeOpeningMaterial = Readonly<{
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly sourceTrusteeCommitmentRoot: ProtocolHash;
    readonly sourceTrusteeCoefficientCommitmentRecord: VssSourceTrusteeCoefficientCommitmentRecord;
    readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly VssCoefficientCommitmentMaterialRecord[];
    readonly coefficientOpenings: readonly VssCoefficientOpeningMaterial[];
}>;

export type VssSourceTrusteeCoefficientCommitmentContribution = Readonly<{
    readonly sourceTrusteeRecord: VssSourceTrusteeCoefficientCommitmentRecord;
    readonly materialRecords: readonly VssCoefficientCommitmentMaterialRecord[];
    readonly privateOpeningMaterial: VssSourceTrusteeOpeningMaterial;
}>;

export type VssCoefficientCommitmentBundle = Readonly<{
    readonly commitmentSet: VssCoefficientCommitmentSet;
    readonly materialSet: VssCoefficientCommitmentMaterialSet;
    readonly privateOpeningMaterialBySourceTrustee: readonly VssSourceTrusteeOpeningMaterial[];
}>;

export type VssCoefficientCommitmentBundleInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly participantCount: number;
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


export type SetupCommitmentOpeningComputation = Readonly<{
    readonly commitment: SetupCommitmentValue;
    readonly commitmentRoot: ProtocolHash;
}>;

export type SetupCommitmentOpeningComputer = (
    input: Readonly<{
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceRnsLimbIndex: number;
        readonly sourceMessageModulus: number;
        readonly shamirCoefficientIndex: number;
        readonly messageCoefficients: readonly number[];
        readonly randomnessByColumn: readonly (readonly number[])[];
        readonly ringDegree: number;
    }>,
) => SetupCommitmentOpeningComputation;
