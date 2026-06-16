// Shared vocabulary and types for the VSS coefficient-commitment record
// builders: profile and transport constants, the BDLOP commitment shape, the
// per-source-trustee opening-state and commitment record families, the binary
// transport object shapes, and the bundle input/output contracts. This is the
// leaf module the other parts build on.
import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

export type JsonRecord = Record<string, unknown>;

export const setupCommitmentProfileId = 'SealedLattice-BDLOP-Commitment-v1';

const setupCommitmentModuleRank = 2;

export const setupCommitmentRandomnessWidth = 2 * setupCommitmentModuleRank + 1;

export const setupCommitmentRowCount = setupCommitmentModuleRank + 1;

export const setupCommitmentModulusLimbIndices = [0, 1, 2] as const;

export const acceptedBgvProfileRingDegree = 32_768;

export const acceptedBgvSetupQSharePrimes = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
    140_737_485_864_961, 140_737_484_685_313, 140_737_483_898_881,
    140_737_482_981_377, 140_737_481_801_729, 140_737_481_342_977,
    140_737_480_949_761, 140_737_480_359_937, 140_737_479_639_041,
    140_737_476_100_097, 140_737_472_299_009, 140_737_471_971_329,
    140_737_471_774_721, 140_737_471_578_113,
] as const;

export const acceptedBgvSetupQShare = {
    objectType: 'QSharePrimeList',
    objectVersion: 1,
    sharingDomain: 'per-rns-prime',
    primeOrder: 'profile-order',
    targetDecryptionReadiness: 'refused-until-q-target-certificate-closes',
    primes: acceptedBgvSetupQSharePrimes,
} as const;

export const acceptedBgvSetupQShareHash = deriveProtocolHash(
    'QSharePrimeListHash',
    acceptedBgvSetupQShare,
);

export const setupTransportProfileId =
    'sealed-lattice-setup-binary-chunked-transport-v1';

export const setupTransportChunkSizeBytes = 1_048_576;

export const vssCoefficientCommitmentMaterialBinaryFormat =
    'sealed-lattice-vss-coefficient-commitment-material-binary-v1';

export const vssCoefficientCommitmentMaterialBinaryMagic =
    new TextEncoder().encode('SLVSSMAT');

export type SetupCommitmentLimbValue = {
    readonly commitmentModulusIndex: number;
    readonly modulus: number;
    readonly rows: readonly (readonly number[])[];
};

export type SetupCommitmentValue = {
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
        readonly objectVersion: 1;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly shamirCoefficientIndex: number;
        readonly commitmentRoot: ProtocolHash;
        readonly commitmentChunkRoot: ProtocolHash;
        readonly coefficientVectorHash512: string;
    }
>;

export type VssSourceTrusteeCoefficientCommitmentRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'VssSourceTrusteeCoefficientCommitments';
        readonly objectVersion: 1;
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
        readonly objectVersion: 1;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly shamirCoefficientIndex: number;
        readonly commitmentRoot: ProtocolHash;
        readonly commitment: JsonRecord;
    }
>;

export type VssCoefficientCommitmentSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssCoefficientCommitmentSet';
        readonly objectVersion: 1;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceTrusteeRecords: readonly VssSourceTrusteeCoefficientCommitmentRecord[];
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
    }
>;

export type VssCoefficientCommitmentMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssCoefficientCommitmentMaterialSet';
        readonly objectVersion: 1;
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly materialEncoding: 'full-public-setup-commitment-values';
        readonly participantCount: number;
        readonly thresholdDegree: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly ringDegreeStatus: 'profile-ring' | 'development-reduced-ring';
        readonly materialRecordCount: number;
        readonly coefficientCommitments: readonly VssCoefficientCommitmentMaterialRecord[];
        readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
    }
>;

export type SetupTransportChunk = Readonly<
    JsonRecord & {
        readonly chunkIndex: number;
        readonly bytesHex: string;
    }
>;

export type SetupTransportedVssCoefficientCommitmentMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportedVssCoefficientCommitmentMaterial';
        readonly objectVersion: 1;
        readonly binaryFormat: typeof vssCoefficientCommitmentMaterialBinaryFormat;
        readonly chunkSizeBytes: typeof setupTransportChunkSizeBytes;
        readonly chunkCount: number;
        readonly totalByteLength: number;
        readonly fullObjectHash: ProtocolHash;
        readonly chunkHashes: readonly ProtocolHash[];
        readonly chunkRoot: ProtocolHash;
        readonly chunks: readonly SetupTransportChunk[];
    }
>;

export type SetupTransportedVssCoefficientCommitmentMaterialReference =
    Readonly<
        JsonRecord & {
            readonly objectType: 'SetupTransportedVssCoefficientCommitmentMaterial';
            readonly objectVersion: 1;
            readonly binaryFormat: typeof vssCoefficientCommitmentMaterialBinaryFormat;
            readonly chunkSizeBytes: typeof setupTransportChunkSizeBytes;
            readonly chunkCount: number;
            readonly totalByteLength: number;
            readonly fullObjectHash: ProtocolHash;
            readonly chunkHashes: readonly ProtocolHash[];
            readonly chunkRoot: ProtocolHash;
        }
    >;

export type SetupTransportedVssCoefficientCommitmentMaterialTemplate = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportedVssCoefficientCommitmentMaterial';
        readonly objectVersion: 1;
        readonly binaryFormat: typeof vssCoefficientCommitmentMaterialBinaryFormat;
        readonly chunkSizeBytes: typeof setupTransportChunkSizeBytes;
        readonly chunkCount: number;
        readonly totalByteLength: number;
    }
>;

export type SetupTransportedVssCoefficientCommitmentMaterialLike =
    | SetupTransportedVssCoefficientCommitmentMaterial
    | SetupTransportedVssCoefficientCommitmentMaterialReference;

export type BinaryChunkedVssCoefficientCommitmentMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssCoefficientCommitmentMaterialSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly commitmentProfileHash: ProtocolHash;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly materialEncoding: 'binary-chunked-full-public-setup-commitment-values';
        readonly binaryFormat: typeof vssCoefficientCommitmentMaterialBinaryFormat;
        readonly participantCount: number;
        readonly thresholdDegree: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly ringDegreeStatus: 'profile-ring' | 'development-reduced-ring';
        readonly materialRecordCount: number;
        readonly transport: Readonly<
            JsonRecord & {
                readonly transportProfileId: typeof setupTransportProfileId;
                readonly chunkSizeBytes: typeof setupTransportChunkSizeBytes;
                readonly chunkCount: number;
                readonly totalByteLength: number;
                readonly fullObjectHash: ProtocolHash;
                readonly chunkRoot: ProtocolHash;
            }
        >;
        readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
    }
>;

export type SetupPackageVssCoefficientCommitmentMaterialSet =
    | VssCoefficientCommitmentMaterialSet
    | BinaryChunkedVssCoefficientCommitmentMaterialSet;

export type BinaryChunkedVssCoefficientCommitmentMaterialTransport = Readonly<{
    readonly materialSet: BinaryChunkedVssCoefficientCommitmentMaterialSet;
    readonly transportedVssCoefficientCommitmentMaterial: SetupTransportedVssCoefficientCommitmentMaterial;
}>;

export type BinaryChunkedVssCoefficientCommitmentBundle = Readonly<{
    readonly commitmentSet: VssCoefficientCommitmentSet;
    readonly materialSet: BinaryChunkedVssCoefficientCommitmentMaterialSet;
    readonly transportedVssCoefficientCommitmentMaterial: SetupTransportedVssCoefficientCommitmentMaterial;
    readonly privateOpeningMaterialBySourceTrustee: readonly VssSourceTrusteeOpeningMaterial[];
    readonly sourceTrusteeOpeningMaterialSource: VssSourceTrusteeOpeningMaterialSource;
}>;

export type VerifiedVssCoefficientCommitmentMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'VerifiedVssCoefficientCommitmentMaterial';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly verificationId: string;
        readonly materialBinaryFormat: typeof vssCoefficientCommitmentMaterialBinaryFormat;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
        readonly thresholdShareCommitmentRoot: ProtocolHash;
        readonly transportProfileId: typeof setupTransportProfileId;
        readonly transportChunkSizeBytes: typeof setupTransportChunkSizeBytes;
        readonly transportChunkCount: number;
        readonly transportTotalByteLength: number;
        readonly transportFullObjectHash: ProtocolHash;
        readonly transportChunkRoot: ProtocolHash;
    }
>;

export type ThresholdShareCommitmentTransportStreamComputer = Readonly<{
    beginThresholdShareCommitmentsFromTransportStream: (input: {
        readonly derivationId: string;
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly transportedVssCoefficientCommitmentMaterial:
            | SetupTransportedVssCoefficientCommitmentMaterialReference
            | SetupTransportedVssCoefficientCommitmentMaterialTemplate;
    }) => JsonRecord;
    absorbThresholdShareCommitmentsFromTransportStreamChunk: (input: {
        readonly derivationId: string;
        readonly chunkIndex: number;
        readonly bytesHex: string;
    }) => JsonRecord;
    finishThresholdShareCommitmentsFromTransportStream: (input: {
        readonly derivationId: string;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
    }) => {
        readonly thresholdShareCommitmentRoot: ProtocolHash;
        readonly thresholdShareCommitments: JsonRecord;
        readonly vssCoefficientCommitmentMaterial: JsonRecord;
        readonly verifiedVssCoefficientCommitmentMaterial: VerifiedVssCoefficientCommitmentMaterial;
        readonly transport: JsonRecord;
    };
}>;

export type StreamingBinaryChunkedVssCoefficientCommitmentBundle = Readonly<{
    readonly commitmentSet: VssCoefficientCommitmentSet;
    readonly materialSet: BinaryChunkedVssCoefficientCommitmentMaterialSet;
    readonly transportedVssCoefficientCommitmentMaterial: SetupTransportedVssCoefficientCommitmentMaterialReference;
    readonly verifiedVssCoefficientCommitmentMaterial: VerifiedVssCoefficientCommitmentMaterial;
    readonly privateOpeningMaterialBySourceTrustee: readonly VssSourceTrusteeOpeningMaterial[];
    readonly sourceTrusteeOpeningMaterialSource: VssSourceTrusteeOpeningMaterialSource;
    readonly thresholdShareCommitments: JsonRecord;
}>;

export type VssSourceTrusteeOpeningMaterial = Readonly<{
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly sourceTrusteeCommitmentRoot: ProtocolHash;
    readonly sourceTrusteeCoefficientCommitmentRecord: VssSourceTrusteeCoefficientCommitmentRecord;
    readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly VssCoefficientCommitmentMaterialRecord[];
    readonly coefficientOpenings: readonly VssCoefficientOpeningMaterial[];
}>;

export type VssSourceTrusteeOpeningMaterialReference = Readonly<{
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly sourceTrusteeCommitmentRoot: ProtocolHash;
}>;

export type VssSourceTrusteeOpeningMaterialSource = Readonly<{
    readonly sourceTrusteeReferences: readonly VssSourceTrusteeOpeningMaterialReference[];
    readonly loadSourceTrusteeOpeningMaterial: (
        sourceTrusteeReference: VssSourceTrusteeOpeningMaterialReference,
    ) => VssSourceTrusteeOpeningMaterial;
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
    readonly sourceTrusteeOpeningMaterialSource: VssSourceTrusteeOpeningMaterialSource;
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

export type VssSourceTrusteeCoefficientCommitmentContributionOptions =
    Readonly<{
        readonly retainMaterialRecords: boolean;
        readonly consumeMaterialRecord?: (
            materialRecord: VssCoefficientCommitmentMaterialRecord,
        ) => void;
        readonly setupCommitmentComputer: SetupCommitmentOpeningComputer;
    }>;

export type SetupCommitmentOpeningComputation = Readonly<{
    readonly commitment: JsonRecord;
    readonly commitmentRoot: ProtocolHash;
    readonly commitmentChunkRoot: ProtocolHash;
    readonly coefficientVectorHash512: string;
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
