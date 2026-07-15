import type { ProtocolHash } from '@sealed-lattice/types';

import type {
    CanonicalProofMaterialChunkPull,
    TransportedSetupProofMaterialSet,
} from '../setup-proof-material-transport.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

export const publicKeyShareCoefficientVectorHashDomain =
    'sealed-lattice-bgv-rns/public-key-share-coefficient-vector';

type PublicKeyShareCoefficientVectorHash = Readonly<{
    readonly coefficientVectorHash512: ProtocolHash;
}>;

export type PublicKeyShareContributionInput = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareCoefficientVectorHash512ByLimb: readonly PublicKeyShareCoefficientVectorHash[];
}>;

export type PublicKeyShareCoefficientVectorMaterial = Readonly<{
    readonly coefficientsLeHex: string;
}>;

export type PublicKeyShareMaterialContributionInput = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareCoefficientVectorsByLimb: readonly PublicKeyShareCoefficientVectorMaterial[];
}>;

export type PublicKeyShareRecord = Readonly<{
    readonly objectType: 'PublicKeyShare';
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareCoefficientVectorHash512ByLimb: readonly PublicKeyShareCoefficientVectorHash[];
}>;

export type PublicKeyShareSet = Readonly<{
    readonly objectType: 'PublicKeyShareSet';
    readonly shareRecords: readonly PublicKeyShareRecord[];
}>;

export type PublicKeyShareMaterialRecord = Readonly<{
    readonly objectType: 'PublicKeyShareMaterial';
    readonly shareCoefficientVectorsByLimb: readonly PublicKeyShareCoefficientVectorMaterial[];
}>;

export type BinaryChunkedPublicKeyShareMaterialSet = Readonly<{
    readonly objectType: 'PublicKeyShareMaterialSet';
    readonly publicKeyShareMaterialSetRoot: ProtocolHash;
}>;

export type SetupTransportedPublicKeyShareMaterial = Readonly<{
    readonly publicKeyShareMaterialSetRoot: ProtocolHash;
    readonly descriptorBytes: Uint8Array;
}>;

export type PublicKeyShareMaterialChunkSource = Readonly<{
    readonly pullChunk: CanonicalProofMaterialChunkPull;
}>;

type PublicKeyShareMaterialWriter = (input: {
    readonly publicKeyShareMaterialSetRoot: ProtocolHash;
    readonly pullChunk: CanonicalProofMaterialChunkPull;
    readonly totalByteLength: number;
}) => Promise<Uint8Array>;

export type BinaryChunkedPublicKeyShareMaterialBundleInput = Readonly<
    PublicKeyShareMaterialSetInput & {
        readonly writePublicKeyShareMaterial: PublicKeyShareMaterialWriter;
    }
>;

export type BinaryChunkedPublicKeyShareMaterialBundle = Readonly<{
    readonly materialSet: BinaryChunkedPublicKeyShareMaterialSet;
    readonly transportedPublicKeyShareMaterial: SetupTransportedPublicKeyShareMaterial;
    readonly publicKeyShareMaterialChunkSource: PublicKeyShareMaterialChunkSource;
}>;

export type SetupPackagePublicKeyShareMaterialSet =
    BinaryChunkedPublicKeyShareMaterialSet;

export type PublicKeyShareSuccinctProofMaterial = Readonly<{
    readonly proofBytesHash: ProtocolHash;
}>;

export type PublicKeyShareSuccinctProofRecord = Readonly<{
    readonly objectType: 'PublicKeyShareSuccinctProof';
    readonly proofBytesHash: ProtocolHash;
}>;

export type PublicKeyShareSuccinctProofSet = Readonly<{
    readonly objectType: 'PublicKeyShareSuccinctProofSet';
    readonly proofRecords: readonly PublicKeyShareSuccinctProofRecord[];
}>;

type CollectivePublicKeyCoefficientVectorMaterial = Readonly<{
    readonly coefficientsLeHex: string;
}>;

export type CollectivePublicKey = Readonly<{
    readonly objectType: 'CollectivePublicKey';
    readonly aggregateCoefficientVectorsByLimb: readonly CollectivePublicKeyCoefficientVectorMaterial[];
}>;

export type PublicKeyShareSetInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly shareContributions: readonly PublicKeyShareContributionInput[];
};

export type PublicKeyShareMaterialSetInput = Omit<
    PublicKeyShareSetInput,
    'shareContributions'
> & {
    readonly ringDegree: number;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly materialContributions: readonly PublicKeyShareMaterialContributionInput[];
};

export type PublicKeyShareSuccinctProofSetInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly proofMaterials: readonly PublicKeyShareSuccinctProofMaterial[];
}>;

export type TransportedPublicKeyShareProofMaterialSet =
    TransportedSetupProofMaterialSet;
