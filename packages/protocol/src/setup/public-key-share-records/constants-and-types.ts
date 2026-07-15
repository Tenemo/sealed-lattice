import type { ProtocolHash } from '@sealed-lattice/types';

import type {
    CanonicalProofMaterialChunkPull,
    SetupProofMaterialStreamSet,
} from '../setup-proof-material-transport.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

export const publicKeyShareCoefficientVectorHashDomain =
    'sealed-lattice-bgv-rns/public-key-share-coefficient-vector';

export type PublicKeyShareContributionInput = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly shareCoefficientVectorHashesByLimb: readonly ProtocolHash[];
}>;

export type PublicKeyShareMaterialContributionInput = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly shareCoefficientVectorsLittleEndianHexByLimb: readonly string[];
}>;

export type PublicKeyShareRecord = Readonly<{
    readonly objectType: 'PublicKeyShare';
    readonly shareCoefficientVectorHashesByLimb: readonly ProtocolHash[];
}>;

export type PublicKeyShareSet = Readonly<{
    readonly objectType: 'PublicKeyShareSet';
    readonly shareRecords: readonly PublicKeyShareRecord[];
}>;

export type PublicKeyShareMaterialRecord = Readonly<{
    readonly objectType: 'PublicKeyShareMaterial';
    readonly shareCoefficientVectorsLittleEndianHexByLimb: readonly string[];
}>;

export type BinaryChunkedPublicKeyShareMaterialSet = Readonly<{
    readonly objectType: 'PublicKeyShareMaterialSet';
    readonly publicKeyShareMaterialSetRoot: ProtocolHash;
}>;

export type PublicKeyShareMaterialStream = Readonly<{
    readonly descriptorBytes: Uint8Array;
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
    readonly publicKeyShareMaterialStream: PublicKeyShareMaterialStream;
}>;

export type SetupPackagePublicKeyShareMaterialSet =
    BinaryChunkedPublicKeyShareMaterialSet;

export type PublicKeyShareSuccinctProofMaterial = Readonly<{
    readonly proofBytesHash: ProtocolHash;
}>;

export type PublicKeyShareSuccinctProofSet = Readonly<{
    readonly objectType: 'PublicKeyShareSuccinctProofSet';
    readonly proofBytesHashes: readonly ProtocolHash[];
}>;

export type CollectivePublicKey = Readonly<{
    readonly objectType: 'CollectivePublicKey';
    readonly aggregateCoefficientVectorsLittleEndianHexByLimb: readonly string[];
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
    SetupProofMaterialStreamSet;
