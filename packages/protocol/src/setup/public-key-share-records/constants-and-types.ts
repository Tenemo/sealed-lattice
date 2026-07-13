import type { ProtocolHash } from '@sealed-lattice/types';

import type {
    CanonicalProofMaterialChunkPull,
    TransportedSetupProofMaterialSet,
} from '../setup-proof-material-transport.js';
import type {
    VssSameSecretBridgeProofMaterialSet,
    VssSameSecretBridgeStatementSet,
} from '../vss-commitments.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

export type JsonRecord = Record<string, unknown>;

export const publicKeyShareCoefficientVectorHashDomain =
    'sealed-lattice-bgv-rns/public-key-share-coefficient-vector';

export type PublicKeyShareCoefficientVectorHash = Readonly<{
    readonly coefficientVectorHash512: ProtocolHash;
}>;

export type PublicKeyShareContributionInput = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareCoefficientVectorHash512ByLimb: readonly PublicKeyShareCoefficientVectorHash[];
}>;

export type PublicKeyShareCoefficientVectorMaterial = Readonly<
    JsonRecord & {
        readonly coefficientsLeHex: string;
    }
>;

export type PublicKeyShareMaterialContributionInput = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareCoefficientVectorsByLimb: readonly PublicKeyShareCoefficientVectorMaterial[];
}>;

export type PublicKeyShareRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShare';
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly shareCoefficientVectorHash512ByLimb: readonly PublicKeyShareCoefficientVectorHash[];
        readonly publicKeyShareRoot: ProtocolHash;
    }
>;

export type PublicKeyShareSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareSet';
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly shareRecords: readonly PublicKeyShareRecord[];
        readonly publicKeyShareSetRoot: ProtocolHash;
    }
>;

export type PublicKeyShareMaterialRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareMaterial';
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareRoot: ProtocolHash;
        readonly shareCoefficientVectorsByLimb: readonly PublicKeyShareCoefficientVectorMaterial[];
        readonly publicKeyShareMaterialRoot: ProtocolHash;
    }
>;

export type PublicKeyShareMaterialRootReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly publicKeyShareMaterialRoot: ProtocolHash;
}>;

export type PublicKeyShareMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareMaterialSet';
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly shareMaterialRecords: readonly PublicKeyShareMaterialRecord[];
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
    }
>;

export type BinaryChunkedPublicKeyShareMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareMaterialSet';
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialRoots: readonly PublicKeyShareMaterialRootReference[];
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
    }
>;

export type SetupTransportedPublicKeyShareMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportedPublicKeyShareMaterial';
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        readonly descriptorBytes: Uint8Array;
    }
>;

export type PublicKeyShareMaterialChunkSource = Readonly<{
    readonly publicKeyShareMaterialSetRoot: ProtocolHash;
    readonly pullChunk: CanonicalProofMaterialChunkPull;
}>;

export type PublicKeyShareMaterialWriter = (input: {
    readonly publicKeyShareMaterialSetRoot: ProtocolHash;
    readonly pullChunk: CanonicalProofMaterialChunkPull;
    readonly totalByteLength: number;
}) => Promise<Uint8Array>;

export type BinaryChunkedPublicKeyShareMaterialTransportInput = Readonly<{
    readonly materialSet: PublicKeyShareMaterialSet;
    readonly qSharePrimes: readonly number[];
    readonly writePublicKeyShareMaterial: PublicKeyShareMaterialWriter;
}>;

export type BinaryChunkedPublicKeyShareMaterialBundleInput = Readonly<
    PublicKeyShareMaterialSetInput & {
        readonly writePublicKeyShareMaterial: PublicKeyShareMaterialWriter;
    }
>;

export type BinaryChunkedPublicKeyShareMaterialTransport = Readonly<{
    readonly materialSet: BinaryChunkedPublicKeyShareMaterialSet;
    readonly transportedPublicKeyShareMaterial: SetupTransportedPublicKeyShareMaterial;
    readonly publicKeyShareMaterialChunkSource: PublicKeyShareMaterialChunkSource;
}>;

export type BinaryChunkedPublicKeyShareMaterialBundle = Readonly<{
    readonly materialSet: BinaryChunkedPublicKeyShareMaterialSet;
    readonly transportedPublicKeyShareMaterial: SetupTransportedPublicKeyShareMaterial;
    readonly publicKeyShareMaterialChunkSource: PublicKeyShareMaterialChunkSource;
}>;

export type SetupPackagePublicKeyShareMaterialSet =
    | PublicKeyShareMaterialSet
    | BinaryChunkedPublicKeyShareMaterialSet;

export type PublicKeyShareSuccinctProofByteMaterial = Readonly<{
    readonly proofMaterialRoot: ProtocolHash;
}>;

export type PublicKeyShareSuccinctProofMaterial = Readonly<
    PublicKeyShareSuccinctProofByteMaterial & {
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly statementHash: ProtocolHash;
        readonly proofBytesHash: ProtocolHash;
    }
>;

export type PublicKeyShareSuccinctProofRecord = Readonly<
    JsonRecord &
        PublicKeyShareSuccinctProofByteMaterial & {
            readonly objectType: 'PublicKeyShareSuccinctProof';
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly publicKeyShareRoot: ProtocolHash;
            readonly publicKeyShareMaterialRoot: ProtocolHash;
            readonly sameSecretBridgeStatementRoot: ProtocolHash;
            readonly sameSecretBridgeProofRecordRoot: ProtocolHash;
            readonly statementHash: ProtocolHash;
            readonly proofBytesHash: ProtocolHash;
        }
>;

export type PublicKeyShareSuccinctProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareSuccinctProofSet';
        readonly proofRecords: readonly PublicKeyShareSuccinctProofRecord[];
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
    }
>;

type CollectivePublicKeyCoefficientVectorMaterial = Readonly<
    JsonRecord & {
        readonly coefficientsLeHex: string;
    }
>;

export type CollectivePublicKey = Readonly<
    JsonRecord & {
        readonly objectType: 'CollectivePublicKey';
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly aggregateCoefficientVectorsByLimb: readonly CollectivePublicKeyCoefficientVectorMaterial[];
        readonly collectivePublicKeyRoot: ProtocolHash;
    }
>;

export type PublicKeyShareSetInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly publicKeyCrpRoot: ProtocolHash;
    readonly publicAPolynomialRoot: ProtocolHash;
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

export type PublicKeyShareSuccinctProofSetInput = Omit<
    PublicKeyShareSetInput,
    'shareContributions'
> & {
    readonly publicKeyShares: PublicKeyShareSet;
    readonly publicKeyShareMaterial: SetupPackagePublicKeyShareMaterialSet;
    readonly sameSecretBridgeStatementSet: VssSameSecretBridgeStatementSet;
    readonly sameSecretBridgeProofMaterialSet: VssSameSecretBridgeProofMaterialSet;
    readonly proofMaterials: readonly PublicKeyShareSuccinctProofMaterial[];
};

export type TransportedPublicKeyShareProofMaterialSet = Readonly<
    TransportedSetupProofMaterialSet & {
        readonly objectType: 'SetupTransportedPublicKeyShareProofMaterialSet';
    }
>;
