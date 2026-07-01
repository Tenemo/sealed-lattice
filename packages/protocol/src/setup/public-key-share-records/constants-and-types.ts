import type { ProtocolHash } from '@sealed-lattice/types';

import {
    type SameSecretProofSet,
    type SameSecretConsistencyStatementSet,
} from '../same-secret-consistency-records.js';
import type { TransportedSetupProofMaterialSet } from '../setup-proof-material-transport.js';
import {
    setupTransportChunkSizeBytes,
    setupTransportSchemeId,
} from '../vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

export type JsonRecord = Record<string, unknown>;

export const isJsonRecord = (value: unknown): value is JsonRecord =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

export const publicKeyShareProofFamily = 'public-key-share';
export const publicKeyShareMaterialEncoding =
    'embedded-full-public-key-share-coefficients';
export const publicKeyShareMaterialTransportEncoding =
    'binary-chunked-full-public-key-share-coefficients';
export const publicKeyShareMaterialBinaryFormat =
    'sealed-lattice-public-key-share-material-binary-v1';
export const publicKeyShareCoefficientVectorHashDomain =
    'sealed-lattice-bgv-rns/public-key-share-coefficient-vector-v1';

export type PublicKeyShareCoefficientVectorHash = Readonly<{
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly component: 'b_i';
    readonly coefficientVectorHash512: ProtocolHash;
}>;

export type PublicKeyShareContributionInput = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareCoefficientVectorHash512ByLimb: readonly PublicKeyShareCoefficientVectorHash[];
}>;

export type PublicKeyShareCoefficientVectorMaterial = Readonly<
    JsonRecord & {
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly component: 'b_i';
        readonly coefficientByteLength: number;
        readonly coefficientVectorHash512: ProtocolHash;
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
        readonly objectVersion: 1;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly shareComponent: 'component-zero-b_i';
        readonly rnsLimbCount: number;
        readonly shareCoefficientVectorHash512ByLimb: readonly PublicKeyShareCoefficientVectorHash[];
        readonly publicKeyShareRoot: ProtocolHash;
    }
>;

export type PublicKeyShareSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareSet';
        readonly objectVersion: 1;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly shareRecords: readonly PublicKeyShareRecord[];
        readonly publicKeyShareSetRoot: ProtocolHash;
    }
>;

export type PublicKeyShareProofRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareProof';
        readonly objectVersion: 1;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly rnsLimbCount: number;
        readonly publicKeyShareProofRoot: ProtocolHash;
    }
>;

export type PublicKeyShareProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareProofSet';
        readonly objectVersion: 1;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly proofRecords: readonly PublicKeyShareProofRecord[];
        readonly publicKeyShareProofSetRoot: ProtocolHash;
    }
>;

export type PublicKeyShareMaterialRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareMaterial';
        readonly objectVersion: 1;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly materialEncoding: typeof publicKeyShareMaterialEncoding;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
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
        readonly objectVersion: 1;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly materialEncoding: typeof publicKeyShareMaterialEncoding;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialRoots: readonly PublicKeyShareMaterialRootReference[];
        readonly shareMaterialRecords: readonly PublicKeyShareMaterialRecord[];
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
    }
>;

export type BinaryChunkedPublicKeyShareMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareMaterialSet';
        readonly objectVersion: 1;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly materialEncoding: typeof publicKeyShareMaterialTransportEncoding;
        readonly binaryFormat: typeof publicKeyShareMaterialBinaryFormat;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialRoots: readonly PublicKeyShareMaterialRootReference[];
        readonly transport: {
            readonly transportSchemeId: typeof setupTransportSchemeId;
            readonly chunkSizeBytes: typeof setupTransportChunkSizeBytes;
            readonly chunkCount: number;
            readonly totalByteLength: number;
            readonly fullObjectHash: ProtocolHash;
            readonly chunkRoot: ProtocolHash;
        };
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
    }
>;

export type SetupTransportedPublicKeyShareMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportedPublicKeyShareMaterial';
        readonly objectVersion: 1;
        readonly binaryFormat: typeof publicKeyShareMaterialBinaryFormat;
        readonly chunkSizeBytes: typeof setupTransportChunkSizeBytes;
        readonly chunkCount: number;
        readonly totalByteLength: number;
        readonly fullObjectHash: ProtocolHash;
        readonly chunkHashes: readonly ProtocolHash[];
        readonly chunkRoot: ProtocolHash;
        readonly chunks: readonly {
            readonly chunkIndex: number;
            readonly bytesHex: string;
        }[];
    }
>;

export type BinaryChunkedPublicKeyShareMaterialTransport = Readonly<{
    readonly materialSet: BinaryChunkedPublicKeyShareMaterialSet;
    readonly transportedPublicKeyShareMaterial: SetupTransportedPublicKeyShareMaterial;
}>;

export type BinaryChunkedPublicKeyShareMaterialBundle = Readonly<{
    readonly materialSet: BinaryChunkedPublicKeyShareMaterialSet;
    readonly transportedPublicKeyShareMaterial: SetupTransportedPublicKeyShareMaterial;
}>;

export type SetupPackagePublicKeyShareMaterialSet =
    | PublicKeyShareMaterialSet
    | BinaryChunkedPublicKeyShareMaterialSet;

export type PublicKeyShareSuccinctEmbeddedProofBytes = Readonly<{
    readonly proofBytesHex: string;
}>;

export type PublicKeyShareSuccinctTransportedProofBytes = Readonly<{
    readonly proofBytesEncoding: 'binary-chunked-proof-bytes';
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofChunkSizeBytes: number;
    readonly proofChunkCount: number;
    readonly proofTotalByteLength: number;
    readonly proofFullObjectHash: ProtocolHash;
    readonly proofChunkRoot: ProtocolHash;
    readonly proofChunkHashes: readonly ProtocolHash[];
}>;

export type PublicKeyShareSuccinctProofByteMaterial =
    | PublicKeyShareSuccinctEmbeddedProofBytes
    | PublicKeyShareSuccinctTransportedProofBytes;

export type PublicKeyShareSuccinctProofMaterial = Readonly<
    PublicKeyShareSuccinctProofByteMaterial & {
        readonly proofFamily: typeof publicKeyShareProofFamily;
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
            readonly objectVersion: 1;
            readonly proofFamily: typeof publicKeyShareProofFamily;
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly ringDegree: number;
            readonly publicKeyShareRoot: ProtocolHash;
            readonly publicKeyShareProofRoot: ProtocolHash;
            readonly publicKeyShareMaterialRoot: ProtocolHash;
            readonly sameSecretStatementRoot: ProtocolHash;
            readonly trusteeSecretCommitmentRoot: ProtocolHash;
            readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
            readonly sameSecretProofRoot: ProtocolHash;
            readonly statementHash: ProtocolHash;
            readonly proofBytesHash: ProtocolHash;
            readonly publicKeyShareSuccinctProofRoot: ProtocolHash;
        }
>;

export type PublicKeyShareSuccinctProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareSuccinctProofSet';
        readonly objectVersion: 1;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareProofSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        readonly proofRecords: readonly PublicKeyShareSuccinctProofRecord[];
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
    }
>;

export type CollectivePublicKeySourceShareMaterialRoot = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly publicKeyShareRoot: ProtocolHash;
    readonly publicKeyShareMaterialRoot: ProtocolHash;
}>;

export type CollectivePublicKeyCoefficientVectorMaterial = Readonly<
    JsonRecord & {
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly component: 'b';
        readonly coefficientByteLength: number;
        readonly coefficientVectorHash512: ProtocolHash;
        readonly coefficientsLeHex: string;
    }
>;

export type CollectivePublicKey = Readonly<
    JsonRecord & {
        readonly objectType: 'CollectivePublicKey';
        readonly objectVersion: 1;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly materialEncoding: 'embedded-full-collective-public-key-coefficients';
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareProofSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly sourceShareMaterialRoots: readonly CollectivePublicKeySourceShareMaterialRoot[];
        readonly aggregateCoefficientVectorsByLimb: readonly CollectivePublicKeyCoefficientVectorMaterial[];
        readonly collectivePublicKeyRoot: ProtocolHash;
    }
>;

export type CollectivePublicKeyInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly ringDegree: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly publicKeyCrpRoot: ProtocolHash;
    readonly publicAPolynomialRoot: ProtocolHash;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
    readonly publicKeyShareMaterial: PublicKeyShareMaterialSet;
    readonly publicKeyShareSuccinctProofs: PublicKeyShareSuccinctProofSet;
}>;

export type CollectivePublicKeySourceBindingInput = Omit<
    CollectivePublicKeyInput,
    'publicKeyShareMaterial'
> & {
    readonly publicKeyShareMaterial: SetupPackagePublicKeyShareMaterialSet;
};

export type TransportedCollectivePublicKeyInput = Omit<
    CollectivePublicKeyInput,
    'publicKeyShareMaterial'
> & {
    readonly publicKeyShareMaterial: BinaryChunkedPublicKeyShareMaterialSet;
    readonly transportedPublicKeyShareMaterial:
        | SetupTransportedPublicKeyShareMaterial
        | JsonRecord;
};

export type PublicKeyShareSetInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly publicKeyCrpRoot: ProtocolHash;
    readonly publicAPolynomialRoot: ProtocolHash;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly shareContributions: readonly PublicKeyShareContributionInput[];
};

export type PublicKeyShareProofSetInput = Omit<
    PublicKeyShareSetInput,
    'shareContributions'
> & {
    readonly publicKeyShares: PublicKeyShareSet;
};

export type PublicKeyShareMaterialSetInput = Omit<
    PublicKeyShareSetInput,
    'shareContributions' | 'sameSecretConsistency'
> & {
    readonly ringDegree: number;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly materialContributions: readonly PublicKeyShareMaterialContributionInput[];
};

export type PublicKeyShareSuccinctProofSetInput = Omit<
    PublicKeyShareProofSetInput,
    'sameSecretConsistency'
> & {
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
    readonly publicKeyShareMaterial: SetupPackagePublicKeyShareMaterialSet;
    readonly proofMaterials: readonly PublicKeyShareSuccinctProofMaterial[];
};

export type TransportedPublicKeyShareProofMaterialSet = Readonly<
    TransportedSetupProofMaterialSet & {
        readonly objectType: 'SetupTransportedPublicKeyShareProofMaterialSet';
        readonly proofFamily: typeof publicKeyShareProofFamily;
    }
>;

export type BinaryChunkedPublicKeyShareProofMaterialTransport = Readonly<{
    readonly proofMaterials: readonly PublicKeyShareSuccinctProofMaterial[];
    readonly transportedPublicKeyShareProofMaterial: TransportedPublicKeyShareProofMaterialSet;
}>;
