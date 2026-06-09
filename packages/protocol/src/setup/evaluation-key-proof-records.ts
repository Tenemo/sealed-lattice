import {
    canonicalJson,
    deriveProtocolHash,
    hash512Hex,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { BinaryChunkWriter } from './binary-chunk-writer.js';
import {
    type EvaluatorKeySchedule,
    type RelinearizationLevelScheduleEntry,
    type RequiredGaloisKeyScheduleEntry,
} from './evaluator-key-schedule.js';
import { setupProofProfileId } from './same-secret-consistency-records.js';
import {
    assertSetupProofChallenge,
    optionalSetupProofTboxZ34Metadata,
    setupProofTransportChunkSizeBytes,
    transportSetupProofMaterials,
    type SetupProofChallenge,
    type SetupProofTboxZ34Metadata,
    type TransportedSetupProofMaterialSet,
} from './setup-proof-material-transport.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;
type WideInteger = number | string;
type EvaluationKeyShareProofFamily =
    | 'relinearization-key-share'
    | 'galois-key-share';
type ProofRandomnessSource =
    | 'fresh-csprng'
    | 'development-deterministic-fixture';

export const relinearizationProofVerificationStatus =
    'lnp-relinearization-key-share-relation-verified-with-accepted-setup-proof-accounting';
export const relinearizationProofModelStatus =
    'pinned LNP tbox proof bytes with deterministic statement-and-relation-bound full-width tbox commitment-prefix residue generation, h zero-position enforcement, z34-bound lower-protocol challenge sampling, generated lower-protocol tbox suffix enforcement, setup-proof challenge domain, 63-bit scalar relation challenge, binary proof-material schema, same-secret-bound secret opening response with centered signed 80-bit committed-secret masks and responses, fixed-width signed big-integer key-switch relation commitments, deterministic key-switch sampler, public component-vector material, lifted key-switch algebra, round-one same-secret source response, generator-side round-two aggregate-source product validation, centered-binomial error support, carried no-wrap responses, fixed response bounds, root-bound relinearization source binding records, verifier-side round-two source-square aggregate roots, and repo-owned setup proof soundness, zero-knowledge, and QROM accounting accepted for claim-bearing relinearization proof acceptance';
export const galoisProofVerificationStatus =
    'lnp-galois-key-share-relation-verified-with-accepted-setup-proof-accounting';
export const galoisProofModelStatus =
    'pinned LNP tbox proof bytes with deterministic statement-and-relation-bound full-width tbox commitment-prefix residue generation, h zero-position enforcement, z34-bound lower-protocol challenge sampling, generated lower-protocol tbox suffix enforcement, setup-proof challenge domain, 63-bit scalar relation challenge, binary proof-material schema, same-secret-bound secret opening response with centered signed 80-bit committed-secret masks and responses, fixed-width signed big-integer key-switch relation commitments, deterministic key-switch sampler, public component-vector material, Galois automorphism source response, lifted key-switch algebra, centered-binomial error support, carried no-wrap responses, fixed response bounds, and repo-owned setup proof soundness, zero-knowledge, and QROM accounting accepted for claim-bearing Galois-key proof acceptance';
const publicEvaluationKeyAssemblyStatus =
    'assembled-from-proof-bearing-shares-and-accepted-key-correctness-certificate';
const publicEvaluationKeyMaterialEncoding =
    'root-bound-public-key-switch-component-roots';
const publicEvaluationKeyTransportMaterialEncoding =
    'binary-chunked-public-evaluation-key-root-manifest';
const publicEvaluationKeyMaterialSource =
    'verified-relinearization-and-galois-proof-records';
const publicEvaluationKeyMaterialTransportSetObjectType =
    'SetupTransportedPublicEvaluationKeyMaterialSet';
const publicEvaluationKeyMaterialTransportObjectType =
    'SetupTransportedPublicEvaluationKeyMaterial';
const evaluationKeyShareProofTransportSetObjectType =
    'SetupTransportedEvaluationKeyShareProofMaterialSet';
const evaluationKeyShareProofTransportObjectType =
    'SetupTransportedEvaluationKeyShareProofMaterial';
const evaluationKeyShareComponentMaterialTransportSetObjectType =
    'SetupTransportedEvaluationKeyShareComponentMaterialSet';
const evaluationKeyShareComponentMaterialTransportObjectType =
    'SetupTransportedEvaluationKeyShareComponentMaterial';
const evaluationKeyShareComponentMaterialEncoding =
    'binary-chunked-key-switch-component-vectors';
const evaluationKeyShareComponentVectorHashDomain =
    'sealed-lattice-bgv-rns/evaluation-key-share-component-vector-v1';
const evaluationKeyShareComponentMaterialFullObjectHashDomain =
    'sealed-lattice/setup/evaluation-key-share/component-material/full-object-v1';
const evaluationKeyShareComponentMaterialChunkHashDomain =
    'sealed-lattice/setup/evaluation-key-share/component-material/chunk-v1';
const relinearizationProofBytesHashDomain =
    'sealed-lattice/setup/relinearization-key-share/lnp-proof-bytes-v1';
const galoisProofBytesHashDomain =
    'sealed-lattice/setup/galois-key-share/lnp-proof-bytes-v1';
const evaluationKeyShareComponentMaterialMagic = new Uint8Array([
    0x53, 0x4c, 0x45, 0x4b, 0x43, 0x4d, 0x56, 0x31,
]);
const publicEvaluationKeyMaterialMagic = new Uint8Array([
    0x53, 0x4c, 0x45, 0x4b, 0x50, 0x4d, 0x56, 0x31,
]);
const textEncoder = new TextEncoder();

export type SameSecretProofReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly sameSecretStatementRoot: ProtocolHash;
    readonly trusteeSecretCommitmentRoot: ProtocolHash;
    readonly sameSecretProofRoot: ProtocolHash;
}>;

export type KeySwitchComponentVectorEntry = Readonly<JsonRecord>;

export type EvaluationKeyShareEmbeddedProofBytes = Readonly<{
    readonly proofBytesHex: string;
}>;

export type EvaluationKeyShareTransportedProofBytes = Readonly<{
    readonly proofBytesEncoding: 'binary-chunked-proof-bytes';
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofChunkSizeBytes: number;
    readonly proofChunkCount: number;
    readonly proofTotalByteLength: number;
    readonly proofFullObjectHash: ProtocolHash;
    readonly proofChunkRoot: ProtocolHash;
    readonly proofChunkHashes: readonly ProtocolHash[];
}>;

export type EvaluationKeyShareProofByteMaterial =
    | EvaluationKeyShareEmbeddedProofBytes
    | EvaluationKeyShareTransportedProofBytes;

export type EvaluationKeyShareEmbeddedKeySwitchComponentMaterial = Readonly<{
    readonly keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors';
    readonly keySwitchComponentVectors: readonly KeySwitchComponentVectorEntry[];
}>;

export type EvaluationKeyShareTransportedKeySwitchComponentMaterial = Readonly<{
    readonly keySwitchMaterialEncoding: 'binary-chunked-key-switch-component-vectors';
    readonly keySwitchComponentMaterialRoot: ProtocolHash;
    readonly keySwitchComponentChunkSizeBytes: number;
    readonly keySwitchComponentChunkCount: number;
    readonly keySwitchComponentTotalByteLength: number;
    readonly keySwitchComponentFullObjectHash: ProtocolHash;
    readonly keySwitchComponentChunkRoot: ProtocolHash;
    readonly keySwitchComponentChunkHashes: readonly ProtocolHash[];
}>;

export type EvaluationKeyShareKeySwitchComponentMaterial =
    | EvaluationKeyShareEmbeddedKeySwitchComponentMaterial
    | EvaluationKeyShareTransportedKeySwitchComponentMaterial;

export type EvaluationKeyShareProofGenerationBase = Readonly<{
    readonly setupProofBinding: JsonRecord;
    readonly keySwitchDomain: string;
    readonly keySwitchSeedHex: string;
    readonly ringDegree: number;
    readonly keySwitchComponentVectorRoot: ProtocolHash;
    readonly constantCommitments: readonly JsonRecord[];
    readonly secretCoefficients: readonly number[];
    readonly openingRandomnessByLimb: readonly (readonly (readonly WideInteger[])[])[];
    readonly errorCoefficientsByDigit: readonly (readonly number[])[];
    readonly transportedKeySwitchComponentMaterial?: JsonRecord;
    readonly proofRandomnessSource?: ProofRandomnessSource;
    readonly proofRandomnessSeedHex: string;
}> &
    EvaluationKeyShareKeySwitchComponentMaterial;

export type RelinearizationKeyShareProofGeneration =
    EvaluationKeyShareProofGenerationBase &
        Readonly<{
            readonly proofProfileId: 'sealed-lattice-relinearization-key-share-proof-lnp-v1';
            readonly relinearizationKeyShareTboxParameterProfileHash: ProtocolHash;
            readonly relinearizationSourceCoefficientsByDigit: readonly (readonly WideInteger[])[];
            readonly roundOneAggregateSourceCoefficientsByDigit?: readonly (readonly WideInteger[])[];
        }>;

export type GaloisKeyShareProofGeneration =
    EvaluationKeyShareProofGenerationBase &
        Readonly<{
            readonly proofProfileId: 'sealed-lattice-galois-key-share-proof-lnp-v1';
            readonly galoisKeyShareTboxParameterProfileHash: ProtocolHash;
        }>;

export type EvaluationKeyShareProofGenerationOutput = Readonly<{
    readonly ok: true;
    readonly operation: 'generateEvaluationKeyShareLnpProof';
    readonly setupProofProfileId: string;
    readonly proofFamily: 'relinearization-key-share' | 'galois-key-share';
    readonly proofVerificationStatus: string;
    readonly proofModelStatus: string;
    readonly statementHash: ProtocolHash;
    readonly relationCommitmentHash: ProtocolHash;
    readonly tboxCommitmentPrefixHash: ProtocolHash;
    readonly challenge: SetupProofChallenge;
    readonly proofSizeBytes: number;
    readonly proofBytesHash: ProtocolHash;
    readonly proofBytesHex: string;
    readonly relinearizationKeyShareTboxParameterProfileHash?: ProtocolHash;
    readonly galoisKeyShareTboxParameterProfileHash?: ProtocolHash;
    readonly proofRandomness: Readonly<{
        readonly source: ProofRandomnessSource;
        readonly seedBytes: 64;
        readonly retention: string;
    }>;
}> &
    SetupProofTboxZ34Metadata;

export type EvaluationKeyShareProofGenerator = (
    input: Readonly<{
        readonly proofFamily: 'relinearization-key-share' | 'galois-key-share';
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly proofRecord: JsonRecord;
        readonly sameSecretStatementRecord: JsonRecord;
        readonly constantCommitments: readonly JsonRecord[];
        readonly setupProofBinding: JsonRecord;
        readonly transportedKeySwitchComponentMaterial?: JsonRecord;
        readonly secretCoefficients: readonly number[];
        readonly openingRandomnessByLimb: readonly (readonly (readonly WideInteger[])[])[];
        readonly errorCoefficientsByDigit: readonly (readonly number[])[];
        readonly relinearizationSourceCoefficientsByDigit?: readonly (readonly WideInteger[])[];
        readonly roundOneAggregateSourceCoefficientsByDigit?: readonly (readonly WideInteger[])[];
        readonly proofRandomnessSource?: ProofRandomnessSource;
        readonly proofRandomnessSeedHex: string;
    }>,
) => EvaluationKeyShareProofGenerationOutput;

export type EvaluationKeyShareProofMaterialBase = Readonly<{
    readonly setupProofBinding: JsonRecord;
    readonly keySwitchDomain: string;
    readonly keySwitchSeedHex: string;
    readonly ringDegree: number;
    readonly keySwitchComponentVectorRoot: ProtocolHash;
    readonly statementHash: ProtocolHash;
    readonly relationCommitmentHash: ProtocolHash;
    readonly tboxCommitmentPrefixHash: ProtocolHash;
    readonly challenge: SetupProofChallenge;
    readonly proofSizeBytes: number;
    readonly proofBytesHash: ProtocolHash;
}> &
    EvaluationKeyShareKeySwitchComponentMaterial &
    Partial<SetupProofTboxZ34Metadata> &
    EvaluationKeyShareProofByteMaterial;

export type RelinearizationKeyShareProofMaterial =
    EvaluationKeyShareProofMaterialBase &
        Readonly<{
            readonly proofProfileId: 'sealed-lattice-relinearization-key-share-proof-lnp-v1';
            readonly relinearizationKeyShareTboxParameterProfileHash: ProtocolHash;
        }>;

export type GaloisKeyShareProofMaterial = EvaluationKeyShareProofMaterialBase &
    Readonly<{
        readonly proofProfileId: 'sealed-lattice-galois-key-share-proof-lnp-v1';
        readonly galoisKeyShareTboxParameterProfileHash: ProtocolHash;
    }>;

export type RelinearizationRoundOneContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly roundOneShareRoot: ProtocolHash;
    readonly proofMaterial?: RelinearizationKeyShareProofMaterial;
    readonly proofGeneration?: RelinearizationKeyShareProofGeneration;
}>;

export type RelinearizationRoundTwoContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly roundTwoShareRoot: ProtocolHash;
    readonly proofMaterial?: RelinearizationKeyShareProofMaterial;
    readonly proofGeneration?: RelinearizationKeyShareProofGeneration;
}>;

export type RelinearizationKeyShareRoundOneRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'RelinearizationKeyShareRoundOne';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'relinearization-key-share';
        readonly proofVerificationStatus: typeof relinearizationProofVerificationStatus;
        readonly proofModelStatus: typeof relinearizationProofModelStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly level: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly roundOneShareRoot: ProtocolHash;
        readonly sourceSquareBindingRoot: ProtocolHash;
        readonly proofProfileId: 'sealed-lattice-relinearization-key-share-proof-lnp-v1';
        readonly setupProofBinding: JsonRecord;
        readonly keySwitchDomain: string;
        readonly keySwitchSeedHex: string;
        readonly ringDegree: number;
        readonly keySwitchComponentVectorRoot: ProtocolHash;
        readonly relinearizationKeyShareTboxParameterProfileHash: ProtocolHash;
        readonly statementHash: ProtocolHash;
        readonly relationCommitmentHash: ProtocolHash;
        readonly tboxCommitmentPrefixHash: ProtocolHash;
        readonly challenge: SetupProofChallenge;
        readonly proofSizeBytes: number;
        readonly proofBytesHash: ProtocolHash;
        readonly roundOneProofRoot: ProtocolHash;
        readonly roundOneRecordRoot: ProtocolHash;
    } & EvaluationKeyShareKeySwitchComponentMaterial &
        Partial<SetupProofTboxZ34Metadata> &
        EvaluationKeyShareProofByteMaterial
>;

export type RelinearizationKeyShareRoundTwoRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'RelinearizationKeyShareRoundTwo';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'relinearization-key-share';
        readonly proofVerificationStatus: typeof relinearizationProofVerificationStatus;
        readonly proofModelStatus: typeof relinearizationProofModelStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly level: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly roundOneShareRoot: ProtocolHash;
        readonly roundOneRecordRoot: ProtocolHash;
        readonly roundOneAggregateRoot: ProtocolHash;
        readonly roundOneSourceSquareBindingRoot: ProtocolHash;
        readonly roundOneSourceSquareAggregateRoot: ProtocolHash;
        readonly roundTwoShareRoot: ProtocolHash;
        readonly sourceSquareBindingRoot: ProtocolHash;
        readonly proofProfileId: 'sealed-lattice-relinearization-key-share-proof-lnp-v1';
        readonly setupProofBinding: JsonRecord;
        readonly keySwitchDomain: string;
        readonly keySwitchSeedHex: string;
        readonly ringDegree: number;
        readonly keySwitchComponentVectorRoot: ProtocolHash;
        readonly relinearizationKeyShareTboxParameterProfileHash: ProtocolHash;
        readonly statementHash: ProtocolHash;
        readonly relationCommitmentHash: ProtocolHash;
        readonly tboxCommitmentPrefixHash: ProtocolHash;
        readonly challenge: SetupProofChallenge;
        readonly proofSizeBytes: number;
        readonly proofBytesHash: ProtocolHash;
        readonly roundTwoProofRoot: ProtocolHash;
        readonly roundTwoRecordRoot: ProtocolHash;
    } & EvaluationKeyShareKeySwitchComponentMaterial &
        Partial<SetupProofTboxZ34Metadata> &
        EvaluationKeyShareProofByteMaterial
>;

export type RelinearizationKeyShareRounds = Readonly<
    JsonRecord & {
        readonly objectType: 'RelinearizationKeyShareRounds';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'relinearization-key-share';
        readonly proofVerificationStatus: typeof relinearizationProofVerificationStatus;
        readonly proofModelStatus: typeof relinearizationProofModelStatus;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly relinearizationLevelSchedule: readonly RelinearizationLevelScheduleEntry[];
        readonly roundOneAggregateRoots: readonly {
            readonly level: number;
            readonly roundOneAggregateRoot: ProtocolHash;
            readonly roundOneSourceSquareAggregateRoot: ProtocolHash;
        }[];
        readonly roundOneRecords: readonly RelinearizationKeyShareRoundOneRecord[];
        readonly roundTwoAggregateRoots: readonly {
            readonly level: number;
            readonly roundTwoAggregateRoot: ProtocolHash;
            readonly roundTwoSourceSquareAggregateRoot: ProtocolHash;
        }[];
        readonly roundTwoRecords: readonly RelinearizationKeyShareRoundTwoRecord[];
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
    }
>;

export type GaloisKeyShareRootReference = Readonly<{
    readonly rotation: number;
    readonly level: number;
    readonly galoisKeyShareRoot: ProtocolHash;
}>;

export type GaloisKeyShareProofContribution = GaloisKeyShareRootReference &
    Readonly<{
        readonly proofMaterial?: GaloisKeyShareProofMaterial;
        readonly proofGeneration?: GaloisKeyShareProofGeneration;
    }>;

export type GaloisKeyShareBatchContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly galoisKeyShareProofs: readonly GaloisKeyShareProofContribution[];
}>;

export type GaloisKeyShareProof = Readonly<
    JsonRecord & {
        readonly objectType: 'GaloisKeyShareProof';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'galois-key-share';
        readonly proofVerificationStatus: typeof galoisProofVerificationStatus;
        readonly proofModelStatus: typeof galoisProofModelStatus;
        readonly proofProfileId: 'sealed-lattice-galois-key-share-proof-lnp-v1';
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly galoisKeyCrpRoot: ProtocolHash;
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly rotation: number;
        readonly level: number;
        readonly galoisKeyShareRoot: ProtocolHash;
        readonly setupProofBinding: JsonRecord;
        readonly keySwitchDomain: string;
        readonly keySwitchSeedHex: string;
        readonly ringDegree: number;
        readonly keySwitchComponentVectorRoot: ProtocolHash;
        readonly galoisKeyShareTboxParameterProfileHash: ProtocolHash;
        readonly statementHash: ProtocolHash;
        readonly relationCommitmentHash: ProtocolHash;
        readonly tboxCommitmentPrefixHash: ProtocolHash;
        readonly challenge: SetupProofChallenge;
        readonly proofSizeBytes: number;
        readonly proofBytesHash: ProtocolHash;
        readonly galoisKeyShareProofRoot: ProtocolHash;
    } & EvaluationKeyShareKeySwitchComponentMaterial &
        Partial<SetupProofTboxZ34Metadata> &
        EvaluationKeyShareProofByteMaterial
>;

export type GaloisKeyShareBatch = Readonly<
    JsonRecord & {
        readonly objectType: 'GaloisKeyShareBatch';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'galois-key-share';
        readonly proofVerificationStatus: typeof galoisProofVerificationStatus;
        readonly proofModelStatus: typeof galoisProofModelStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly galoisKeyCrpRoot: ProtocolHash;
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
        readonly galoisKeyShareRoots: readonly GaloisKeyShareRootReference[];
        readonly galoisKeyShareProofs: readonly GaloisKeyShareProof[];
        readonly galoisKeyBatchProofRoot: ProtocolHash;
        readonly galoisKeyShareBatchRoot: ProtocolHash;
    }
>;

export type RelinearizationKeyRootReference = Readonly<{
    readonly level: number;
    readonly decompositionDigitCount: number;
    readonly rnsLimbCount: number;
    readonly roundOneAggregateRoot: ProtocolHash;
    readonly roundOneSourceSquareAggregateRoot: ProtocolHash;
    readonly roundTwoAggregateRoot: ProtocolHash;
    readonly roundTwoSourceSquareAggregateRoot: ProtocolHash;
    readonly relinearizationKeyRoot: ProtocolHash;
}>;

export type GaloisKeyShareBatchRootReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly galoisKeyShareBatchRoot: ProtocolHash;
}>;

export type GaloisKeyContributingShareRoot = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly galoisKeyShareRoot: ProtocolHash;
    readonly galoisKeyShareProofRoot: ProtocolHash;
}>;

export type GaloisKeyRootReference = Readonly<{
    readonly rotation: number;
    readonly level: number;
    readonly decompositionDigitCount: number;
    readonly rnsLimbCount: number;
    readonly galoisKeyRoot: ProtocolHash;
    readonly contributingShareRoots: readonly GaloisKeyContributingShareRoot[];
}>;

export type PublicEvaluationKeySet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicEvaluationKeySet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly assemblyStatus: typeof publicEvaluationKeyAssemblyStatus;
        readonly materialEncoding: typeof publicEvaluationKeyMaterialEncoding;
        readonly materialSource: typeof publicEvaluationKeyMaterialSource;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
        readonly relinearizationLevelSchedule: readonly RelinearizationLevelScheduleEntry[];
        readonly relinearizationKeyRoots: readonly RelinearizationKeyRootReference[];
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
        readonly galoisKeyShareBatchRoots: readonly GaloisKeyShareBatchRootReference[];
        readonly galoisKeyRoots: readonly GaloisKeyRootReference[];
        readonly genericKeySwitchKeyRoots: readonly ProtocolHash[];
        readonly rawKeyBytesEmbedded: false;
        readonly verifierGeneratedKeyMaterial: false;
        readonly publicEvaluationKeyMaterialEncoding?: typeof publicEvaluationKeyTransportMaterialEncoding;
        readonly publicEvaluationKeyMaterialRoot?: ProtocolHash;
        readonly publicEvaluationKeyMaterialChunkSizeBytes?: number;
        readonly publicEvaluationKeyMaterialChunkCount?: number;
        readonly publicEvaluationKeyMaterialTotalByteLength?: number;
        readonly publicEvaluationKeyMaterialFullObjectHash?: ProtocolHash;
        readonly publicEvaluationKeyMaterialChunkRoot?: ProtocolHash;
        readonly publicEvaluationKeyMaterialChunkHashes?: readonly ProtocolHash[];
        readonly evaluationKeySetHash: ProtocolHash;
    }
>;

export type PublicEvaluationKeyMaterialReference = Readonly<{
    readonly publicEvaluationKeyMaterialEncoding: typeof publicEvaluationKeyTransportMaterialEncoding;
    readonly publicEvaluationKeyMaterialRoot: ProtocolHash;
    readonly publicEvaluationKeyMaterialChunkSizeBytes: number;
    readonly publicEvaluationKeyMaterialChunkCount: number;
    readonly publicEvaluationKeyMaterialTotalByteLength: number;
    readonly publicEvaluationKeyMaterialFullObjectHash: ProtocolHash;
    readonly publicEvaluationKeyMaterialChunkRoot: ProtocolHash;
    readonly publicEvaluationKeyMaterialChunkHashes: readonly ProtocolHash[];
}>;

export type TransportedEvaluationKeyShareProofMaterialSet =
    TransportedSetupProofMaterialSet<
        typeof evaluationKeyShareProofTransportSetObjectType
    >;

export type TransportedEvaluationKeyShareComponentMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof evaluationKeyShareComponentMaterialTransportSetObjectType;
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly componentMaterials: readonly JsonRecord[];
    }
>;

export type TransportedPublicEvaluationKeyMaterial = Readonly<
    JsonRecord & {
        readonly objectType: typeof publicEvaluationKeyMaterialTransportObjectType;
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly materialEncoding: typeof publicEvaluationKeyTransportMaterialEncoding;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly evaluationKeySetHash: ProtocolHash;
        readonly publicEvaluationKeyMaterialRoot: ProtocolHash;
        readonly chunkSizeBytes: number;
        readonly chunkCount: number;
        readonly totalByteLength: number;
        readonly fullObjectHash: ProtocolHash;
        readonly chunkRoot: ProtocolHash;
        readonly chunkHashes: readonly ProtocolHash[];
        readonly chunks: readonly {
            readonly chunkIndex: number;
            readonly bytesHex: string;
        }[];
    }
>;

export type TransportedPublicEvaluationKeyMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof publicEvaluationKeyMaterialTransportSetObjectType;
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly materialEncoding: typeof publicEvaluationKeyTransportMaterialEncoding;
        readonly publicEvaluationKeyMaterials: readonly TransportedPublicEvaluationKeyMaterial[];
        readonly componentMaterials?: readonly JsonRecord[];
    }
>;

export type BinaryChunkedPublicEvaluationKeyMaterialTransport = Readonly<{
    readonly evaluationKeys: PublicEvaluationKeySet;
    readonly publicEvaluationKeyMaterialReference: PublicEvaluationKeyMaterialReference;
    readonly transportedPublicEvaluationKeyMaterial: TransportedPublicEvaluationKeyMaterialSet;
}>;

export type BinaryChunkedEvaluationKeyShareMaterialTransport = Readonly<{
    readonly relinearizationRoundOneContributions: readonly RelinearizationRoundOneContribution[];
    readonly relinearizationRoundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    readonly galoisKeyShareBatchContributions: readonly GaloisKeyShareBatchContribution[];
    readonly transportedEvaluationKeyShareProofMaterial: TransportedEvaluationKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareComponentMaterial: TransportedEvaluationKeyShareComponentMaterialSet;
}>;

export type EvaluationKeyShareMaterialTransportInput = Readonly<{
    readonly sameSecretProofReferences: readonly Pick<
        SameSecretProofReference,
        'trusteeIdentity' | 'trusteeRosterPosition'
    >[];
    readonly relinearizationRoundOneContributions: readonly RelinearizationRoundOneContribution[];
    readonly relinearizationRoundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    readonly galoisKeyShareBatchContributions: readonly GaloisKeyShareBatchContribution[];
}>;

export type EvaluationKeyProofCommonInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly evaluatorKeySchedule: EvaluatorKeySchedule;
    readonly sameSecretProofSetRoot: ProtocolHash;
    readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
    readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
    readonly sameSecretProofReferences: readonly SameSecretProofReference[];
    readonly evaluationKeyShareProofGenerator?: EvaluationKeyShareProofGenerator;
}>;

export type RelinearizationKeyShareRoundsInput = EvaluationKeyProofCommonInput &
    Readonly<{
        readonly roundOneContributions: readonly RelinearizationRoundOneContribution[];
        readonly roundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    }>;

export type GaloisKeyShareBatchesInput = EvaluationKeyProofCommonInput &
    Readonly<{
        readonly batchContributions: readonly GaloisKeyShareBatchContribution[];
    }>;

export type PublicEvaluationKeySetInput = EvaluationKeyProofCommonInput &
    Readonly<{
        readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
        readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
        readonly publicEvaluationKeyMaterialReference?: PublicEvaluationKeyMaterialReference;
    }>;

export type PublicEvaluationKeyMaterialTransportInput = Omit<
    PublicEvaluationKeySetInput,
    'publicEvaluationKeyMaterialReference'
> &
    Readonly<{
        readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
    }>;

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const lowercaseHexPattern = /^[0-9a-f]+$/u;
const setupContextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertPositiveSafeInteger = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const assertLowercaseHex = (value: string, fieldName: string): void => {
    if (!lowercaseHexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be lowercase hex.`);
    }
};

const jsonRecordValue = (value: unknown, fieldName: string): JsonRecord => {
    if (value === null || Array.isArray(value) || typeof value !== 'object') {
        throw new TypeError(`${fieldName} must be a JSON object.`);
    }

    return value as JsonRecord;
};

const stringRecordField = (
    record: JsonRecord,
    fieldName: string,
    objectPath: string,
): string => {
    const value = record[fieldName];
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${objectPath}.${fieldName} must be non-empty.`);
    }

    return value;
};

const nonNegativeIntegerRecordField = (
    record: JsonRecord,
    fieldName: string,
    objectPath: string,
): number => {
    const value = record[fieldName];
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a non-negative safe integer.`,
        );
    }

    return value;
};

const bytesFromHex = (hex: string, fieldName: string): Uint8Array => {
    if (!/^(?:[0-9a-f]{2})*$/u.test(hex)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return bytes;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const appendVaruint = (outputBytes: number[], value: number): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            'binary varuint value must be a non-negative safe integer.',
        );
    }
    let remainingValue = value;
    do {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        outputBytes.push(byte);
    } while (remainingValue !== 0);
};

const varUintBytes = (value: number): Uint8Array => {
    const outputBytes: number[] = [];
    appendVaruint(outputBytes, value);

    return Uint8Array.from(outputBytes);
};

const coefficientVectorFromLittleEndianHex = (
    coefficientsLeHex: string,
    expectedCoefficientCount: number,
    fieldName: string,
): readonly number[] => {
    const coefficientBytes = bytesFromHex(coefficientsLeHex, fieldName);
    if (coefficientBytes.byteLength !== expectedCoefficientCount * 8) {
        throw new Error(`${fieldName} byte length must match ringDegree.`);
    }

    return Array.from(
        { length: expectedCoefficientCount },
        (_unused, coefficientIndex) => {
            let coefficient = 0n;
            for (let byteOffset = 7; byteOffset >= 0; byteOffset -= 1) {
                coefficient <<= 8n;
                coefficient |= BigInt(
                    coefficientBytes[coefficientIndex * 8 + byteOffset] ?? 0,
                );
            }
            if (coefficient > BigInt(Number.MAX_SAFE_INTEGER)) {
                throw new Error(
                    `${fieldName} contains a coefficient outside the JavaScript safe integer range.`,
                );
            }

            return Number(coefficient);
        },
    );
};

const coefficientVectorBytes = (
    coefficients: readonly number[],
): Uint8Array => {
    const bytes = new Uint8Array(coefficients.length * 8);
    coefficients.forEach((coefficient, coefficientIndex) => {
        if (!Number.isSafeInteger(coefficient) || coefficient < 0) {
            throw new TypeError(
                'evaluation-key component coefficient must be a non-negative safe integer.',
            );
        }
        let remainingValue = BigInt(coefficient);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[coefficientIndex * 8 + byteIndex] = Number(
                remainingValue & 0xffn,
            );
            remainingValue >>= 8n;
        }
    });

    return bytes;
};

const evaluationKeyShareComponentVectorHash = (
    coefficients: readonly number[],
): ProtocolHash =>
    hash512Hex(evaluationKeyShareComponentVectorHashDomain, [
        coefficientVectorBytes(coefficients),
    ]);

const u64LittleEndianBytes = (value: number, fieldName: string): Uint8Array => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);

    return bytes;
};

const evaluationKeyShareComponentVectorRoot = (
    proofFamily: EvaluationKeyShareProofFamily,
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    level: number,
    ringDegree: number,
    componentVectors: readonly JsonRecord[],
): ProtocolHash =>
    deriveProtocolHash('EvaluationKeyShareComponentVectorRoot', {
        objectType: 'EvaluationKeyShareComponentVectorSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily,
        keySwitchDomain,
        keySwitchSeedHex,
        level,
        ringDegree,
        digitCount: level + 1,
        rnsLimbCount: level + 1,
        componentVectors,
    });

const evaluationKeyShareComponentMaterialFullObjectHash = (
    proofFamily: EvaluationKeyShareProofFamily,
    totalByteLength: number,
    chunks: readonly Uint8Array[],
): ProtocolHash =>
    hash512Hex(evaluationKeyShareComponentMaterialFullObjectHashDomain, [
        textEncoder.encode(proofFamily),
        varUintBytes(totalByteLength),
        ...chunks,
    ]);

const evaluationKeyShareComponentMaterialChunkHash = (
    proofFamily: EvaluationKeyShareProofFamily,
    fullObjectHash: ProtocolHash,
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash =>
    hash512Hex(evaluationKeyShareComponentMaterialChunkHashDomain, [
        textEncoder.encode(proofFamily),
        textEncoder.encode(fullObjectHash),
        varUintBytes(chunkIndex),
        chunk,
    ]);

const evaluationKeyShareComponentMaterialTransportHashes = (
    proofFamily: EvaluationKeyShareProofFamily,
    chunks: readonly Uint8Array[],
): Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly chunkRoot: ProtocolHash;
    readonly totalByteLength: number;
}> => {
    const totalByteLength = chunks.reduce(
        (byteLength, chunk) => byteLength + chunk.byteLength,
        0,
    );
    const fullObjectHash = evaluationKeyShareComponentMaterialFullObjectHash(
        proofFamily,
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        evaluationKeyShareComponentMaterialChunkHash(
            proofFamily,
            fullObjectHash,
            chunkIndex,
            chunk,
        ),
    );
    const chunkRoot = deriveProtocolHash(
        'EvaluationKeyShareComponentMaterialChunkRoot',
        {
            objectType: 'EvaluationKeyShareComponentMaterialChunkManifest',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily,
            keySwitchMaterialEncoding:
                evaluationKeyShareComponentMaterialEncoding,
            chunkSizeBytes: setupProofTransportChunkSizeBytes,
            chunkCount: chunkHashes.length,
            totalByteLength,
            chunkHashes,
            fullObjectHash,
        },
    );

    return {
        fullObjectHash,
        chunkHashes,
        chunkRoot,
        totalByteLength,
    };
};

const evaluationKeyShareComponentMaterialReferenceRoot = (
    proofFamily: EvaluationKeyShareProofFamily,
    proofMaterial: EvaluationKeyShareProofMaterialBase,
    trusteeIdentity: string,
    trusteeRosterPosition: number,
    level: number,
    transportHashes: ReturnType<
        typeof evaluationKeyShareComponentMaterialTransportHashes
    >,
): ProtocolHash =>
    deriveProtocolHash('EvaluationKeyShareComponentMaterialRoot', {
        objectType: 'EvaluationKeyShareComponentMaterialReference',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily,
        keySwitchMaterialEncoding: evaluationKeyShareComponentMaterialEncoding,
        trusteeIdentity,
        trusteeRosterPosition,
        keySwitchDomain: proofMaterial.keySwitchDomain,
        keySwitchSeedHex: proofMaterial.keySwitchSeedHex,
        level,
        ringDegree: proofMaterial.ringDegree,
        digitCount: level + 1,
        rnsLimbCount: level + 1,
        keySwitchComponentVectorRoot:
            proofMaterial.keySwitchComponentVectorRoot,
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        chunkCount: transportHashes.chunkHashes.length,
        totalByteLength: transportHashes.totalByteLength,
        fullObjectHash: transportHashes.fullObjectHash,
        chunkRoot: transportHashes.chunkRoot,
        chunkHashes: transportHashes.chunkHashes,
    });

const assertJsonRecord = (value: JsonRecord, fieldName: string): void => {
    if (value === null || Array.isArray(value) || typeof value !== 'object') {
        throw new TypeError(`${fieldName} must be a JSON object.`);
    }
};

const assertProofByteMaterial = (
    proofMaterial: EvaluationKeyShareProofMaterialBase,
    fieldName: string,
): void => {
    if ('proofBytesHex' in proofMaterial) {
        assertNonEmptyString(
            proofMaterial.proofBytesHex,
            `${fieldName}.proofBytesHex`,
        );
        assertLowercaseHex(
            proofMaterial.proofBytesHex,
            `${fieldName}.proofBytesHex`,
        );
        return;
    }
    if (proofMaterial.proofBytesEncoding !== 'binary-chunked-proof-bytes') {
        throw new TypeError(
            `${fieldName}.proofBytesEncoding must be binary-chunked-proof-bytes.`,
        );
    }
    for (const [hashFieldName, hashValue] of [
        ['proofMaterialRoot', proofMaterial.proofMaterialRoot],
        ['proofFullObjectHash', proofMaterial.proofFullObjectHash],
        ['proofChunkRoot', proofMaterial.proofChunkRoot],
    ] as const) {
        assertProtocolHash(hashValue, `${fieldName}.${hashFieldName}`);
    }
    assertPositiveSafeInteger(
        proofMaterial.proofChunkSizeBytes,
        `${fieldName}.proofChunkSizeBytes`,
    );
    assertPositiveSafeInteger(
        proofMaterial.proofChunkCount,
        `${fieldName}.proofChunkCount`,
    );
    assertPositiveSafeInteger(
        proofMaterial.proofTotalByteLength,
        `${fieldName}.proofTotalByteLength`,
    );
    if (
        proofMaterial.proofChunkHashes.length !== proofMaterial.proofChunkCount
    ) {
        throw new Error(
            `${fieldName}.proofChunkHashes must match proofChunkCount.`,
        );
    }
    proofMaterial.proofChunkHashes.forEach((proofChunkHash, chunkIndex) => {
        assertProtocolHash(
            proofChunkHash,
            `${fieldName}.proofChunkHashes.${String(chunkIndex)}`,
        );
    });
};

const assertEvaluationKeyShareProofMaterial = (
    proofMaterial: EvaluationKeyShareProofMaterialBase,
    expectedComponentVectorRoot: ProtocolHash,
    fieldName: string,
): void => {
    assertJsonRecord(
        proofMaterial.setupProofBinding,
        `${fieldName}.setupProofBinding`,
    );
    if (
        proofMaterial.keySwitchMaterialEncoding ===
        'embedded-full-key-switch-component-vectors'
    ) {
        if (proofMaterial.keySwitchComponentVectors.length === 0) {
            throw new Error(
                `${fieldName}.keySwitchComponentVectors must be non-empty.`,
            );
        }
        proofMaterial.keySwitchComponentVectors.forEach(
            (componentVector, vectorIndex) => {
                assertJsonRecord(
                    componentVector,
                    `${fieldName}.keySwitchComponentVectors.${String(vectorIndex)}`,
                );
            },
        );
    } else if (
        proofMaterial.keySwitchMaterialEncoding ===
        'binary-chunked-key-switch-component-vectors'
    ) {
        for (const [hashFieldName, hashValue] of [
            [
                'keySwitchComponentMaterialRoot',
                proofMaterial.keySwitchComponentMaterialRoot,
            ],
            [
                'keySwitchComponentFullObjectHash',
                proofMaterial.keySwitchComponentFullObjectHash,
            ],
            [
                'keySwitchComponentChunkRoot',
                proofMaterial.keySwitchComponentChunkRoot,
            ],
        ] as const) {
            assertProtocolHash(hashValue, `${fieldName}.${hashFieldName}`);
        }
        assertPositiveSafeInteger(
            proofMaterial.keySwitchComponentChunkSizeBytes,
            `${fieldName}.keySwitchComponentChunkSizeBytes`,
        );
        assertPositiveSafeInteger(
            proofMaterial.keySwitchComponentChunkCount,
            `${fieldName}.keySwitchComponentChunkCount`,
        );
        assertPositiveSafeInteger(
            proofMaterial.keySwitchComponentTotalByteLength,
            `${fieldName}.keySwitchComponentTotalByteLength`,
        );
        if (
            proofMaterial.keySwitchComponentChunkHashes.length !==
            proofMaterial.keySwitchComponentChunkCount
        ) {
            throw new Error(
                `${fieldName}.keySwitchComponentChunkHashes must match keySwitchComponentChunkCount.`,
            );
        }
        proofMaterial.keySwitchComponentChunkHashes.forEach(
            (chunkHash, chunkIndex) => {
                assertProtocolHash(
                    chunkHash,
                    `${fieldName}.keySwitchComponentChunkHashes.${String(chunkIndex)}`,
                );
            },
        );
    } else {
        throw new TypeError(
            `${fieldName}.keySwitchMaterialEncoding must be embedded-full-key-switch-component-vectors or binary-chunked-key-switch-component-vectors.`,
        );
    }
    assertNonEmptyString(
        proofMaterial.keySwitchDomain,
        `${fieldName}.keySwitchDomain`,
    );
    assertNonEmptyString(
        proofMaterial.keySwitchSeedHex,
        `${fieldName}.keySwitchSeedHex`,
    );
    assertLowercaseHex(
        proofMaterial.keySwitchSeedHex,
        `${fieldName}.keySwitchSeedHex`,
    );
    assertPositiveSafeInteger(
        proofMaterial.ringDegree,
        `${fieldName}.ringDegree`,
    );
    assertProtocolHash(
        proofMaterial.keySwitchComponentVectorRoot,
        `${fieldName}.keySwitchComponentVectorRoot`,
    );
    if (
        proofMaterial.keySwitchComponentVectorRoot !==
        expectedComponentVectorRoot
    ) {
        throw new Error(
            `${fieldName}.keySwitchComponentVectorRoot must match the share root.`,
        );
    }
    for (const [hashFieldName, hashValue] of [
        ['statementHash', proofMaterial.statementHash],
        ['relationCommitmentHash', proofMaterial.relationCommitmentHash],
        ['tboxCommitmentPrefixHash', proofMaterial.tboxCommitmentPrefixHash],
        ['proofBytesHash', proofMaterial.proofBytesHash],
    ] as const) {
        assertProtocolHash(hashValue, `${fieldName}.${hashFieldName}`);
    }
    assertSetupProofChallenge(
        proofMaterial.challenge,
        `${fieldName}.challenge`,
    );
    optionalSetupProofTboxZ34Metadata(proofMaterial, fieldName);
    assertPositiveSafeInteger(
        proofMaterial.proofSizeBytes,
        `${fieldName}.proofSizeBytes`,
    );
    assertProofByteMaterial(proofMaterial, fieldName);
};

const assertRelinearizationProofMaterial = (
    proofMaterial: RelinearizationKeyShareProofMaterial,
    expectedComponentVectorRoot: ProtocolHash,
    fieldName: string,
): void => {
    if (
        proofMaterial.proofProfileId !==
        'sealed-lattice-relinearization-key-share-proof-lnp-v1'
    ) {
        throw new TypeError(
            `${fieldName}.proofProfileId must be sealed-lattice-relinearization-key-share-proof-lnp-v1.`,
        );
    }
    assertProtocolHash(
        proofMaterial.relinearizationKeyShareTboxParameterProfileHash,
        `${fieldName}.relinearizationKeyShareTboxParameterProfileHash`,
    );
    assertEvaluationKeyShareProofMaterial(
        proofMaterial,
        expectedComponentVectorRoot,
        fieldName,
    );
};

const assertGaloisProofMaterial = (
    proofMaterial: GaloisKeyShareProofMaterial,
    expectedComponentVectorRoot: ProtocolHash,
    fieldName: string,
): void => {
    if (
        proofMaterial.proofProfileId !==
        'sealed-lattice-galois-key-share-proof-lnp-v1'
    ) {
        throw new TypeError(
            `${fieldName}.proofProfileId must be sealed-lattice-galois-key-share-proof-lnp-v1.`,
        );
    }
    assertProtocolHash(
        proofMaterial.galoisKeyShareTboxParameterProfileHash,
        `${fieldName}.galoisKeyShareTboxParameterProfileHash`,
    );
    assertEvaluationKeyShareProofMaterial(
        proofMaterial,
        expectedComponentVectorRoot,
        fieldName,
    );
};

const assertEvaluationKeyShareProofGenerationBase = (
    proofGeneration: EvaluationKeyShareProofGenerationBase,
    expectedComponentVectorRoot: ProtocolHash,
    fieldName: string,
): void => {
    assertJsonRecord(
        proofGeneration.setupProofBinding,
        `${fieldName}.setupProofBinding`,
    );
    assertNonEmptyString(
        proofGeneration.keySwitchDomain,
        `${fieldName}.keySwitchDomain`,
    );
    assertNonEmptyString(
        proofGeneration.keySwitchSeedHex,
        `${fieldName}.keySwitchSeedHex`,
    );
    assertLowercaseHex(
        proofGeneration.keySwitchSeedHex,
        `${fieldName}.keySwitchSeedHex`,
    );
    assertPositiveSafeInteger(
        proofGeneration.ringDegree,
        `${fieldName}.ringDegree`,
    );
    assertProtocolHash(
        proofGeneration.keySwitchComponentVectorRoot,
        `${fieldName}.keySwitchComponentVectorRoot`,
    );
    if (
        proofGeneration.keySwitchComponentVectorRoot !==
        expectedComponentVectorRoot
    ) {
        throw new Error(
            `${fieldName}.keySwitchComponentVectorRoot must match the share root.`,
        );
    }
    if (proofGeneration.constantCommitments.length === 0) {
        throw new Error(`${fieldName}.constantCommitments must be non-empty.`);
    }
    proofGeneration.constantCommitments.forEach((commitment, commitmentIndex) =>
        assertJsonRecord(
            commitment,
            `${fieldName}.constantCommitments.${String(commitmentIndex)}`,
        ),
    );
    if (proofGeneration.secretCoefficients.length === 0) {
        throw new Error(`${fieldName}.secretCoefficients must be non-empty.`);
    }
    if (proofGeneration.openingRandomnessByLimb.length === 0) {
        throw new Error(
            `${fieldName}.openingRandomnessByLimb must be non-empty.`,
        );
    }
    if (proofGeneration.errorCoefficientsByDigit.length === 0) {
        throw new Error(
            `${fieldName}.errorCoefficientsByDigit must be non-empty.`,
        );
    }
    if (proofGeneration.proofRandomnessSource !== undefined) {
        if (
            proofGeneration.proofRandomnessSource !== 'fresh-csprng' &&
            proofGeneration.proofRandomnessSource !==
                'development-deterministic-fixture'
        ) {
            throw new TypeError(
                `${fieldName}.proofRandomnessSource must be fresh-csprng or development-deterministic-fixture.`,
            );
        }
    }
    assertProtocolHash(
        proofGeneration.proofRandomnessSeedHex,
        `${fieldName}.proofRandomnessSeedHex`,
    );
    if (proofGeneration.transportedKeySwitchComponentMaterial !== undefined) {
        assertJsonRecord(
            proofGeneration.transportedKeySwitchComponentMaterial,
            `${fieldName}.transportedKeySwitchComponentMaterial`,
        );
    }
    if (
        proofGeneration.keySwitchMaterialEncoding ===
        'embedded-full-key-switch-component-vectors'
    ) {
        if (proofGeneration.keySwitchComponentVectors.length === 0) {
            throw new Error(
                `${fieldName}.keySwitchComponentVectors must be non-empty.`,
            );
        }
        proofGeneration.keySwitchComponentVectors.forEach(
            (componentVector, vectorIndex) =>
                assertJsonRecord(
                    componentVector,
                    `${fieldName}.keySwitchComponentVectors.${String(vectorIndex)}`,
                ),
        );
    } else if (
        proofGeneration.keySwitchMaterialEncoding ===
        'binary-chunked-key-switch-component-vectors'
    ) {
        for (const [hashFieldName, hashValue] of [
            [
                'keySwitchComponentMaterialRoot',
                proofGeneration.keySwitchComponentMaterialRoot,
            ],
            [
                'keySwitchComponentFullObjectHash',
                proofGeneration.keySwitchComponentFullObjectHash,
            ],
            [
                'keySwitchComponentChunkRoot',
                proofGeneration.keySwitchComponentChunkRoot,
            ],
        ] as const) {
            assertProtocolHash(hashValue, `${fieldName}.${hashFieldName}`);
        }
        assertPositiveSafeInteger(
            proofGeneration.keySwitchComponentChunkSizeBytes,
            `${fieldName}.keySwitchComponentChunkSizeBytes`,
        );
        assertPositiveSafeInteger(
            proofGeneration.keySwitchComponentChunkCount,
            `${fieldName}.keySwitchComponentChunkCount`,
        );
        assertPositiveSafeInteger(
            proofGeneration.keySwitchComponentTotalByteLength,
            `${fieldName}.keySwitchComponentTotalByteLength`,
        );
        if (
            proofGeneration.keySwitchComponentChunkHashes.length !==
            proofGeneration.keySwitchComponentChunkCount
        ) {
            throw new Error(
                `${fieldName}.keySwitchComponentChunkHashes must match keySwitchComponentChunkCount.`,
            );
        }
        proofGeneration.keySwitchComponentChunkHashes.forEach(
            (chunkHash, chunkIndex) =>
                assertProtocolHash(
                    chunkHash,
                    `${fieldName}.keySwitchComponentChunkHashes.${String(chunkIndex)}`,
                ),
        );
    } else {
        throw new TypeError(
            `${fieldName}.keySwitchMaterialEncoding must be embedded-full-key-switch-component-vectors or binary-chunked-key-switch-component-vectors.`,
        );
    }
};

const sameSecretStatementRecordForProofGeneration = (
    proofReference: SameSecretProofReference,
): JsonRecord => ({
    objectType: 'SameSecretConsistencyStatement',
    objectVersion: 1,
    trusteeIdentity: proofReference.trusteeIdentity,
    trusteeRosterPosition: proofReference.trusteeRosterPosition,
    sameSecretStatementRoot: proofReference.sameSecretStatementRoot,
    trusteeSecretCommitmentRoot: proofReference.trusteeSecretCommitmentRoot,
});

const assertGeneratedProofCommon = (
    generatedProof: EvaluationKeyShareProofGenerationOutput,
    proofFamily: 'relinearization-key-share' | 'galois-key-share',
    fieldName: string,
): void => {
    if (
        generatedProof.ok !== true ||
        generatedProof.operation !== 'generateEvaluationKeyShareLnpProof' ||
        generatedProof.proofFamily !== proofFamily
    ) {
        throw new Error(`${fieldName} returned the wrong proof family.`);
    }
    if (generatedProof.setupProofProfileId !== setupProofProfileId) {
        throw new Error(
            `${fieldName}.setupProofProfileId must match the setup proof profile.`,
        );
    }
    if (
        proofFamily === 'relinearization-key-share' &&
        (generatedProof.proofVerificationStatus !==
            relinearizationProofVerificationStatus ||
            generatedProof.proofModelStatus !== relinearizationProofModelStatus)
    ) {
        throw new Error(
            `${fieldName} returned an unexpected relinearization proof status.`,
        );
    }
    if (
        proofFamily === 'galois-key-share' &&
        (generatedProof.proofVerificationStatus !==
            galoisProofVerificationStatus ||
            generatedProof.proofModelStatus !== galoisProofModelStatus)
    ) {
        throw new Error(
            `${fieldName} returned an unexpected Galois proof status.`,
        );
    }
    for (const [hashFieldName, hashValue] of [
        ['statementHash', generatedProof.statementHash],
        ['relationCommitmentHash', generatedProof.relationCommitmentHash],
        ['tboxCommitmentPrefixHash', generatedProof.tboxCommitmentPrefixHash],
        ['proofBytesHash', generatedProof.proofBytesHash],
    ] as const) {
        assertProtocolHash(hashValue, `${fieldName}.${hashFieldName}`);
    }
    assertSetupProofChallenge(
        generatedProof.challenge,
        `${fieldName}.challenge`,
    );
    optionalSetupProofTboxZ34Metadata(generatedProof, fieldName);
    assertPositiveSafeInteger(
        generatedProof.proofSizeBytes,
        `${fieldName}.proofSizeBytes`,
    );
    assertNonEmptyString(
        generatedProof.proofBytesHex,
        `${fieldName}.proofBytesHex`,
    );
    assertLowercaseHex(
        generatedProof.proofBytesHex,
        `${fieldName}.proofBytesHex`,
    );
    if (
        generatedProof.proofBytesHex.length !==
        generatedProof.proofSizeBytes * 2
    ) {
        throw new Error(
            `${fieldName}.proofBytesHex length must match proofSizeBytes.`,
        );
    }
    if (
        generatedProof.proofRandomness.source !== 'fresh-csprng' &&
        generatedProof.proofRandomness.source !==
            'development-deterministic-fixture'
    ) {
        throw new TypeError(
            `${fieldName}.proofRandomness.source must be fresh-csprng or development-deterministic-fixture.`,
        );
    }
    if (generatedProof.proofRandomness.seedBytes !== 64) {
        throw new Error(`${fieldName}.proofRandomness.seedBytes must be 64.`);
    }
    assertNonEmptyString(
        generatedProof.proofRandomness.retention,
        `${fieldName}.proofRandomness.retention`,
    );
};

const resolveRelinearizationProofMaterial = (
    contribution: Readonly<{
        readonly proofMaterial?: RelinearizationKeyShareProofMaterial;
        readonly proofGeneration?: RelinearizationKeyShareProofGeneration;
    }>,
    expectedComponentVectorRoot: ProtocolHash,
    proofRecord: JsonRecord,
    proofReference: SameSecretProofReference,
    input: EvaluationKeyProofCommonInput,
    fieldName: string,
): RelinearizationKeyShareProofMaterial => {
    if (
        (contribution.proofMaterial === undefined) ===
        (contribution.proofGeneration === undefined)
    ) {
        throw new Error(
            `${fieldName} must provide exactly one of proofMaterial or proofGeneration.`,
        );
    }
    if (contribution.proofMaterial !== undefined) {
        assertRelinearizationProofMaterial(
            contribution.proofMaterial,
            expectedComponentVectorRoot,
            `${fieldName}.proofMaterial`,
        );

        return contribution.proofMaterial;
    }
    const proofGeneration = contribution.proofGeneration;
    if (proofGeneration === undefined) {
        throw new Error(`${fieldName}.proofGeneration is required.`);
    }
    if (input.evaluationKeyShareProofGenerator === undefined) {
        throw new Error(
            'evaluationKeyShareProofGenerator is required when evaluation-key proofGeneration is supplied.',
        );
    }
    if (
        proofGeneration.proofProfileId !==
        'sealed-lattice-relinearization-key-share-proof-lnp-v1'
    ) {
        throw new TypeError(
            `${fieldName}.proofGeneration.proofProfileId must be sealed-lattice-relinearization-key-share-proof-lnp-v1.`,
        );
    }
    assertProtocolHash(
        proofGeneration.relinearizationKeyShareTboxParameterProfileHash,
        `${fieldName}.proofGeneration.relinearizationKeyShareTboxParameterProfileHash`,
    );
    if (proofGeneration.relinearizationSourceCoefficientsByDigit.length === 0) {
        throw new Error(
            `${fieldName}.proofGeneration.relinearizationSourceCoefficientsByDigit must be non-empty.`,
        );
    }
    if (proofRecord.objectType === 'RelinearizationKeyShareRoundTwo') {
        if (
            proofGeneration.roundOneAggregateSourceCoefficientsByDigit ===
                undefined ||
            proofGeneration.roundOneAggregateSourceCoefficientsByDigit
                .length === 0
        ) {
            throw new Error(
                `${fieldName}.proofGeneration.roundOneAggregateSourceCoefficientsByDigit is required for relinearization round-two proof generation.`,
            );
        }
    } else if (
        proofGeneration.roundOneAggregateSourceCoefficientsByDigit !== undefined
    ) {
        throw new Error(
            `${fieldName}.proofGeneration.roundOneAggregateSourceCoefficientsByDigit must not be supplied for relinearization round-one proof generation.`,
        );
    }
    assertEvaluationKeyShareProofGenerationBase(
        proofGeneration,
        expectedComponentVectorRoot,
        `${fieldName}.proofGeneration`,
    );
    const generatedProof = input.evaluationKeyShareProofGenerator({
        proofFamily: 'relinearization-key-share',
        publicMatrixSeedHash: input.evaluatorKeySchedule.publicMatrixSeedHash,
        proofRecord,
        sameSecretStatementRecord:
            sameSecretStatementRecordForProofGeneration(proofReference),
        constantCommitments: proofGeneration.constantCommitments,
        setupProofBinding: proofGeneration.setupProofBinding,
        transportedKeySwitchComponentMaterial:
            proofGeneration.transportedKeySwitchComponentMaterial,
        secretCoefficients: proofGeneration.secretCoefficients,
        openingRandomnessByLimb: proofGeneration.openingRandomnessByLimb,
        errorCoefficientsByDigit: proofGeneration.errorCoefficientsByDigit,
        relinearizationSourceCoefficientsByDigit:
            proofGeneration.relinearizationSourceCoefficientsByDigit,
        roundOneAggregateSourceCoefficientsByDigit:
            proofGeneration.roundOneAggregateSourceCoefficientsByDigit,
        proofRandomnessSource: proofGeneration.proofRandomnessSource,
        proofRandomnessSeedHex: proofGeneration.proofRandomnessSeedHex,
    });
    assertGeneratedProofCommon(
        generatedProof,
        'relinearization-key-share',
        `${fieldName}.generatedProof`,
    );
    if (
        generatedProof.relinearizationKeyShareTboxParameterProfileHash !==
        proofGeneration.relinearizationKeyShareTboxParameterProfileHash
    ) {
        throw new Error(
            `${fieldName}.generatedProof.relinearizationKeyShareTboxParameterProfileHash must match proofGeneration.`,
        );
    }
    const commonProofMaterial = {
        proofProfileId: proofGeneration.proofProfileId,
        setupProofBinding: proofGeneration.setupProofBinding,
        keySwitchDomain: proofGeneration.keySwitchDomain,
        keySwitchSeedHex: proofGeneration.keySwitchSeedHex,
        ringDegree: proofGeneration.ringDegree,
        keySwitchComponentVectorRoot:
            proofGeneration.keySwitchComponentVectorRoot,
        relinearizationKeyShareTboxParameterProfileHash:
            generatedProof.relinearizationKeyShareTboxParameterProfileHash,
        statementHash: generatedProof.statementHash,
        relationCommitmentHash: generatedProof.relationCommitmentHash,
        tboxCommitmentPrefixHash: generatedProof.tboxCommitmentPrefixHash,
        ...optionalSetupProofTboxZ34Metadata(
            generatedProof,
            `${fieldName}.generatedProof`,
        ),
        challenge: generatedProof.challenge,
        proofSizeBytes: generatedProof.proofSizeBytes,
        proofBytesHash: generatedProof.proofBytesHash,
        proofBytesHex: generatedProof.proofBytesHex,
    } as const;
    const proofMaterial =
        proofGeneration.keySwitchMaterialEncoding ===
        'embedded-full-key-switch-component-vectors'
            ? ({
                  ...commonProofMaterial,
                  keySwitchMaterialEncoding:
                      proofGeneration.keySwitchMaterialEncoding,
                  keySwitchComponentVectors:
                      proofGeneration.keySwitchComponentVectors,
              } as const satisfies RelinearizationKeyShareProofMaterial)
            : ({
                  ...commonProofMaterial,
                  keySwitchMaterialEncoding:
                      proofGeneration.keySwitchMaterialEncoding,
                  keySwitchComponentMaterialRoot:
                      proofGeneration.keySwitchComponentMaterialRoot,
                  keySwitchComponentChunkSizeBytes:
                      proofGeneration.keySwitchComponentChunkSizeBytes,
                  keySwitchComponentChunkCount:
                      proofGeneration.keySwitchComponentChunkCount,
                  keySwitchComponentTotalByteLength:
                      proofGeneration.keySwitchComponentTotalByteLength,
                  keySwitchComponentFullObjectHash:
                      proofGeneration.keySwitchComponentFullObjectHash,
                  keySwitchComponentChunkRoot:
                      proofGeneration.keySwitchComponentChunkRoot,
                  keySwitchComponentChunkHashes:
                      proofGeneration.keySwitchComponentChunkHashes,
              } as const satisfies RelinearizationKeyShareProofMaterial);
    assertRelinearizationProofMaterial(
        proofMaterial,
        expectedComponentVectorRoot,
        `${fieldName}.generatedProofMaterial`,
    );

    return proofMaterial;
};

const resolveGaloisProofMaterial = (
    contribution: GaloisKeyShareProofContribution,
    expectedComponentVectorRoot: ProtocolHash,
    proofRecord: JsonRecord,
    proofReference: SameSecretProofReference,
    input: EvaluationKeyProofCommonInput,
    fieldName: string,
): GaloisKeyShareProofMaterial => {
    if (
        (contribution.proofMaterial === undefined) ===
        (contribution.proofGeneration === undefined)
    ) {
        throw new Error(
            `${fieldName} must provide exactly one of proofMaterial or proofGeneration.`,
        );
    }
    if (contribution.proofMaterial !== undefined) {
        assertGaloisProofMaterial(
            contribution.proofMaterial,
            expectedComponentVectorRoot,
            `${fieldName}.proofMaterial`,
        );

        return contribution.proofMaterial;
    }
    const proofGeneration = contribution.proofGeneration;
    if (proofGeneration === undefined) {
        throw new Error(`${fieldName}.proofGeneration is required.`);
    }
    if (input.evaluationKeyShareProofGenerator === undefined) {
        throw new Error(
            'evaluationKeyShareProofGenerator is required when evaluation-key proofGeneration is supplied.',
        );
    }
    if (
        proofGeneration.proofProfileId !==
        'sealed-lattice-galois-key-share-proof-lnp-v1'
    ) {
        throw new TypeError(
            `${fieldName}.proofGeneration.proofProfileId must be sealed-lattice-galois-key-share-proof-lnp-v1.`,
        );
    }
    assertProtocolHash(
        proofGeneration.galoisKeyShareTboxParameterProfileHash,
        `${fieldName}.proofGeneration.galoisKeyShareTboxParameterProfileHash`,
    );
    assertEvaluationKeyShareProofGenerationBase(
        proofGeneration,
        expectedComponentVectorRoot,
        `${fieldName}.proofGeneration`,
    );
    const generatedProof = input.evaluationKeyShareProofGenerator({
        proofFamily: 'galois-key-share',
        publicMatrixSeedHash: input.evaluatorKeySchedule.publicMatrixSeedHash,
        proofRecord,
        sameSecretStatementRecord:
            sameSecretStatementRecordForProofGeneration(proofReference),
        constantCommitments: proofGeneration.constantCommitments,
        setupProofBinding: proofGeneration.setupProofBinding,
        transportedKeySwitchComponentMaterial:
            proofGeneration.transportedKeySwitchComponentMaterial,
        secretCoefficients: proofGeneration.secretCoefficients,
        openingRandomnessByLimb: proofGeneration.openingRandomnessByLimb,
        errorCoefficientsByDigit: proofGeneration.errorCoefficientsByDigit,
        proofRandomnessSource: proofGeneration.proofRandomnessSource,
        proofRandomnessSeedHex: proofGeneration.proofRandomnessSeedHex,
    });
    assertGeneratedProofCommon(
        generatedProof,
        'galois-key-share',
        `${fieldName}.generatedProof`,
    );
    if (
        generatedProof.galoisKeyShareTboxParameterProfileHash !==
        proofGeneration.galoisKeyShareTboxParameterProfileHash
    ) {
        throw new Error(
            `${fieldName}.generatedProof.galoisKeyShareTboxParameterProfileHash must match proofGeneration.`,
        );
    }
    const commonProofMaterial = {
        proofProfileId: proofGeneration.proofProfileId,
        setupProofBinding: proofGeneration.setupProofBinding,
        keySwitchDomain: proofGeneration.keySwitchDomain,
        keySwitchSeedHex: proofGeneration.keySwitchSeedHex,
        ringDegree: proofGeneration.ringDegree,
        keySwitchComponentVectorRoot:
            proofGeneration.keySwitchComponentVectorRoot,
        galoisKeyShareTboxParameterProfileHash:
            generatedProof.galoisKeyShareTboxParameterProfileHash,
        statementHash: generatedProof.statementHash,
        relationCommitmentHash: generatedProof.relationCommitmentHash,
        tboxCommitmentPrefixHash: generatedProof.tboxCommitmentPrefixHash,
        ...optionalSetupProofTboxZ34Metadata(
            generatedProof,
            `${fieldName}.generatedProof`,
        ),
        challenge: generatedProof.challenge,
        proofSizeBytes: generatedProof.proofSizeBytes,
        proofBytesHash: generatedProof.proofBytesHash,
        proofBytesHex: generatedProof.proofBytesHex,
    } as const;
    const proofMaterial =
        proofGeneration.keySwitchMaterialEncoding ===
        'embedded-full-key-switch-component-vectors'
            ? ({
                  ...commonProofMaterial,
                  keySwitchMaterialEncoding:
                      proofGeneration.keySwitchMaterialEncoding,
                  keySwitchComponentVectors:
                      proofGeneration.keySwitchComponentVectors,
              } as const satisfies GaloisKeyShareProofMaterial)
            : ({
                  ...commonProofMaterial,
                  keySwitchMaterialEncoding:
                      proofGeneration.keySwitchMaterialEncoding,
                  keySwitchComponentMaterialRoot:
                      proofGeneration.keySwitchComponentMaterialRoot,
                  keySwitchComponentChunkSizeBytes:
                      proofGeneration.keySwitchComponentChunkSizeBytes,
                  keySwitchComponentChunkCount:
                      proofGeneration.keySwitchComponentChunkCount,
                  keySwitchComponentTotalByteLength:
                      proofGeneration.keySwitchComponentTotalByteLength,
                  keySwitchComponentFullObjectHash:
                      proofGeneration.keySwitchComponentFullObjectHash,
                  keySwitchComponentChunkRoot:
                      proofGeneration.keySwitchComponentChunkRoot,
                  keySwitchComponentChunkHashes:
                      proofGeneration.keySwitchComponentChunkHashes,
              } as const satisfies GaloisKeyShareProofMaterial);
    assertGaloisProofMaterial(
        proofMaterial,
        expectedComponentVectorRoot,
        `${fieldName}.generatedProofMaterial`,
    );

    return proofMaterial;
};

const relinearizationProofRecordMaterialInput = (
    contribution: Readonly<{
        readonly proofMaterial?: RelinearizationKeyShareProofMaterial;
        readonly proofGeneration?: RelinearizationKeyShareProofGeneration;
    }>,
    fieldName: string,
):
    | RelinearizationKeyShareProofMaterial
    | RelinearizationKeyShareProofGeneration => {
    if (
        (contribution.proofMaterial === undefined) ===
        (contribution.proofGeneration === undefined)
    ) {
        throw new Error(
            `${fieldName} must provide exactly one of proofMaterial or proofGeneration.`,
        );
    }

    return (contribution.proofMaterial ?? contribution.proofGeneration)!;
};

const galoisProofRecordMaterialInput = (
    contribution: GaloisKeyShareProofContribution,
    fieldName: string,
): GaloisKeyShareProofMaterial | GaloisKeyShareProofGeneration => {
    if (
        (contribution.proofMaterial === undefined) ===
        (contribution.proofGeneration === undefined)
    ) {
        throw new Error(
            `${fieldName} must provide exactly one of proofMaterial or proofGeneration.`,
        );
    }

    return (contribution.proofMaterial ?? contribution.proofGeneration)!;
};

const keySwitchComponentRecordFields = (
    material:
        | EvaluationKeyShareProofMaterialBase
        | EvaluationKeyShareProofGenerationBase,
): JsonRecord =>
    material.keySwitchMaterialEncoding ===
    'embedded-full-key-switch-component-vectors'
        ? {
              keySwitchMaterialEncoding: material.keySwitchMaterialEncoding,
              keySwitchComponentVectors: material.keySwitchComponentVectors,
          }
        : {
              keySwitchMaterialEncoding: material.keySwitchMaterialEncoding,
              keySwitchComponentMaterialRoot:
                  material.keySwitchComponentMaterialRoot,
              keySwitchComponentChunkSizeBytes:
                  material.keySwitchComponentChunkSizeBytes,
              keySwitchComponentChunkCount:
                  material.keySwitchComponentChunkCount,
              keySwitchComponentTotalByteLength:
                  material.keySwitchComponentTotalByteLength,
              keySwitchComponentFullObjectHash:
                  material.keySwitchComponentFullObjectHash,
              keySwitchComponentChunkRoot: material.keySwitchComponentChunkRoot,
              keySwitchComponentChunkHashes:
                  material.keySwitchComponentChunkHashes,
          };

const relinearizationProofRecordMaterialFields = (
    material:
        | RelinearizationKeyShareProofMaterial
        | RelinearizationKeyShareProofGeneration,
): JsonRecord => ({
    proofProfileId: material.proofProfileId,
    setupProofBinding: material.setupProofBinding,
    ...keySwitchComponentRecordFields(material),
    keySwitchDomain: material.keySwitchDomain,
    keySwitchSeedHex: material.keySwitchSeedHex,
    ringDegree: material.ringDegree,
    keySwitchComponentVectorRoot: material.keySwitchComponentVectorRoot,
    relinearizationKeyShareTboxParameterProfileHash:
        material.relinearizationKeyShareTboxParameterProfileHash,
});

const galoisProofRecordMaterialFields = (
    material: GaloisKeyShareProofMaterial | GaloisKeyShareProofGeneration,
): JsonRecord => ({
    proofProfileId: material.proofProfileId,
    setupProofBinding: material.setupProofBinding,
    ...keySwitchComponentRecordFields(material),
    keySwitchDomain: material.keySwitchDomain,
    keySwitchSeedHex: material.keySwitchSeedHex,
    ringDegree: material.ringDegree,
    keySwitchComponentVectorRoot: material.keySwitchComponentVectorRoot,
    galoisKeyShareTboxParameterProfileHash:
        material.galoisKeyShareTboxParameterProfileHash,
});

const contextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<
    CollectiveBgvSetupContext,
    (typeof setupContextFieldNames)[number]
> => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
    setupEpoch: setupContext.setupEpoch,
});

const assertContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    valueName: string,
): void => {
    for (const fieldName of setupContextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${valueName}.${fieldName} must match setupContext.`,
            );
        }
    }
};

const contributionKey = (
    level: number,
    trusteeRosterPosition: number,
): string => `${String(level)}:${String(trusteeRosterPosition)}`;

const relinearizationKeySwitchSeed = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    round: 'round-one' | 'round-two',
    level: number,
): ProtocolHash =>
    deriveProtocolHash('RelinearizationKeyShareSeed', {
        objectType: 'RelinearizationKeySwitchPublicSampleSeed',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: 'relinearization-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-level-and-round',
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        relinearizationCrpRoot: evaluatorKeySchedule.relinearizationCrpRoot,
        round,
        level,
    });

const galoisKeySwitchSeed = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    rotation: number,
    level: number,
): ProtocolHash =>
    deriveProtocolHash('GaloisKeyShareSeed', {
        objectType: 'GaloisKeySwitchPublicSampleSeed',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: 'galois-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-rotation-and-level',
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        galoisKeyCrpRoot: evaluatorKeySchedule.galoisKeyCrpRoot,
        requiredGaloisSetHash: evaluatorKeySchedule.requiredGaloisSetHash,
        rotation,
        level,
    });

const assertRelinearizationKeySwitchSampleBinding = (
    proofMaterial: RelinearizationKeyShareProofMaterial,
    evaluatorKeySchedule: EvaluatorKeySchedule,
    round: 'round-one' | 'round-two',
    level: number,
    fieldName: string,
): void => {
    if (proofMaterial.keySwitchDomain !== 'relinearization') {
        throw new Error(
            `${fieldName}.keySwitchDomain must be relinearization.`,
        );
    }
    const expectedSeed = relinearizationKeySwitchSeed(
        evaluatorKeySchedule,
        round,
        level,
    );
    if (proofMaterial.keySwitchSeedHex !== expectedSeed) {
        throw new Error(
            `${fieldName}.keySwitchSeedHex must be shared by scheduled relinearization level and round.`,
        );
    }
};

const assertGaloisKeySwitchSampleBinding = (
    proofMaterial: GaloisKeyShareProofMaterial,
    evaluatorKeySchedule: EvaluatorKeySchedule,
    rotation: number,
    level: number,
    fieldName: string,
): void => {
    const expectedDomain = `galois-${String(rotation)}`;
    if (proofMaterial.keySwitchDomain !== expectedDomain) {
        throw new Error(
            `${fieldName}.keySwitchDomain must match the scheduled Galois rotation.`,
        );
    }
    const expectedSeed = galoisKeySwitchSeed(
        evaluatorKeySchedule,
        rotation,
        level,
    );
    if (proofMaterial.keySwitchSeedHex !== expectedSeed) {
        throw new Error(
            `${fieldName}.keySwitchSeedHex must be shared by scheduled Galois rotation and level.`,
        );
    }
};

const relinearizationSourceRelationForRound = (
    round: 'round-one' | 'round-two',
): Readonly<{ relation: string; status: string }> =>
    round === 'round-one'
        ? {
              relation: 'same-secret-for-relinearization-round-one-source',
              status: 'verified-by-round-one-same-secret-source-response',
          }
        : {
              relation:
                  'same-secret-times-round-one-aggregate-for-relinearization-source',
              status: 'verifier-checked-round-two-source-square-aggregate-binding',
          };

const relinearizationSourceSquareBindingRoot = (
    record: Readonly<Record<string, unknown>>,
    round: 'round-one' | 'round-two',
    shareRoot: ProtocolHash,
): ProtocolHash => {
    const sourceRelation = relinearizationSourceRelationForRound(round);

    return deriveProtocolHash('RelinearizationSourceSquareBindingRoot', {
        objectType: 'RelinearizationSourceSquareBinding',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: 'relinearization-key-share',
        sourceRelation: sourceRelation.relation,
        sourceRelationStatus: sourceRelation.status,
        round,
        evaluatorKeyScheduleRoot: record.evaluatorKeyScheduleRoot,
        sameSecretProofSetRoot: record.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            record.sameSecretProofFamilyBindingRoot,
        publicKeyShareLnpProofSetRoot: record.publicKeyShareLnpProofSetRoot,
        relinearizationCrpRoot: record.relinearizationCrpRoot,
        trusteeIdentity: record.trusteeIdentity,
        trusteeRosterPosition: record.trusteeRosterPosition,
        level: record.level,
        sameSecretStatementRoot: record.sameSecretStatementRoot,
        trusteeSecretCommitmentRoot: record.trusteeSecretCommitmentRoot,
        sameSecretProofRoot: record.sameSecretProofRoot,
        shareRoot,
        keySwitchComponentVectorRoot: record.keySwitchComponentVectorRoot,
        statementHash: record.statementHash,
        relationCommitmentHash: record.relationCommitmentHash,
        proofBytesHash: record.proofBytesHash,
    });
};

const relinearizationSourceSquareAggregateRoot = (
    round: 'round-one' | 'round-two',
    evaluatorKeyScheduleRoot: ProtocolHash,
    level: number,
    sourceSquareBindingRoots: readonly JsonRecord[],
    roundOneSourceSquareAggregateRoot?: ProtocolHash,
): ProtocolHash => {
    const sourceRelation = relinearizationSourceRelationForRound(round);

    return deriveProtocolHash('RelinearizationSourceSquareAggregateRoot', {
        objectType: 'RelinearizationSourceSquareAggregate',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: 'relinearization-key-share',
        sourceRelation: sourceRelation.relation,
        sourceRelationStatus: sourceRelation.status,
        round,
        evaluatorKeyScheduleRoot,
        level,
        ...(roundOneSourceSquareAggregateRoot === undefined
            ? {}
            : { roundOneSourceSquareAggregateRoot }),
        sourceSquareBindingRoots,
    });
};

const sortedSameSecretProofReferences = (
    input: Pick<
        EvaluationKeyProofCommonInput,
        'participantCount' | 'sameSecretProofReferences'
    >,
): SameSecretProofReference[] => {
    const references = [...input.sameSecretProofReferences].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (references.length !== input.participantCount) {
        throw new Error(
            'sameSecretProofReferences must contain one proof per participant.',
        );
    }
    references.forEach((reference, expectedRosterPosition) => {
        assertNonEmptyString(reference.trusteeIdentity, 'trusteeIdentity');
        assertNonNegativeSafeInteger(
            reference.trusteeRosterPosition,
            'trusteeRosterPosition',
        );
        if (reference.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'sameSecretProofReferences roster positions must be contiguous from zero.',
            );
        }
        for (const [fieldName, hashValue] of [
            ['sameSecretStatementRoot', reference.sameSecretStatementRoot],
            [
                'trusteeSecretCommitmentRoot',
                reference.trusteeSecretCommitmentRoot,
            ],
            ['sameSecretProofRoot', reference.sameSecretProofRoot],
        ] as const) {
            assertProtocolHash(hashValue, fieldName);
        }
    });

    return references;
};

const validateCommonInput = (
    input: EvaluationKeyProofCommonInput,
): SameSecretProofReference[] => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    if (input.qSharePrimes.length === 0) {
        throw new Error('qSharePrimes must contain at least one RNS prime.');
    }
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    assertContextMatches(
        input.setupContext,
        input.evaluatorKeySchedule,
        'evaluatorKeySchedule',
    );
    if (
        input.evaluatorKeySchedule.participantCount !==
            input.participantCount ||
        input.evaluatorKeySchedule.rnsLimbCount !== input.qSharePrimes.length
    ) {
        throw new Error(
            'evaluatorKeySchedule must match participant and RNS limb counts.',
        );
    }
    for (const [fieldName, hashValue] of [
        [
            'evaluatorKeyScheduleRoot',
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        ],
        [
            'sameSecretConsistencyRoot',
            input.evaluatorKeySchedule.sameSecretConsistencyRoot,
        ],
        ['sameSecretProofSetRoot', input.sameSecretProofSetRoot],
        [
            'sameSecretProofFamilyBindingRoot',
            input.sameSecretProofFamilyBindingRoot,
        ],
        [
            'publicKeyShareSetRoot',
            input.evaluatorKeySchedule.publicKeyShareSetRoot,
        ],
        ['publicKeyShareLnpProofSetRoot', input.publicKeyShareLnpProofSetRoot],
        [
            'relinearizationCrpRoot',
            input.evaluatorKeySchedule.relinearizationCrpRoot,
        ],
        ['galoisKeyCrpRoot', input.evaluatorKeySchedule.galoisKeyCrpRoot],
        [
            'requiredGaloisSetHash',
            input.evaluatorKeySchedule.requiredGaloisSetHash,
        ],
    ] as const) {
        assertProtocolHash(hashValue, fieldName);
    }

    return sortedSameSecretProofReferences(input);
};

type EvaluationKeyShareCompletedProofMaterial =
    | RelinearizationKeyShareProofMaterial
    | GaloisKeyShareProofMaterial;

type EvaluationKeyShareTransportWorkItem = Readonly<{
    readonly key: string;
    readonly proofFamily: EvaluationKeyShareProofFamily;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly proofMaterial: EvaluationKeyShareCompletedProofMaterial;
}>;

const proofBytesHashDomainForFamily = (
    proofFamily: EvaluationKeyShareProofFamily,
): string =>
    proofFamily === 'relinearization-key-share'
        ? relinearizationProofBytesHashDomain
        : galoisProofBytesHashDomain;

const evaluationKeyTransportItemKey = (
    proofFamily: EvaluationKeyShareProofFamily,
    scope: string,
    trusteeRosterPosition: number,
    level: number,
    rotation?: number,
): string =>
    [
        proofFamily,
        scope,
        String(trusteeRosterPosition),
        String(level),
        ...(rotation === undefined ? [] : [String(rotation)]),
    ].join(':');

const trusteeIdentityByRosterPosition = (
    sameSecretProofReferences: readonly Pick<
        SameSecretProofReference,
        'trusteeIdentity' | 'trusteeRosterPosition'
    >[],
): ReadonlyMap<number, string> => {
    const identities = new Map<number, string>();
    sameSecretProofReferences.forEach((reference, referenceIndex) => {
        assertNonEmptyString(
            reference.trusteeIdentity,
            `sameSecretProofReferences.${String(referenceIndex)}.trusteeIdentity`,
        );
        assertNonNegativeSafeInteger(
            reference.trusteeRosterPosition,
            `sameSecretProofReferences.${String(referenceIndex)}.trusteeRosterPosition`,
        );
        if (identities.has(reference.trusteeRosterPosition)) {
            throw new Error(
                'sameSecretProofReferences must not repeat trusteeRosterPosition.',
            );
        }
        identities.set(
            reference.trusteeRosterPosition,
            reference.trusteeIdentity,
        );
    });

    return identities;
};

const trusteeIdentityForContribution = (
    identities: ReadonlyMap<number, string>,
    trusteeRosterPosition: number,
    fieldName: string,
): string => {
    const trusteeIdentity = identities.get(trusteeRosterPosition);
    if (trusteeIdentity === undefined) {
        throw new Error(
            `${fieldName} references a trustee roster position without a same-secret proof reference.`,
        );
    }

    return trusteeIdentity;
};

const evaluationKeyShareTransportWorkItems = (
    input: EvaluationKeyShareMaterialTransportInput,
): readonly EvaluationKeyShareTransportWorkItem[] => {
    const identities = trusteeIdentityByRosterPosition(
        input.sameSecretProofReferences,
    );
    const workItems: EvaluationKeyShareTransportWorkItem[] = [];
    input.relinearizationRoundOneContributions.forEach(
        (contribution, contributionIndex) => {
            if (
                contribution.proofGeneration !== undefined ||
                contribution.proofMaterial === undefined
            ) {
                throw new Error(
                    'evaluation-key material transport requires completed relinearization round-one proof material.',
                );
            }
            assertRelinearizationProofMaterial(
                contribution.proofMaterial,
                contribution.roundOneShareRoot,
                `relinearizationRoundOneContributions.${String(contributionIndex)}.proofMaterial`,
            );
            workItems.push({
                key: evaluationKeyTransportItemKey(
                    'relinearization-key-share',
                    'round-one',
                    contribution.trusteeRosterPosition,
                    contribution.level,
                ),
                proofFamily: 'relinearization-key-share',
                trusteeIdentity: trusteeIdentityForContribution(
                    identities,
                    contribution.trusteeRosterPosition,
                    'relinearizationRoundOneContributions',
                ),
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                level: contribution.level,
                proofMaterial: contribution.proofMaterial,
            });
        },
    );
    input.relinearizationRoundTwoContributions.forEach(
        (contribution, contributionIndex) => {
            if (
                contribution.proofGeneration !== undefined ||
                contribution.proofMaterial === undefined
            ) {
                throw new Error(
                    'evaluation-key material transport requires completed relinearization round-two proof material.',
                );
            }
            assertRelinearizationProofMaterial(
                contribution.proofMaterial,
                contribution.roundTwoShareRoot,
                `relinearizationRoundTwoContributions.${String(contributionIndex)}.proofMaterial`,
            );
            workItems.push({
                key: evaluationKeyTransportItemKey(
                    'relinearization-key-share',
                    'round-two',
                    contribution.trusteeRosterPosition,
                    contribution.level,
                ),
                proofFamily: 'relinearization-key-share',
                trusteeIdentity: trusteeIdentityForContribution(
                    identities,
                    contribution.trusteeRosterPosition,
                    'relinearizationRoundTwoContributions',
                ),
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                level: contribution.level,
                proofMaterial: contribution.proofMaterial,
            });
        },
    );
    input.galoisKeyShareBatchContributions.forEach((batchContribution) => {
        const trusteeIdentity = trusteeIdentityForContribution(
            identities,
            batchContribution.trusteeRosterPosition,
            'galoisKeyShareBatchContributions',
        );
        batchContribution.galoisKeyShareProofs.forEach(
            (proofContribution, proofIndex) => {
                if (
                    proofContribution.proofGeneration !== undefined ||
                    proofContribution.proofMaterial === undefined
                ) {
                    throw new Error(
                        'evaluation-key material transport requires completed Galois proof material.',
                    );
                }
                assertGaloisProofMaterial(
                    proofContribution.proofMaterial,
                    proofContribution.galoisKeyShareRoot,
                    `galoisKeyShareProofs.${String(proofIndex)}.proofMaterial`,
                );
                workItems.push({
                    key: evaluationKeyTransportItemKey(
                        'galois-key-share',
                        'proof',
                        batchContribution.trusteeRosterPosition,
                        proofContribution.level,
                        proofContribution.rotation,
                    ),
                    proofFamily: 'galois-key-share',
                    trusteeIdentity,
                    trusteeRosterPosition:
                        batchContribution.trusteeRosterPosition,
                    level: proofContribution.level,
                    proofMaterial: proofContribution.proofMaterial,
                });
            },
        );
    });

    return workItems;
};

const encodeEvaluationKeyShareComponentMaterial = (
    proofFamily: EvaluationKeyShareProofFamily,
    proofMaterial: EvaluationKeyShareProofMaterialBase &
        EvaluationKeyShareEmbeddedKeySwitchComponentMaterial,
    level: number,
): readonly Uint8Array[] => {
    const digitCount = level + 1;
    if (proofMaterial.keySwitchComponentVectors.length !== digitCount ** 2) {
        throw new Error(
            'evaluation-key component material must contain one vector per scheduled digit and RNS limb.',
        );
    }
    const writer = new BinaryChunkWriter({
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        emptyErrorMessage:
            'evaluation-key component material transport requires bytes.',
    });
    writer.writeBytes(evaluationKeyShareComponentMaterialMagic);
    writer.writeU64LittleEndian(level, 'evaluation-key level');
    writer.writeU64LittleEndian(
        proofMaterial.ringDegree,
        'evaluation-key ringDegree',
    );
    writer.writeU64LittleEndian(digitCount, 'evaluation-key digitCount');
    writer.writeU64LittleEndian(digitCount, 'evaluation-key rnsLimbCount');
    const canonicalComponentVectors: JsonRecord[] = [];
    for (let digitIndex = 0; digitIndex < digitCount; digitIndex += 1) {
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < digitCount;
            rnsLimbIndex += 1
        ) {
            const componentVector = jsonRecordValue(
                proofMaterial.keySwitchComponentVectors[
                    digitIndex * digitCount + rnsLimbIndex
                ],
                'keySwitchComponentVectors',
            );
            const vectorPath = `keySwitchComponentVectors.${String(
                digitIndex,
            )}.${String(rnsLimbIndex)}`;
            if (
                nonNegativeIntegerRecordField(
                    componentVector,
                    'digitIndex',
                    vectorPath,
                ) !== digitIndex ||
                nonNegativeIntegerRecordField(
                    componentVector,
                    'rnsLimbIndex',
                    vectorPath,
                ) !== rnsLimbIndex ||
                componentVector.component !== 'b'
            ) {
                throw new Error(
                    'evaluation-key component material vectors must be ordered by digit and RNS limb.',
                );
            }
            const rnsPrime = nonNegativeIntegerRecordField(
                componentVector,
                'rnsPrime',
                vectorPath,
            );
            const coefficientByteLength = nonNegativeIntegerRecordField(
                componentVector,
                'coefficientByteLength',
                vectorPath,
            );
            if (coefficientByteLength !== proofMaterial.ringDegree * 8) {
                throw new Error(
                    'evaluation-key component material coefficientByteLength must match ringDegree.',
                );
            }
            const coefficientsLeHex = stringRecordField(
                componentVector,
                'coefficientsLeHex',
                vectorPath,
            );
            const coefficients = coefficientVectorFromLittleEndianHex(
                coefficientsLeHex,
                proofMaterial.ringDegree,
                `${vectorPath}.coefficientsLeHex`,
            );
            if (coefficients.some((coefficient) => coefficient >= rnsPrime)) {
                throw new Error(
                    'evaluation-key component material coefficients must be canonical residues.',
                );
            }
            const coefficientVectorHash =
                evaluationKeyShareComponentVectorHash(coefficients);
            if (
                stringRecordField(
                    componentVector,
                    'coefficientVectorHash512',
                    vectorPath,
                ) !== coefficientVectorHash
            ) {
                throw new Error(
                    'evaluation-key component material coefficient hash must match coefficientsLeHex.',
                );
            }
            canonicalComponentVectors.push({
                digitIndex,
                rnsLimbIndex,
                rnsPrime,
                component: 'b',
                coefficientByteLength,
                coefficientVectorHash512: coefficientVectorHash,
                coefficientsLeHex,
            });
            writer.writeU64LittleEndian(
                digitIndex,
                'evaluation-key component digitIndex',
            );
            writer.writeU64LittleEndian(
                rnsLimbIndex,
                'evaluation-key component rnsLimbIndex',
            );
            writer.writeU64LittleEndian(
                rnsPrime,
                'evaluation-key component rnsPrime',
            );
            writer.writeU64LittleEndian(
                proofMaterial.ringDegree,
                'evaluation-key component coefficientCount',
            );
            coefficients.forEach((coefficient) =>
                writer.writeU64LittleEndian(
                    coefficient,
                    'evaluation-key component coefficient',
                ),
            );
        }
    }
    const componentVectorRoot = evaluationKeyShareComponentVectorRoot(
        proofFamily,
        proofMaterial.keySwitchDomain,
        proofMaterial.keySwitchSeedHex,
        level,
        proofMaterial.ringDegree,
        canonicalComponentVectors,
    );
    if (componentVectorRoot !== proofMaterial.keySwitchComponentVectorRoot) {
        throw new Error(
            'evaluation-key component material root must match keySwitchComponentVectorRoot before transport.',
        );
    }

    return writer.finish();
};

const transportEvaluationKeyShareComponentMaterial = (
    workItem: EvaluationKeyShareTransportWorkItem,
): Readonly<{
    readonly proofMaterial: EvaluationKeyShareCompletedProofMaterial;
    readonly componentMaterial: JsonRecord;
}> => {
    if (
        workItem.proofMaterial.keySwitchMaterialEncoding !==
        'embedded-full-key-switch-component-vectors'
    ) {
        throw new Error(
            'evaluation-key component material transport must be built from embedded full component vectors.',
        );
    }
    const chunks = encodeEvaluationKeyShareComponentMaterial(
        workItem.proofFamily,
        workItem.proofMaterial,
        workItem.level,
    );
    const transportHashes = evaluationKeyShareComponentMaterialTransportHashes(
        workItem.proofFamily,
        chunks,
    );
    const keySwitchComponentMaterialRoot =
        evaluationKeyShareComponentMaterialReferenceRoot(
            workItem.proofFamily,
            workItem.proofMaterial,
            workItem.trusteeIdentity,
            workItem.trusteeRosterPosition,
            workItem.level,
            transportHashes,
        );
    const proofMaterialWithoutVectors = {
        ...workItem.proofMaterial,
    } as JsonRecord;
    delete proofMaterialWithoutVectors.keySwitchComponentVectors;
    const proofMaterial = {
        ...proofMaterialWithoutVectors,
        keySwitchMaterialEncoding: evaluationKeyShareComponentMaterialEncoding,
        keySwitchComponentMaterialRoot,
        keySwitchComponentChunkSizeBytes: setupProofTransportChunkSizeBytes,
        keySwitchComponentChunkCount: transportHashes.chunkHashes.length,
        keySwitchComponentTotalByteLength: transportHashes.totalByteLength,
        keySwitchComponentFullObjectHash: transportHashes.fullObjectHash,
        keySwitchComponentChunkRoot: transportHashes.chunkRoot,
        keySwitchComponentChunkHashes: transportHashes.chunkHashes,
    } as EvaluationKeyShareCompletedProofMaterial;

    return {
        proofMaterial,
        componentMaterial: {
            objectType: evaluationKeyShareComponentMaterialTransportObjectType,
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: workItem.proofFamily,
            keySwitchMaterialEncoding:
                evaluationKeyShareComponentMaterialEncoding,
            trusteeIdentity: workItem.trusteeIdentity,
            trusteeRosterPosition: workItem.trusteeRosterPosition,
            keySwitchDomain: workItem.proofMaterial.keySwitchDomain,
            keySwitchSeedHex: workItem.proofMaterial.keySwitchSeedHex,
            level: workItem.level,
            ringDegree: workItem.proofMaterial.ringDegree,
            digitCount: workItem.level + 1,
            rnsLimbCount: workItem.level + 1,
            keySwitchComponentVectorRoot:
                workItem.proofMaterial.keySwitchComponentVectorRoot,
            keySwitchComponentMaterialRoot,
            chunkSizeBytes: setupProofTransportChunkSizeBytes,
            chunkCount: transportHashes.chunkHashes.length,
            totalByteLength: transportHashes.totalByteLength,
            fullObjectHash: transportHashes.fullObjectHash,
            chunkRoot: transportHashes.chunkRoot,
            chunkHashes: transportHashes.chunkHashes,
            chunks: chunks.map((chunk, chunkIndex) => ({
                chunkIndex,
                bytesHex: bytesToHex(chunk),
            })),
        },
    };
};

const stripEvaluationKeyProofMaterialTransportContext = (
    proofMaterial: EvaluationKeyShareCompletedProofMaterial &
        Readonly<{
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly proofFamily: EvaluationKeyShareProofFamily;
        }>,
): EvaluationKeyShareCompletedProofMaterial => {
    const record = { ...proofMaterial } as JsonRecord;
    delete record.trusteeIdentity;
    delete record.trusteeRosterPosition;
    delete record.proofFamily;

    return record as EvaluationKeyShareCompletedProofMaterial;
};

export const createBinaryChunkedEvaluationKeyShareMaterialTransport = (
    input: EvaluationKeyShareMaterialTransportInput,
): BinaryChunkedEvaluationKeyShareMaterialTransport => {
    const workItems = evaluationKeyShareTransportWorkItems(input);
    const componentTransportByKey = new Map<
        string,
        EvaluationKeyShareCompletedProofMaterial
    >();
    const componentMaterials: JsonRecord[] = [];
    const componentRoots = new Set<string>();
    workItems.forEach((workItem) => {
        const componentTransport =
            transportEvaluationKeyShareComponentMaterial(workItem);
        const componentMaterialRoot = stringRecordField(
            componentTransport.componentMaterial,
            'keySwitchComponentMaterialRoot',
            'componentMaterial',
        );
        if (componentRoots.has(componentMaterialRoot)) {
            throw new Error(
                'transported evaluation-key component material contains duplicate roots.',
            );
        }
        componentRoots.add(componentMaterialRoot);
        componentTransportByKey.set(
            workItem.key,
            componentTransport.proofMaterial,
        );
        componentMaterials.push(componentTransport.componentMaterial);
    });

    const transportedProofMaterialByKey = new Map<
        string,
        EvaluationKeyShareCompletedProofMaterial
    >();
    const transportedProofMaterials: JsonRecord[] = [];
    (['relinearization-key-share', 'galois-key-share'] as const).forEach(
        (proofFamily) => {
            const familyItems = workItems.filter(
                (workItem) => workItem.proofFamily === proofFamily,
            );
            if (familyItems.length === 0) {
                return;
            }
            const proofMaterialTransport = transportSetupProofMaterials(
                familyItems.map((workItem) => ({
                    ...componentTransportByKey.get(workItem.key),
                    trusteeIdentity: workItem.trusteeIdentity,
                    trusteeRosterPosition: workItem.trusteeRosterPosition,
                    proofFamily,
                })),
                {
                    proofFamily,
                    proofBytesHashDomain:
                        proofBytesHashDomainForFamily(proofFamily),
                    transportedSetObjectType:
                        evaluationKeyShareProofTransportSetObjectType,
                    transportedObjectType:
                        evaluationKeyShareProofTransportObjectType,
                    transportedObjectHashFieldPrefix: 'proof',
                },
            );
            proofMaterialTransport.proofMaterials.forEach(
                (proofMaterial, proofIndex) => {
                    transportedProofMaterialByKey.set(
                        familyItems[proofIndex].key,
                        stripEvaluationKeyProofMaterialTransportContext(
                            proofMaterial as EvaluationKeyShareCompletedProofMaterial &
                                Readonly<{
                                    readonly trusteeIdentity: string;
                                    readonly trusteeRosterPosition: number;
                                    readonly proofFamily: EvaluationKeyShareProofFamily;
                                }>,
                        ),
                    );
                },
            );
            transportedProofMaterials.push(
                ...proofMaterialTransport.transportedProofMaterial
                    .proofMaterials,
            );
        },
    );

    const proofMaterialForKey = (
        key: string,
    ): EvaluationKeyShareCompletedProofMaterial => {
        const proofMaterial = transportedProofMaterialByKey.get(key);
        if (proofMaterial === undefined) {
            throw new Error(
                'evaluation-key proof material transport did not produce a transported proof material.',
            );
        }

        return proofMaterial;
    };

    return {
        relinearizationRoundOneContributions:
            input.relinearizationRoundOneContributions.map((contribution) => ({
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                level: contribution.level,
                roundOneShareRoot: contribution.roundOneShareRoot,
                proofMaterial: proofMaterialForKey(
                    evaluationKeyTransportItemKey(
                        'relinearization-key-share',
                        'round-one',
                        contribution.trusteeRosterPosition,
                        contribution.level,
                    ),
                ) as RelinearizationKeyShareProofMaterial,
            })),
        relinearizationRoundTwoContributions:
            input.relinearizationRoundTwoContributions.map((contribution) => ({
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                level: contribution.level,
                roundTwoShareRoot: contribution.roundTwoShareRoot,
                proofMaterial: proofMaterialForKey(
                    evaluationKeyTransportItemKey(
                        'relinearization-key-share',
                        'round-two',
                        contribution.trusteeRosterPosition,
                        contribution.level,
                    ),
                ) as RelinearizationKeyShareProofMaterial,
            })),
        galoisKeyShareBatchContributions:
            input.galoisKeyShareBatchContributions.map((batchContribution) => ({
                trusteeRosterPosition: batchContribution.trusteeRosterPosition,
                galoisKeyShareProofs:
                    batchContribution.galoisKeyShareProofs.map(
                        (proofContribution) => ({
                            rotation: proofContribution.rotation,
                            level: proofContribution.level,
                            galoisKeyShareRoot:
                                proofContribution.galoisKeyShareRoot,
                            proofMaterial: proofMaterialForKey(
                                evaluationKeyTransportItemKey(
                                    'galois-key-share',
                                    'proof',
                                    batchContribution.trusteeRosterPosition,
                                    proofContribution.level,
                                    proofContribution.rotation,
                                ),
                            ) as GaloisKeyShareProofMaterial,
                        }),
                    ),
            })),
        transportedEvaluationKeyShareProofMaterial: {
            objectType: evaluationKeyShareProofTransportSetObjectType,
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: 'evaluation-key-share',
            proofMaterials: transportedProofMaterials,
        },
        transportedEvaluationKeyShareComponentMaterial: {
            objectType:
                evaluationKeyShareComponentMaterialTransportSetObjectType,
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            componentMaterials,
        },
    };
};

const contributionMap = <
    Contribution extends {
        readonly trusteeRosterPosition: number;
        readonly level: number;
    },
>(
    contributions: readonly Contribution[],
    fieldName: string,
): ReadonlyMap<string, Contribution> => {
    const byKey = new Map<string, Contribution>();
    contributions.forEach((contribution) => {
        assertNonNegativeSafeInteger(
            contribution.trusteeRosterPosition,
            `${fieldName}.trusteeRosterPosition`,
        );
        assertNonNegativeSafeInteger(contribution.level, `${fieldName}.level`);
        const key = contributionKey(
            contribution.level,
            contribution.trusteeRosterPosition,
        );
        if (byKey.has(key)) {
            throw new Error(
                `${fieldName} must not repeat a trustee and level.`,
            );
        }
        byKey.set(key, contribution);
    });

    return byKey;
};

export const createRelinearizationKeyShareRounds = (
    input: RelinearizationKeyShareRoundsInput,
): RelinearizationKeyShareRounds => {
    const sameSecretProofReferences = validateCommonInput(input);
    const roundOneContributions = contributionMap(
        input.roundOneContributions,
        'roundOneContributions',
    );
    const roundTwoContributions = contributionMap(
        input.roundTwoContributions,
        'roundTwoContributions',
    );
    const levels = input.evaluatorKeySchedule.relinearizationLevelSchedule.map(
        (entry) => entry.level,
    );
    const roundOneRecords: RelinearizationKeyShareRoundOneRecord[] = [];
    const roundOneShareRoots = new Map<string, ProtocolHash>();
    const roundOneRecordRoots = new Map<string, ProtocolHash>();
    const roundOneSourceSquareBindingRoots = new Map<string, ProtocolHash>();
    const roundOneAggregateRootByLevel = new Map<number, ProtocolHash>();
    const roundOneSourceSquareAggregateRootByLevel = new Map<
        number,
        ProtocolHash
    >();
    const roundOneAggregateRoots = levels.map((level) => {
        const roundOneRecordRootsForLevel = sameSecretProofReferences.map(
            (proofReference) => {
                const key = contributionKey(
                    level,
                    proofReference.trusteeRosterPosition,
                );
                const contribution = roundOneContributions.get(key);
                if (contribution === undefined) {
                    throw new Error(
                        'roundOneContributions is missing a scheduled trustee and level.',
                    );
                }
                assertProtocolHash(
                    contribution.roundOneShareRoot,
                    'roundOneShareRoot',
                );
                const proofRecordMaterialInput =
                    relinearizationProofRecordMaterialInput(
                        contribution,
                        'roundOneContributions',
                    );
                const recordForProofGeneration = {
                    objectType: 'RelinearizationKeyShareRoundOne',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    proofFamily: 'relinearization-key-share',
                    proofVerificationStatus:
                        relinearizationProofVerificationStatus,
                    proofModelStatus: relinearizationProofModelStatus,
                    ...contextFields(input.setupContext),
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    level,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    sameSecretConsistencyRoot:
                        input.evaluatorKeySchedule.sameSecretConsistencyRoot,
                    sameSecretProofSetRoot: input.sameSecretProofSetRoot,
                    sameSecretProofFamilyBindingRoot:
                        input.sameSecretProofFamilyBindingRoot,
                    publicKeyShareLnpProofSetRoot:
                        input.publicKeyShareLnpProofSetRoot,
                    sameSecretStatementRoot:
                        proofReference.sameSecretStatementRoot,
                    trusteeSecretCommitmentRoot:
                        proofReference.trusteeSecretCommitmentRoot,
                    sameSecretProofRoot: proofReference.sameSecretProofRoot,
                    relinearizationCrpRoot:
                        input.evaluatorKeySchedule.relinearizationCrpRoot,
                    roundOneShareRoot: contribution.roundOneShareRoot,
                    ...relinearizationProofRecordMaterialFields(
                        proofRecordMaterialInput,
                    ),
                } as const satisfies JsonRecord;
                const proofMaterial = resolveRelinearizationProofMaterial(
                    contribution,
                    contribution.roundOneShareRoot,
                    recordForProofGeneration,
                    proofReference,
                    input,
                    'roundOneContributions',
                );
                assertRelinearizationKeySwitchSampleBinding(
                    proofMaterial,
                    input.evaluatorKeySchedule,
                    'round-one',
                    level,
                    'roundOneContributions.proofMaterial',
                );
                const recordWithoutProofRoot = {
                    ...recordForProofGeneration,
                    ...proofMaterial,
                } as const satisfies Omit<
                    RelinearizationKeyShareRoundOneRecord,
                    | 'sourceSquareBindingRoot'
                    | 'roundOneProofRoot'
                    | 'roundOneRecordRoot'
                >;
                const sourceSquareBindingRoot =
                    relinearizationSourceSquareBindingRoot(
                        recordWithoutProofRoot,
                        'round-one',
                        contribution.roundOneShareRoot,
                    );
                const recordWithSourceSquareRoot = {
                    ...recordWithoutProofRoot,
                    sourceSquareBindingRoot,
                } as const satisfies Omit<
                    RelinearizationKeyShareRoundOneRecord,
                    'roundOneProofRoot' | 'roundOneRecordRoot'
                >;
                const roundOneProofRoot = deriveProtocolHash(
                    'RelinearizationKeyShareProofRoot',
                    recordWithSourceSquareRoot,
                );
                const recordWithoutRoot = {
                    ...recordWithSourceSquareRoot,
                    roundOneProofRoot,
                } as const satisfies Omit<
                    RelinearizationKeyShareRoundOneRecord,
                    'roundOneRecordRoot'
                >;
                const roundOneRecordRoot = deriveProtocolHash(
                    'RelinearizationRoundOneRecordRoot',
                    recordWithoutRoot,
                );
                roundOneShareRoots.set(key, contribution.roundOneShareRoot);
                roundOneRecordRoots.set(key, roundOneRecordRoot);
                roundOneSourceSquareBindingRoots.set(
                    key,
                    sourceSquareBindingRoot,
                );
                roundOneRecords.push({
                    ...recordWithoutRoot,
                    roundOneRecordRoot,
                });

                return {
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    roundOneRecordRoot,
                };
            },
        );
        const roundOneSourceSquareBindingRootEntries =
            sameSecretProofReferences.map((proofReference) => {
                const sourceSquareBindingRoot =
                    roundOneSourceSquareBindingRoots.get(
                        contributionKey(
                            level,
                            proofReference.trusteeRosterPosition,
                        ),
                    );
                if (sourceSquareBindingRoot === undefined) {
                    throw new Error(
                        'roundOneContributions is missing a source-square binding root.',
                    );
                }

                return {
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    sourceSquareBindingRoot,
                };
            });
        const roundOneSourceSquareAggregateRoot =
            relinearizationSourceSquareAggregateRoot(
                'round-one',
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                level,
                roundOneSourceSquareBindingRootEntries,
            );
        const roundOneAggregateRoot = deriveProtocolHash(
            'RelinearizationRoundOneAggregateRoot',
            {
                objectType: 'RelinearizationRoundOneAggregate',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                evaluatorKeyScheduleRoot:
                    input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                level,
                roundOneSourceSquareAggregateRoot,
                roundOneRecordRoots: roundOneRecordRootsForLevel,
            },
        );
        roundOneAggregateRootByLevel.set(level, roundOneAggregateRoot);
        roundOneSourceSquareAggregateRootByLevel.set(
            level,
            roundOneSourceSquareAggregateRoot,
        );

        return {
            level,
            roundOneAggregateRoot,
            roundOneSourceSquareAggregateRoot,
        };
    });

    const roundTwoRecords: RelinearizationKeyShareRoundTwoRecord[] = [];
    const roundTwoAggregateRoots = levels.map((level) => {
        const roundTwoRecordRootsForLevel = sameSecretProofReferences.map(
            (proofReference) => {
                const key = contributionKey(
                    level,
                    proofReference.trusteeRosterPosition,
                );
                const contribution = roundTwoContributions.get(key);
                const roundOneShareRoot = roundOneShareRoots.get(key);
                const roundOneRecordRoot = roundOneRecordRoots.get(key);
                const roundOneAggregateRoot =
                    roundOneAggregateRootByLevel.get(level);
                const roundOneSourceSquareBindingRoot =
                    roundOneSourceSquareBindingRoots.get(key);
                const roundOneSourceSquareAggregateRoot =
                    roundOneSourceSquareAggregateRootByLevel.get(level);
                if (
                    contribution === undefined ||
                    roundOneShareRoot === undefined ||
                    roundOneRecordRoot === undefined ||
                    roundOneAggregateRoot === undefined ||
                    roundOneSourceSquareBindingRoot === undefined ||
                    roundOneSourceSquareAggregateRoot === undefined
                ) {
                    throw new Error(
                        'roundTwoContributions is missing a scheduled trustee and level.',
                    );
                }
                assertProtocolHash(
                    contribution.roundTwoShareRoot,
                    'roundTwoShareRoot',
                );
                const proofRecordMaterialInput =
                    relinearizationProofRecordMaterialInput(
                        contribution,
                        'roundTwoContributions',
                    );
                const recordForProofGeneration = {
                    objectType: 'RelinearizationKeyShareRoundTwo',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    proofFamily: 'relinearization-key-share',
                    proofVerificationStatus:
                        relinearizationProofVerificationStatus,
                    proofModelStatus: relinearizationProofModelStatus,
                    ...contextFields(input.setupContext),
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    level,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    sameSecretConsistencyRoot:
                        input.evaluatorKeySchedule.sameSecretConsistencyRoot,
                    sameSecretProofSetRoot: input.sameSecretProofSetRoot,
                    sameSecretProofFamilyBindingRoot:
                        input.sameSecretProofFamilyBindingRoot,
                    publicKeyShareLnpProofSetRoot:
                        input.publicKeyShareLnpProofSetRoot,
                    sameSecretStatementRoot:
                        proofReference.sameSecretStatementRoot,
                    trusteeSecretCommitmentRoot:
                        proofReference.trusteeSecretCommitmentRoot,
                    sameSecretProofRoot: proofReference.sameSecretProofRoot,
                    relinearizationCrpRoot:
                        input.evaluatorKeySchedule.relinearizationCrpRoot,
                    roundOneShareRoot,
                    roundOneRecordRoot,
                    roundOneAggregateRoot,
                    roundOneSourceSquareBindingRoot,
                    roundOneSourceSquareAggregateRoot,
                    roundTwoShareRoot: contribution.roundTwoShareRoot,
                    ...relinearizationProofRecordMaterialFields(
                        proofRecordMaterialInput,
                    ),
                } as const satisfies JsonRecord;
                const proofMaterial = resolveRelinearizationProofMaterial(
                    contribution,
                    contribution.roundTwoShareRoot,
                    recordForProofGeneration,
                    proofReference,
                    input,
                    'roundTwoContributions',
                );
                assertRelinearizationKeySwitchSampleBinding(
                    proofMaterial,
                    input.evaluatorKeySchedule,
                    'round-two',
                    level,
                    'roundTwoContributions.proofMaterial',
                );
                const recordWithoutProofRoot = {
                    ...recordForProofGeneration,
                    ...proofMaterial,
                } as const satisfies Omit<
                    RelinearizationKeyShareRoundTwoRecord,
                    | 'sourceSquareBindingRoot'
                    | 'roundTwoProofRoot'
                    | 'roundTwoRecordRoot'
                >;
                const sourceSquareBindingRoot =
                    relinearizationSourceSquareBindingRoot(
                        recordWithoutProofRoot,
                        'round-two',
                        contribution.roundTwoShareRoot,
                    );
                const recordWithSourceSquareRoot = {
                    ...recordWithoutProofRoot,
                    sourceSquareBindingRoot,
                } as const satisfies Omit<
                    RelinearizationKeyShareRoundTwoRecord,
                    'roundTwoProofRoot' | 'roundTwoRecordRoot'
                >;
                const roundTwoProofRoot = deriveProtocolHash(
                    'RelinearizationKeyShareProofRoot',
                    recordWithSourceSquareRoot,
                );
                const recordWithoutRoot = {
                    ...recordWithSourceSquareRoot,
                    roundTwoProofRoot,
                } as const satisfies Omit<
                    RelinearizationKeyShareRoundTwoRecord,
                    'roundTwoRecordRoot'
                >;
                const roundTwoRecordRoot = deriveProtocolHash(
                    'RelinearizationRoundTwoRecordRoot',
                    recordWithoutRoot,
                );
                roundTwoRecords.push({
                    ...recordWithoutRoot,
                    roundTwoRecordRoot,
                });

                return {
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    roundTwoRecordRoot,
                };
            },
        );
        const roundOneSourceSquareAggregateRoot =
            roundOneSourceSquareAggregateRootByLevel.get(level);
        if (roundOneSourceSquareAggregateRoot === undefined) {
            throw new Error(
                'roundTwoContributions is missing a scheduled source-square aggregate root.',
            );
        }
        const roundTwoSourceSquareBindingRootEntries = roundTwoRecords
            .filter((record) => record.level === level)
            .map((record) => ({
                trusteeIdentity: record.trusteeIdentity,
                trusteeRosterPosition: record.trusteeRosterPosition,
                sourceSquareBindingRoot: record.sourceSquareBindingRoot,
            }));
        const roundTwoSourceSquareAggregateRoot =
            relinearizationSourceSquareAggregateRoot(
                'round-two',
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                level,
                roundTwoSourceSquareBindingRootEntries,
                roundOneSourceSquareAggregateRoot,
            );
        const roundTwoAggregateRoot = deriveProtocolHash(
            'RelinearizationRoundTwoAggregateRoot',
            {
                objectType: 'RelinearizationRoundTwoAggregate',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                evaluatorKeyScheduleRoot:
                    input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                level,
                roundOneAggregateRoot: roundOneAggregateRootByLevel.get(level),
                roundOneSourceSquareAggregateRoot,
                roundTwoSourceSquareAggregateRoot,
                roundTwoRecordRoots: roundTwoRecordRootsForLevel,
            },
        );

        return {
            level,
            roundTwoAggregateRoot,
            roundTwoSourceSquareAggregateRoot,
        };
    });

    const roundsWithoutRoot = {
        objectType: 'RelinearizationKeyShareRounds',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: 'relinearization-key-share',
        proofVerificationStatus: relinearizationProofVerificationStatus,
        proofModelStatus: relinearizationProofModelStatus,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        evaluatorKeyScheduleRoot:
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        sameSecretConsistencyRoot:
            input.evaluatorKeySchedule.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretProofFamilyBindingRoot,
        publicKeyShareSetRoot: input.evaluatorKeySchedule.publicKeyShareSetRoot,
        publicKeyShareLnpProofSetRoot: input.publicKeyShareLnpProofSetRoot,
        relinearizationCrpRoot:
            input.evaluatorKeySchedule.relinearizationCrpRoot,
        relinearizationLevelSchedule:
            input.evaluatorKeySchedule.relinearizationLevelSchedule,
        roundOneAggregateRoots,
        roundOneRecords,
        roundTwoAggregateRoots,
        roundTwoRecords,
    } as const satisfies Omit<
        RelinearizationKeyShareRounds,
        'relinearizationKeyShareRoundsRoot'
    >;

    return {
        ...roundsWithoutRoot,
        relinearizationKeyShareRoundsRoot: deriveProtocolHash(
            'RelinearizationKeyShareRoundsRoot',
            roundsWithoutRoot,
        ),
    } satisfies RelinearizationKeyShareRounds;
};

export const createGaloisKeyShareBatches = (
    input: GaloisKeyShareBatchesInput,
): readonly GaloisKeyShareBatch[] => {
    const sameSecretProofReferences = validateCommonInput(input);
    const contributionsByRosterPosition = new Map<
        number,
        GaloisKeyShareBatchContribution
    >();
    input.batchContributions.forEach((contribution) => {
        assertNonNegativeSafeInteger(
            contribution.trusteeRosterPosition,
            'batchContributions.trusteeRosterPosition',
        );
        if (
            contributionsByRosterPosition.has(
                contribution.trusteeRosterPosition,
            )
        ) {
            throw new Error(
                'batchContributions must not repeat a trustee roster position.',
            );
        }
        contributionsByRosterPosition.set(
            contribution.trusteeRosterPosition,
            contribution,
        );
    });

    return sameSecretProofReferences.map((proofReference) => {
        const contribution = contributionsByRosterPosition.get(
            proofReference.trusteeRosterPosition,
        );
        if (contribution === undefined) {
            throw new Error(
                'batchContributions must contain one batch per participant.',
            );
        }
        if (
            contribution.galoisKeyShareProofs.length !==
            input.evaluatorKeySchedule.requiredGaloisKeySchedule.length
        ) {
            throw new Error(
                'galoisKeyShareProofs must contain one proof per required Galois key.',
            );
        }
        const galoisKeyShareProofs = contribution.galoisKeyShareProofs.map(
            (proofContribution, index) => {
                const expectedScheduleEntry =
                    input.evaluatorKeySchedule.requiredGaloisKeySchedule[index];
                if (
                    proofContribution.rotation !==
                        expectedScheduleEntry.rotation ||
                    proofContribution.level !== expectedScheduleEntry.level
                ) {
                    throw new Error(
                        'galoisKeyShareProofs must follow the frozen Galois key schedule.',
                    );
                }
                assertProtocolHash(
                    proofContribution.galoisKeyShareRoot,
                    'galoisKeyShareRoot',
                );
                const proofRecordMaterialInput = galoisProofRecordMaterialInput(
                    proofContribution,
                    'galoisKeyShareProofs',
                );
                const proofRecordForGeneration = {
                    objectType: 'GaloisKeyShareProof',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    proofFamily: 'galois-key-share',
                    proofVerificationStatus: galoisProofVerificationStatus,
                    proofModelStatus: galoisProofModelStatus,
                    ...contextFields(input.setupContext),
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    sameSecretConsistencyRoot:
                        input.evaluatorKeySchedule.sameSecretConsistencyRoot,
                    sameSecretProofSetRoot: input.sameSecretProofSetRoot,
                    sameSecretProofFamilyBindingRoot:
                        input.sameSecretProofFamilyBindingRoot,
                    publicKeyShareLnpProofSetRoot:
                        input.publicKeyShareLnpProofSetRoot,
                    sameSecretStatementRoot:
                        proofReference.sameSecretStatementRoot,
                    trusteeSecretCommitmentRoot:
                        proofReference.trusteeSecretCommitmentRoot,
                    sameSecretProofRoot: proofReference.sameSecretProofRoot,
                    galoisKeyCrpRoot:
                        input.evaluatorKeySchedule.galoisKeyCrpRoot,
                    requiredGaloisSetHash:
                        input.evaluatorKeySchedule.requiredGaloisSetHash,
                    rotation: proofContribution.rotation,
                    level: proofContribution.level,
                    galoisKeyShareRoot: proofContribution.galoisKeyShareRoot,
                    ...galoisProofRecordMaterialFields(
                        proofRecordMaterialInput,
                    ),
                } as const satisfies JsonRecord;
                const proofMaterial = resolveGaloisProofMaterial(
                    proofContribution,
                    proofContribution.galoisKeyShareRoot,
                    proofRecordForGeneration,
                    proofReference,
                    input,
                    'galoisKeyShareProofs',
                );
                assertGaloisKeySwitchSampleBinding(
                    proofMaterial,
                    input.evaluatorKeySchedule,
                    proofContribution.rotation,
                    proofContribution.level,
                    'galoisKeyShareProofs.proofMaterial',
                );
                const proofWithoutRoot = {
                    ...proofRecordForGeneration,
                    ...proofMaterial,
                } as const satisfies Omit<
                    GaloisKeyShareProof,
                    'galoisKeyShareProofRoot'
                >;

                return {
                    ...proofWithoutRoot,
                    galoisKeyShareProofRoot: deriveProtocolHash(
                        'GaloisKeyShareProofRoot',
                        proofWithoutRoot,
                    ),
                } satisfies GaloisKeyShareProof;
            },
        );
        const galoisKeyShareRoots = galoisKeyShareProofs.map((proof) => ({
            rotation: proof.rotation,
            level: proof.level,
            galoisKeyShareRoot: proof.galoisKeyShareRoot,
        }));
        const proofRoots = galoisKeyShareProofs.map((proof) => ({
            rotation: proof.rotation,
            level: proof.level,
            galoisKeyShareProofRoot: proof.galoisKeyShareProofRoot,
        }));
        const galoisKeyBatchProofRoot = deriveProtocolHash(
            'GaloisKeyBatchProofRoot',
            {
                objectType: 'GaloisKeyBatchProofAggregate',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: 'galois-key-share',
                evaluatorKeyScheduleRoot:
                    input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                requiredGaloisSetHash:
                    input.evaluatorKeySchedule.requiredGaloisSetHash,
                trusteeRosterPosition: proofReference.trusteeRosterPosition,
                proofRoots,
            },
        );
        const batchWithoutRoot = {
            objectType: 'GaloisKeyShareBatch',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: 'galois-key-share',
            proofVerificationStatus: galoisProofVerificationStatus,
            proofModelStatus: galoisProofModelStatus,
            ...contextFields(input.setupContext),
            trusteeIdentity: proofReference.trusteeIdentity,
            trusteeRosterPosition: proofReference.trusteeRosterPosition,
            evaluatorKeyScheduleRoot:
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
            sameSecretConsistencyRoot:
                input.evaluatorKeySchedule.sameSecretConsistencyRoot,
            sameSecretProofSetRoot: input.sameSecretProofSetRoot,
            sameSecretProofFamilyBindingRoot:
                input.sameSecretProofFamilyBindingRoot,
            publicKeyShareLnpProofSetRoot: input.publicKeyShareLnpProofSetRoot,
            sameSecretStatementRoot: proofReference.sameSecretStatementRoot,
            trusteeSecretCommitmentRoot:
                proofReference.trusteeSecretCommitmentRoot,
            sameSecretProofRoot: proofReference.sameSecretProofRoot,
            galoisKeyCrpRoot: input.evaluatorKeySchedule.galoisKeyCrpRoot,
            requiredGaloisSetHash:
                input.evaluatorKeySchedule.requiredGaloisSetHash,
            requiredGaloisKeySchedule:
                input.evaluatorKeySchedule.requiredGaloisKeySchedule,
            galoisKeyShareRoots,
            galoisKeyShareProofs,
            galoisKeyBatchProofRoot,
        } as const satisfies Omit<
            GaloisKeyShareBatch,
            'galoisKeyShareBatchRoot'
        >;

        return {
            ...batchWithoutRoot,
            galoisKeyShareBatchRoot: deriveProtocolHash(
                'GaloisKeyShareBatchRoot',
                batchWithoutRoot,
            ),
        } satisfies GaloisKeyShareBatch;
    });
};

const relinearizationShareMaterialManifest = (
    relinearizationKeyShareRounds: RelinearizationKeyShareRounds,
): readonly JsonRecord[] => {
    const entries: {
        readonly level: number;
        readonly roundOrder: number;
        readonly trusteeRosterPosition: number;
        readonly entry: JsonRecord;
    }[] = [];
    const recordGroups = [
        {
            round: 'round-one',
            roundOrder: 0,
            records: relinearizationKeyShareRounds.roundOneRecords,
            shareRootFieldName: 'roundOneShareRoot',
            proofRootFieldName: 'roundOneProofRoot',
            recordRootFieldName: 'roundOneRecordRoot',
        },
        {
            round: 'round-two',
            roundOrder: 1,
            records: relinearizationKeyShareRounds.roundTwoRecords,
            shareRootFieldName: 'roundTwoShareRoot',
            proofRootFieldName: 'roundTwoProofRoot',
            recordRootFieldName: 'roundTwoRecordRoot',
        },
    ] as const;

    recordGroups.forEach((group) => {
        group.records.forEach((record) => {
            const recordFields = record as JsonRecord;
            entries.push({
                level: record.level,
                roundOrder: group.roundOrder,
                trusteeRosterPosition: record.trusteeRosterPosition,
                entry: {
                    round: group.round,
                    trusteeIdentity: record.trusteeIdentity,
                    trusteeRosterPosition: record.trusteeRosterPosition,
                    level: record.level,
                    keySwitchMaterialEncoding: record.keySwitchMaterialEncoding,
                    keySwitchDomain: record.keySwitchDomain,
                    keySwitchSeedHex: record.keySwitchSeedHex,
                    keySwitchComponentVectorRoot:
                        record.keySwitchComponentVectorRoot,
                    keySwitchComponentMaterialRoot:
                        recordFields.keySwitchComponentMaterialRoot ?? null,
                    shareRoot: recordFields[group.shareRootFieldName],
                    proofRoot: recordFields[group.proofRootFieldName],
                    recordRoot: recordFields[group.recordRootFieldName],
                },
            });
        });
    });

    return entries
        .sort(
            (left, right) =>
                left.level - right.level ||
                left.roundOrder - right.roundOrder ||
                left.trusteeRosterPosition - right.trusteeRosterPosition,
        )
        .map((entry) => entry.entry);
};

const galoisShareMaterialManifest = (
    galoisKeyShareBatches: readonly GaloisKeyShareBatch[],
): readonly JsonRecord[] => {
    const entries: {
        readonly rotation: number;
        readonly level: number;
        readonly trusteeRosterPosition: number;
        readonly entry: JsonRecord;
    }[] = [];
    galoisKeyShareBatches.forEach((batch) => {
        batch.galoisKeyShareProofs.forEach((proofRecord) => {
            const proofFields = proofRecord as JsonRecord;
            entries.push({
                rotation: proofRecord.rotation,
                level: proofRecord.level,
                trusteeRosterPosition: proofRecord.trusteeRosterPosition,
                entry: {
                    trusteeIdentity: proofRecord.trusteeIdentity,
                    trusteeRosterPosition: proofRecord.trusteeRosterPosition,
                    rotation: proofRecord.rotation,
                    level: proofRecord.level,
                    keySwitchMaterialEncoding:
                        proofRecord.keySwitchMaterialEncoding,
                    keySwitchDomain: proofRecord.keySwitchDomain,
                    keySwitchSeedHex: proofRecord.keySwitchSeedHex,
                    keySwitchComponentVectorRoot:
                        proofRecord.keySwitchComponentVectorRoot,
                    keySwitchComponentMaterialRoot:
                        proofFields.keySwitchComponentMaterialRoot ?? null,
                    galoisKeyShareRoot: proofRecord.galoisKeyShareRoot,
                    galoisKeyShareProofRoot:
                        proofRecord.galoisKeyShareProofRoot,
                },
            });
        });
    });

    return entries
        .sort(
            (left, right) =>
                left.rotation - right.rotation ||
                left.level - right.level ||
                left.trusteeRosterPosition - right.trusteeRosterPosition,
        )
        .map((entry) => entry.entry);
};

const publicEvaluationKeyMaterialManifest = (
    input: PublicEvaluationKeyMaterialTransportInput,
    evaluationKeys: PublicEvaluationKeySet,
): JsonRecord => ({
    objectType: 'PublicEvaluationKeyMaterialManifest',
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    setupProofProfileId,
    assemblyStatus: publicEvaluationKeyAssemblyStatus,
    materialEncoding: publicEvaluationKeyMaterialEncoding,
    materialTransportEncoding: publicEvaluationKeyTransportMaterialEncoding,
    materialSource: publicEvaluationKeyMaterialSource,
    ...contextFields(input.setupContext),
    participantCount: input.participantCount,
    rnsLimbCount: input.qSharePrimes.length,
    evaluatorKeyScheduleRoot: evaluationKeys.evaluatorKeyScheduleRoot,
    sameSecretProofFamilyBindingRoot:
        evaluationKeys.sameSecretProofFamilyBindingRoot,
    publicKeyShareLnpProofSetRoot: evaluationKeys.publicKeyShareLnpProofSetRoot,
    relinearizationKeyShareRoundsRoot:
        evaluationKeys.relinearizationKeyShareRoundsRoot,
    relinearizationLevelSchedule: evaluationKeys.relinearizationLevelSchedule,
    relinearizationKeyRoots: evaluationKeys.relinearizationKeyRoots,
    relinearizationShareMaterialRoots: relinearizationShareMaterialManifest(
        input.relinearizationKeyShareRounds,
    ),
    requiredGaloisSetHash: evaluationKeys.requiredGaloisSetHash,
    requiredGaloisKeySchedule: evaluationKeys.requiredGaloisKeySchedule,
    galoisKeyShareBatchRoots: evaluationKeys.galoisKeyShareBatchRoots,
    galoisKeyRoots: evaluationKeys.galoisKeyRoots,
    galoisShareMaterialRoots: galoisShareMaterialManifest(
        input.galoisKeyShareBatches,
    ),
    genericKeySwitchKeyRoots: evaluationKeys.genericKeySwitchKeyRoots,
    rawKeyBytesEmbedded: false,
    verifierGeneratedKeyMaterial: false,
});

const encodePublicEvaluationKeyMaterialManifest = (
    manifest: JsonRecord,
): Uint8Array => {
    const manifestBytes = textEncoder.encode(canonicalJson(manifest));
    const materialBytes = new Uint8Array(
        publicEvaluationKeyMaterialMagic.byteLength + manifestBytes.byteLength,
    );
    materialBytes.set(publicEvaluationKeyMaterialMagic, 0);
    materialBytes.set(manifestBytes, publicEvaluationKeyMaterialMagic.length);

    return materialBytes;
};

const publicEvaluationKeyMaterialChunks = (
    materialBytes: Uint8Array,
): readonly Uint8Array[] => {
    if (materialBytes.byteLength === 0) {
        throw new Error(
            'public evaluation-key material transport requires bytes.',
        );
    }
    const chunks: Uint8Array[] = [];
    for (
        let byteOffset = 0;
        byteOffset < materialBytes.byteLength;
        byteOffset += setupProofTransportChunkSizeBytes
    ) {
        chunks.push(
            materialBytes.slice(
                byteOffset,
                byteOffset + setupProofTransportChunkSizeBytes,
            ),
        );
    }

    return chunks;
};

const publicEvaluationKeyMaterialFullObjectHash = (
    totalByteLength: number,
    chunks: readonly Uint8Array[],
): ProtocolHash =>
    hash512Hex(
        'sealed-lattice/setup/public-evaluation-key-material/full-object-v1',
        [u64LittleEndianBytes(totalByteLength, 'totalByteLength'), ...chunks],
    );

const publicEvaluationKeyMaterialChunkHash = (
    fullObjectHash: ProtocolHash,
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash =>
    hash512Hex('sealed-lattice/setup/public-evaluation-key-material/chunk-v1', [
        textEncoder.encode(fullObjectHash),
        u64LittleEndianBytes(chunkIndex, 'chunkIndex'),
        chunk,
    ]);

const publicEvaluationKeyMaterialTransportHashes = (
    chunks: readonly Uint8Array[],
): Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly chunkRoot: ProtocolHash;
    readonly totalByteLength: number;
}> => {
    if (chunks.length === 0) {
        throw new Error(
            'public evaluation-key material transport requires at least one chunk.',
        );
    }
    const totalByteLength = chunks.reduce((byteLength, chunk, chunkIndex) => {
        if (chunk.byteLength === 0) {
            throw new Error(
                'public evaluation-key material chunks must be non-empty.',
            );
        }
        if (chunk.byteLength > setupProofTransportChunkSizeBytes) {
            throw new Error(
                'public evaluation-key material chunk exceeds the accepted chunk size.',
            );
        }
        if (
            chunkIndex + 1 < chunks.length &&
            chunk.byteLength !== setupProofTransportChunkSizeBytes
        ) {
            throw new Error(
                'public evaluation-key material contains a short non-final chunk.',
            );
        }

        return byteLength + chunk.byteLength;
    }, 0);
    const fullObjectHash = publicEvaluationKeyMaterialFullObjectHash(
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        publicEvaluationKeyMaterialChunkHash(fullObjectHash, chunkIndex, chunk),
    );
    const chunkRoot = deriveProtocolHash(
        'PublicEvaluationKeyMaterialChunkRoot',
        {
            objectType: 'PublicEvaluationKeyMaterialChunkManifest',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            materialEncoding: publicEvaluationKeyTransportMaterialEncoding,
            chunkSizeBytes: setupProofTransportChunkSizeBytes,
            chunkCount: chunkHashes.length,
            totalByteLength,
            chunkHashes,
            fullObjectHash,
        },
    );

    return {
        fullObjectHash,
        chunkHashes,
        chunkRoot,
        totalByteLength,
    };
};

const publicEvaluationKeyMaterialReferenceRoot = (
    evaluationKeys: PublicEvaluationKeySet,
    expectedMaterialManifest: JsonRecord,
    transportHashes: ReturnType<
        typeof publicEvaluationKeyMaterialTransportHashes
    >,
): ProtocolHash =>
    deriveProtocolHash('PublicEvaluationKeyMaterialRoot', {
        objectType: 'PublicEvaluationKeyMaterialReference',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        assemblyStatus: publicEvaluationKeyAssemblyStatus,
        materialEncoding: publicEvaluationKeyTransportMaterialEncoding,
        materialSource: publicEvaluationKeyMaterialSource,
        ceremonyId: evaluationKeys.ceremonyId,
        manifestHash: evaluationKeys.manifestHash,
        rosterHash: evaluationKeys.rosterHash,
        setupProfileHash: evaluationKeys.setupProfileHash,
        qShareHash: evaluationKeys.qShareHash,
        carryAwareVssShareRelationProfileHash:
            evaluationKeys.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: evaluationKeys.commitmentProfileHash,
        setupEpoch: evaluationKeys.setupEpoch,
        evaluatorKeyScheduleRoot: evaluationKeys.evaluatorKeyScheduleRoot,
        sameSecretProofFamilyBindingRoot:
            evaluationKeys.sameSecretProofFamilyBindingRoot,
        publicKeyShareLnpProofSetRoot:
            evaluationKeys.publicKeyShareLnpProofSetRoot,
        relinearizationKeyShareRoundsRoot:
            evaluationKeys.relinearizationKeyShareRoundsRoot,
        requiredGaloisSetHash: evaluationKeys.requiredGaloisSetHash,
        expectedMaterialManifest,
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        chunkCount: transportHashes.chunkHashes.length,
        totalByteLength: transportHashes.totalByteLength,
        fullObjectHash: transportHashes.fullObjectHash,
        chunkRoot: transportHashes.chunkRoot,
        chunkHashes: transportHashes.chunkHashes,
    });

const expectedPublicEvaluationKeyComponentMaterialRoots = (
    input: PublicEvaluationKeyMaterialTransportInput,
): ReadonlySet<ProtocolHash> => {
    const roots = new Set<ProtocolHash>();
    const collectRoot = (record: JsonRecord): void => {
        if (
            record.keySwitchMaterialEncoding !==
            evaluationKeyShareComponentMaterialEncoding
        ) {
            return;
        }
        const root = record.keySwitchComponentMaterialRoot;
        if (typeof root !== 'string') {
            throw new TypeError(
                'binary evaluation-key proof records must carry keySwitchComponentMaterialRoot.',
            );
        }
        assertProtocolHash(root, 'keySwitchComponentMaterialRoot');
        roots.add(root);
    };

    input.relinearizationKeyShareRounds.roundOneRecords.forEach((record) =>
        collectRoot(record),
    );
    input.relinearizationKeyShareRounds.roundTwoRecords.forEach((record) =>
        collectRoot(record),
    );
    input.galoisKeyShareBatches.forEach((batch) =>
        batch.galoisKeyShareProofs.forEach((proofRecord) =>
            collectRoot(proofRecord),
        ),
    );

    return roots;
};

const assertPublicEvaluationKeyComponentMaterialCoverage = (
    input: PublicEvaluationKeyMaterialTransportInput,
): void => {
    const expectedRoots =
        expectedPublicEvaluationKeyComponentMaterialRoots(input);
    const componentMaterials =
        input.transportedEvaluationKeyShareComponentMaterial
            ?.componentMaterials ?? [];
    if (expectedRoots.size === 0) {
        if (componentMaterials.length !== 0) {
            throw new Error(
                'transportedEvaluationKeyShareComponentMaterial must not be supplied when evaluation-key records do not use binary component material.',
            );
        }

        return;
    }
    if (componentMaterials.length === 0) {
        throw new Error(
            'transportedEvaluationKeyShareComponentMaterial is required for binary evaluation-key component material.',
        );
    }

    const suppliedRoots = new Set<ProtocolHash>();
    componentMaterials.forEach((componentMaterial, componentIndex) => {
        const materialRoot = componentMaterial.keySwitchComponentMaterialRoot;
        if (typeof materialRoot !== 'string') {
            throw new TypeError(
                `transportedEvaluationKeyShareComponentMaterial.componentMaterials.${String(componentIndex)}.keySwitchComponentMaterialRoot must be a protocol hash.`,
            );
        }
        assertProtocolHash(
            materialRoot,
            `transportedEvaluationKeyShareComponentMaterial.componentMaterials.${String(componentIndex)}.keySwitchComponentMaterialRoot`,
        );
        if (suppliedRoots.has(materialRoot)) {
            throw new Error(
                'transportedEvaluationKeyShareComponentMaterial contains duplicate key-switch component material roots.',
            );
        }
        suppliedRoots.add(materialRoot);
    });
    if (
        suppliedRoots.size !== expectedRoots.size ||
        [...expectedRoots].some(
            (expectedRoot) => !suppliedRoots.has(expectedRoot),
        )
    ) {
        throw new Error(
            'transportedEvaluationKeyShareComponentMaterial must cover every binary evaluation-key component material root.',
        );
    }
};

export function createPublicEvaluationKeySet(
    input: PublicEvaluationKeySetInput,
): PublicEvaluationKeySet {
    validateCommonInput(input);
    assertContextMatches(
        input.setupContext,
        input.relinearizationKeyShareRounds,
        'relinearizationKeyShareRounds',
    );
    if (
        input.relinearizationKeyShareRounds.evaluatorKeyScheduleRoot !==
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot ||
        input.relinearizationKeyShareRounds.sameSecretProofFamilyBindingRoot !==
            input.sameSecretProofFamilyBindingRoot ||
        input.relinearizationKeyShareRounds.publicKeyShareLnpProofSetRoot !==
            input.publicKeyShareLnpProofSetRoot
    ) {
        throw new Error(
            'relinearizationKeyShareRounds must match the accepted evaluation-key binding.',
        );
    }
    const roundOneAggregateRootByLevel = new Map(
        input.relinearizationKeyShareRounds.roundOneAggregateRoots.map(
            (entry) => [entry.level, entry.roundOneAggregateRoot] as const,
        ),
    );
    const roundOneSourceSquareAggregateRootByLevel = new Map(
        input.relinearizationKeyShareRounds.roundOneAggregateRoots.map(
            (entry) =>
                [entry.level, entry.roundOneSourceSquareAggregateRoot] as const,
        ),
    );
    const roundTwoAggregateRootByLevel = new Map(
        input.relinearizationKeyShareRounds.roundTwoAggregateRoots.map(
            (entry) => [entry.level, entry.roundTwoAggregateRoot] as const,
        ),
    );
    const roundTwoSourceSquareAggregateRootByLevel = new Map(
        input.relinearizationKeyShareRounds.roundTwoAggregateRoots.map(
            (entry) =>
                [entry.level, entry.roundTwoSourceSquareAggregateRoot] as const,
        ),
    );
    const relinearizationKeyRoots =
        input.evaluatorKeySchedule.relinearizationLevelSchedule.map(
            (scheduleEntry) => {
                const { level } = scheduleEntry;
                const roundOneAggregateRoot =
                    roundOneAggregateRootByLevel.get(level);
                const roundOneSourceSquareAggregateRoot =
                    roundOneSourceSquareAggregateRootByLevel.get(level);
                const roundTwoAggregateRoot =
                    roundTwoAggregateRootByLevel.get(level);
                const roundTwoSourceSquareAggregateRoot =
                    roundTwoSourceSquareAggregateRootByLevel.get(level);
                if (
                    roundOneAggregateRoot === undefined ||
                    roundOneSourceSquareAggregateRoot === undefined ||
                    roundTwoAggregateRoot === undefined ||
                    roundTwoSourceSquareAggregateRoot === undefined
                ) {
                    throw new Error(
                        'relinearizationKeyShareRounds is missing a scheduled aggregate root.',
                    );
                }
                const decompositionDigitCount = level + 1;
                const relinearizationKeyRoot = deriveProtocolHash(
                    'RelinearizationKeyRoot',
                    {
                        objectType: 'RelinearizationKeyAggregate',
                        objectVersion: 1,
                        setupProfileId: 'CollectiveBgvSetup-v1',
                        setupProofProfileId,
                        assemblyStatus: publicEvaluationKeyAssemblyStatus,
                        materialEncoding: publicEvaluationKeyMaterialEncoding,
                        materialSource: publicEvaluationKeyMaterialSource,
                        evaluatorKeyScheduleRoot:
                            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                        sameSecretProofFamilyBindingRoot:
                            input.sameSecretProofFamilyBindingRoot,
                        publicKeyShareLnpProofSetRoot:
                            input.publicKeyShareLnpProofSetRoot,
                        relinearizationKeyShareRoundsRoot:
                            input.relinearizationKeyShareRounds
                                .relinearizationKeyShareRoundsRoot,
                        level,
                        decompositionDigitCount,
                        rnsLimbCount: decompositionDigitCount,
                        roundOneAggregateRoot,
                        roundOneSourceSquareAggregateRoot,
                        roundTwoAggregateRoot,
                        roundTwoSourceSquareAggregateRoot,
                    },
                );

                return {
                    level,
                    decompositionDigitCount,
                    rnsLimbCount: decompositionDigitCount,
                    roundOneAggregateRoot,
                    roundOneSourceSquareAggregateRoot,
                    roundTwoAggregateRoot,
                    roundTwoSourceSquareAggregateRoot,
                    relinearizationKeyRoot,
                } satisfies RelinearizationKeyRootReference;
            },
        );

    const sortedGaloisBatches = [...input.galoisKeyShareBatches].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (sortedGaloisBatches.length !== input.participantCount) {
        throw new Error(
            'galoisKeyShareBatches must contain one batch per participant.',
        );
    }
    sortedGaloisBatches.forEach((batch, expectedRosterPosition) => {
        assertContextMatches(input.setupContext, batch, 'galoisKeyShareBatch');
        if (batch.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'galoisKeyShareBatches roster positions must be contiguous from zero.',
            );
        }
        if (
            batch.evaluatorKeyScheduleRoot !==
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot ||
            batch.sameSecretProofFamilyBindingRoot !==
                input.sameSecretProofFamilyBindingRoot ||
            batch.publicKeyShareLnpProofSetRoot !==
                input.publicKeyShareLnpProofSetRoot ||
            batch.requiredGaloisSetHash !==
                input.evaluatorKeySchedule.requiredGaloisSetHash
        ) {
            throw new Error(
                'galoisKeyShareBatches must match the accepted evaluation-key binding.',
            );
        }
    });
    const galoisKeyShareBatchRoots = sortedGaloisBatches.map((batch) => ({
        trusteeIdentity: batch.trusteeIdentity,
        trusteeRosterPosition: batch.trusteeRosterPosition,
        galoisKeyShareBatchRoot: batch.galoisKeyShareBatchRoot,
    })) satisfies GaloisKeyShareBatchRootReference[];
    const galoisKeyRoots =
        input.evaluatorKeySchedule.requiredGaloisKeySchedule.map(
            (scheduleEntry) => {
                const { rotation, level } = scheduleEntry;
                const decompositionDigitCount = level + 1;
                const contributingShareRoots = sortedGaloisBatches.map(
                    (batch) => {
                        const proof = batch.galoisKeyShareProofs.find(
                            (proofRecord) =>
                                proofRecord.rotation === rotation &&
                                proofRecord.level === level,
                        );
                        if (proof === undefined) {
                            throw new Error(
                                'galoisKeyShareBatches is missing a scheduled proof record.',
                            );
                        }

                        return {
                            trusteeIdentity: batch.trusteeIdentity,
                            trusteeRosterPosition: batch.trusteeRosterPosition,
                            galoisKeyShareRoot: proof.galoisKeyShareRoot,
                            galoisKeyShareProofRoot:
                                proof.galoisKeyShareProofRoot,
                        } satisfies GaloisKeyContributingShareRoot;
                    },
                );
                const galoisKeyRoot = deriveProtocolHash('RotationKeyRoot', {
                    objectType: 'GaloisKeyAggregate',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    assemblyStatus: publicEvaluationKeyAssemblyStatus,
                    materialEncoding: publicEvaluationKeyMaterialEncoding,
                    materialSource: publicEvaluationKeyMaterialSource,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    sameSecretProofFamilyBindingRoot:
                        input.sameSecretProofFamilyBindingRoot,
                    publicKeyShareLnpProofSetRoot:
                        input.publicKeyShareLnpProofSetRoot,
                    galoisKeyCrpRoot:
                        input.evaluatorKeySchedule.galoisKeyCrpRoot,
                    requiredGaloisSetHash:
                        input.evaluatorKeySchedule.requiredGaloisSetHash,
                    rotation,
                    level,
                    decompositionDigitCount,
                    rnsLimbCount: decompositionDigitCount,
                    contributingShareRoots,
                });

                return {
                    rotation,
                    level,
                    decompositionDigitCount,
                    rnsLimbCount: decompositionDigitCount,
                    galoisKeyRoot,
                    contributingShareRoots,
                } satisfies GaloisKeyRootReference;
            },
        );
    if (input.publicEvaluationKeyMaterialReference !== undefined) {
        const reference = input.publicEvaluationKeyMaterialReference;
        if (
            reference.publicEvaluationKeyMaterialEncoding !==
            publicEvaluationKeyTransportMaterialEncoding
        ) {
            throw new Error(
                'publicEvaluationKeyMaterialReference uses an unsupported material encoding.',
            );
        }
        assertProtocolHash(
            reference.publicEvaluationKeyMaterialRoot,
            'publicEvaluationKeyMaterialRoot',
        );
        assertProtocolHash(
            reference.publicEvaluationKeyMaterialFullObjectHash,
            'publicEvaluationKeyMaterialFullObjectHash',
        );
        assertProtocolHash(
            reference.publicEvaluationKeyMaterialChunkRoot,
            'publicEvaluationKeyMaterialChunkRoot',
        );
        assertPositiveSafeInteger(
            reference.publicEvaluationKeyMaterialChunkSizeBytes,
            'publicEvaluationKeyMaterialChunkSizeBytes',
        );
        assertPositiveSafeInteger(
            reference.publicEvaluationKeyMaterialChunkCount,
            'publicEvaluationKeyMaterialChunkCount',
        );
        assertPositiveSafeInteger(
            reference.publicEvaluationKeyMaterialTotalByteLength,
            'publicEvaluationKeyMaterialTotalByteLength',
        );
        if (
            reference.publicEvaluationKeyMaterialChunkHashes.length !==
            reference.publicEvaluationKeyMaterialChunkCount
        ) {
            throw new Error(
                'publicEvaluationKeyMaterialChunkHashes must match publicEvaluationKeyMaterialChunkCount.',
            );
        }
        reference.publicEvaluationKeyMaterialChunkHashes.forEach(
            (chunkHash, chunkIndex) => {
                assertProtocolHash(
                    chunkHash,
                    `publicEvaluationKeyMaterialChunkHashes[${chunkIndex}]`,
                );
            },
        );
    }

    const evaluationKeysWithoutHash = {
        objectType: 'PublicEvaluationKeySet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        assemblyStatus: publicEvaluationKeyAssemblyStatus,
        materialEncoding: publicEvaluationKeyMaterialEncoding,
        materialSource: publicEvaluationKeyMaterialSource,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        evaluatorKeyScheduleRoot:
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretProofFamilyBindingRoot,
        publicKeyShareLnpProofSetRoot: input.publicKeyShareLnpProofSetRoot,
        relinearizationKeyShareRoundsRoot:
            input.relinearizationKeyShareRounds
                .relinearizationKeyShareRoundsRoot,
        relinearizationLevelSchedule:
            input.evaluatorKeySchedule.relinearizationLevelSchedule,
        relinearizationKeyRoots,
        requiredGaloisSetHash: input.evaluatorKeySchedule.requiredGaloisSetHash,
        requiredGaloisKeySchedule:
            input.evaluatorKeySchedule.requiredGaloisKeySchedule,
        galoisKeyShareBatchRoots,
        galoisKeyRoots,
        genericKeySwitchKeyRoots: [],
        rawKeyBytesEmbedded: false,
        verifierGeneratedKeyMaterial: false,
        ...(input.publicEvaluationKeyMaterialReference ?? {}),
    } as const satisfies Omit<PublicEvaluationKeySet, 'evaluationKeySetHash'>;

    return {
        ...evaluationKeysWithoutHash,
        evaluationKeySetHash: deriveProtocolHash(
            'EvaluationKeySetHash',
            evaluationKeysWithoutHash,
        ),
    } satisfies PublicEvaluationKeySet;
}

export const createBinaryChunkedPublicEvaluationKeyMaterialTransport = (
    input: PublicEvaluationKeyMaterialTransportInput,
): BinaryChunkedPublicEvaluationKeyMaterialTransport => {
    const evaluationKeysWithoutMaterialReference =
        createPublicEvaluationKeySet(input);
    const manifest = publicEvaluationKeyMaterialManifest(
        input,
        evaluationKeysWithoutMaterialReference,
    );
    const materialBytes = encodePublicEvaluationKeyMaterialManifest(manifest);
    const chunks = publicEvaluationKeyMaterialChunks(materialBytes);
    const transportHashes = publicEvaluationKeyMaterialTransportHashes(chunks);
    const publicEvaluationKeyMaterialRoot =
        publicEvaluationKeyMaterialReferenceRoot(
            evaluationKeysWithoutMaterialReference,
            manifest,
            transportHashes,
        );
    const publicEvaluationKeyMaterialReference = {
        publicEvaluationKeyMaterialEncoding:
            publicEvaluationKeyTransportMaterialEncoding,
        publicEvaluationKeyMaterialRoot,
        publicEvaluationKeyMaterialChunkSizeBytes:
            setupProofTransportChunkSizeBytes,
        publicEvaluationKeyMaterialChunkCount:
            transportHashes.chunkHashes.length,
        publicEvaluationKeyMaterialTotalByteLength:
            transportHashes.totalByteLength,
        publicEvaluationKeyMaterialFullObjectHash:
            transportHashes.fullObjectHash,
        publicEvaluationKeyMaterialChunkRoot: transportHashes.chunkRoot,
        publicEvaluationKeyMaterialChunkHashes: transportHashes.chunkHashes,
    } satisfies PublicEvaluationKeyMaterialReference;
    const evaluationKeys = createPublicEvaluationKeySet({
        ...input,
        publicEvaluationKeyMaterialReference,
    });
    assertPublicEvaluationKeyComponentMaterialCoverage(input);
    const transportedPublicEvaluationKeyMaterial = {
        objectType: publicEvaluationKeyMaterialTransportSetObjectType,
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        materialEncoding: publicEvaluationKeyTransportMaterialEncoding,
        publicEvaluationKeyMaterials: [
            {
                objectType: publicEvaluationKeyMaterialTransportObjectType,
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                materialEncoding: publicEvaluationKeyTransportMaterialEncoding,
                ...contextFields(input.setupContext),
                evaluationKeySetHash: evaluationKeys.evaluationKeySetHash,
                publicEvaluationKeyMaterialRoot,
                chunkSizeBytes: setupProofTransportChunkSizeBytes,
                chunkCount: transportHashes.chunkHashes.length,
                totalByteLength: transportHashes.totalByteLength,
                fullObjectHash: transportHashes.fullObjectHash,
                chunkRoot: transportHashes.chunkRoot,
                chunkHashes: transportHashes.chunkHashes,
                chunks: chunks.map((chunk, chunkIndex) => ({
                    chunkIndex,
                    bytesHex: bytesToHex(chunk),
                })),
            },
        ],
    } satisfies TransportedPublicEvaluationKeyMaterialSet;

    return {
        evaluationKeys,
        publicEvaluationKeyMaterialReference,
        transportedPublicEvaluationKeyMaterial,
    };
};
