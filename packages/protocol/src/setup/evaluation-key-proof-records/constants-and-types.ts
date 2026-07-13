import type { ProtocolHash } from '@sealed-lattice/types';

import {
    type EvaluatorKeySchedule,
    type RelinearizationLevelScheduleEntry,
    type RequiredGaloisKeyScheduleEntry,
} from '../evaluator-key-schedule.js';
import type {
    CanonicalGeneratedSetupProofMaterial,
    CanonicalProofMaterialChunkPull,
} from '../setup-proof-material-transport.js';
import type { VssSameSecretBridgeStatementSet } from '../vss-commitments/linkage-and-bridge.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

export type JsonRecord = Record<string, unknown>;
export type EvaluationKeyShareProofFamily =
    | 'relinearization-key-share'
    | 'galois-key-share';

export const trusteeEvaluationKeyProofFamily = 'trustee-evaluation-key';
export const publicEvaluationKeyMaterialTransportSetObjectType =
    'SetupTransportedPublicEvaluationKeyMaterialSet';
export const publicEvaluationKeyMaterialTransportObjectType =
    'SetupTransportedPublicEvaluationKeyMaterial';
export const evaluationKeyShareProofTransportSetObjectType =
    'SetupTransportedEvaluationKeyShareProofMaterialSet';
export const evaluationKeyShareProofTransportObjectType =
    'SetupTransportedEvaluationKeyShareProofMaterial';
export const evaluationKeyShareComponentMaterialTransportSetObjectType =
    'SetupTransportedEvaluationKeyShareComponentMaterialSet';
export const evaluationKeyShareComponentMaterialTransportObjectType =
    'SetupTransportedEvaluationKeyShareComponentMaterial';
export const evaluationKeyShareComponentMaterialEncoding =
    'binary-chunked-key-switch-component-vectors';
export const evaluationKeyShareComponentVectorHashDomain =
    'sealed-lattice-bgv-rns/evaluation-key-share-component-vector';
export const evaluationKeyShareComponentMaterialMagic = new Uint8Array([
    0x53, 0x4c, 0x45, 0x4b, 0x43, 0x4d, 0x56, 0x31,
]);
export const publicEvaluationKeyMaterialMagic = new Uint8Array([
    0x53, 0x4c, 0x45, 0x4b, 0x50, 0x4d, 0x56, 0x31,
]);
export const textEncoder = new TextEncoder();

export type EvaluationKeyTrusteeReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
}>;

export type KeySwitchComponentVectorEntry = Readonly<JsonRecord>;

export type EvaluationKeyShareEmbeddedKeySwitchComponentMaterial = Readonly<{
    readonly keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors';
    readonly keySwitchComponentVectors: readonly KeySwitchComponentVectorEntry[];
}>;

export type EvaluationKeyShareTransportedKeySwitchComponentMaterial = Readonly<{
    readonly keySwitchMaterialEncoding: typeof evaluationKeyShareComponentMaterialEncoding;
    readonly keySwitchComponentMaterialRoot: ProtocolHash;
}>;

export type EvaluationKeyShareKeySwitchComponentMaterial =
    | EvaluationKeyShareEmbeddedKeySwitchComponentMaterial
    | EvaluationKeyShareTransportedKeySwitchComponentMaterial;

// The public key-switch component material one trustee publishes for one
// scheduled key: the runtime key share itself, either embedded as canonical
// component vector entries or referenced as binary chunked transport.
export type EvaluationKeyShareMaterial = Readonly<{
    readonly keySwitchDomain: string;
    readonly keySwitchSeedHex: string;
    readonly ringDegree: number;
    readonly keySwitchComponentVectorRoot: ProtocolHash;
}> &
    EvaluationKeyShareKeySwitchComponentMaterial;

export type RelinearizationRoundOneContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly roundOneShareRoot: ProtocolHash;
    readonly shareMaterial: EvaluationKeyShareMaterial;
}>;

export type RelinearizationRoundTwoContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly roundTwoShareRoot: ProtocolHash;
    readonly shareMaterial: EvaluationKeyShareMaterial;
}>;

export type GaloisKeyShareContribution = Readonly<{
    readonly rotation: number;
    readonly level: number;
    readonly galoisKeyShareRoot: ProtocolHash;
    readonly shareMaterial: EvaluationKeyShareMaterial;
}>;

export type GaloisKeyShareBatchContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly galoisKeyShares: readonly GaloisKeyShareContribution[];
}>;

export type RelinearizationKeyShareRoundOneRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'RelinearizationKeyShareRoundOne';
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly level: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly keySwitchDomain: string;
        readonly keySwitchSeedHex: string;
        readonly ringDegree: number;
        readonly keySwitchComponentVectorRoot: ProtocolHash;
        readonly roundOneShareRoot: ProtocolHash;
        readonly roundOneRecordRoot: ProtocolHash;
    } & EvaluationKeyShareKeySwitchComponentMaterial
>;

export type RelinearizationKeyShareRoundTwoRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'RelinearizationKeyShareRoundTwo';
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly level: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly keySwitchDomain: string;
        readonly keySwitchSeedHex: string;
        readonly ringDegree: number;
        readonly keySwitchComponentVectorRoot: ProtocolHash;
        readonly roundOneShareRoot: ProtocolHash;
        readonly roundOneRecordRoot: ProtocolHash;
        readonly roundOneAggregateRoot: ProtocolHash;
        readonly roundTwoShareRoot: ProtocolHash;
        readonly roundTwoRecordRoot: ProtocolHash;
    } & EvaluationKeyShareKeySwitchComponentMaterial
>;

export type RelinearizationKeyShareRounds = Readonly<
    JsonRecord & {
        readonly objectType: 'RelinearizationKeyShareRounds';
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly relinearizationLevelSchedule: readonly RelinearizationLevelScheduleEntry[];
        readonly roundOneAggregateRoots: readonly {
            readonly level: number;
            readonly roundOneAggregateRoot: ProtocolHash;
        }[];
        readonly roundOneRecords: readonly RelinearizationKeyShareRoundOneRecord[];
        readonly roundTwoAggregateRoots: readonly {
            readonly level: number;
            readonly roundTwoAggregateRoot: ProtocolHash;
        }[];
        readonly roundTwoRecords: readonly RelinearizationKeyShareRoundTwoRecord[];
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
    }
>;

export type GaloisKeyShareMaterialRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'GaloisKeyShareMaterial';
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly rotation: number;
        readonly level: number;
        readonly galoisKeyShareRoot: ProtocolHash;
        readonly keySwitchDomain: string;
        readonly keySwitchSeedHex: string;
        readonly ringDegree: number;
        readonly keySwitchComponentVectorRoot: ProtocolHash;
    } & EvaluationKeyShareKeySwitchComponentMaterial
>;

export type GaloisKeyShareBatch = Readonly<
    JsonRecord & {
        readonly objectType: 'GaloisKeyShareBatch';
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly galoisKeyCrpRoot: ProtocolHash;
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
        readonly galoisKeyShareMaterialRecords: readonly GaloisKeyShareMaterialRecord[];
        readonly galoisKeyShareBatchRoot: ProtocolHash;
    }
>;

export type TrusteeEvaluationKeyCanonicalProofReference = Readonly<{
    readonly proofMaterialRoot: ProtocolHash;
}>;

export type TrusteeEvaluationKeyProofRecord = Readonly<
    JsonRecord &
        TrusteeEvaluationKeyCanonicalProofReference & {
            readonly objectType: 'TrusteeEvaluationKeyProof';
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly statementHash: ProtocolHash;
            readonly proofBytesHash: ProtocolHash;
            readonly trusteeEvaluationKeyProofRoot: ProtocolHash;
        }
>;

export type TrusteeEvaluationKeyProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'TrusteeEvaluationKeyProofSet';
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly galoisKeyCrpRoot: ProtocolHash;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
        readonly galoisKeyShareBatchRoots: readonly {
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly galoisKeyShareBatchRoot: ProtocolHash;
        }[];
        readonly proofRecords: readonly TrusteeEvaluationKeyProofRecord[];
        readonly trusteeEvaluationKeyProofSetRoot: ProtocolHash;
    }
>;

// Statement key descriptors for the kernel trustee evaluation-key proof
// commands: relinearization round-one and round-two keys plus Galois rotation
// keys, each with the full public component-b material. The round-two keys
// additionally carry the recomputed public round-one aggregate diagonal.
export type TrusteeEvaluationKeyStatementKey = Readonly<{
    readonly proofFamily:
        | 'relinearization-round-one'
        | 'relinearization-round-two'
        | 'galois-rotation';
    readonly rotation?: number;
    readonly level: number;
    readonly keySwitchDomain: string;
    readonly keySwitchSeedHex: string;
    readonly componentBByDigit: readonly (readonly (readonly number[])[])[];
    readonly roundOneAggregateDiagonal?: readonly (readonly number[])[];
}>;

export type TrusteeEvaluationKeyStatementContext = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupEpoch: string;
    readonly requiredGaloisSetHash: ProtocolHash;
    readonly evaluatorKeyScheduleRoot: ProtocolHash;
    readonly sourceConstantCoefficientCommitmentRoot: ProtocolHash;
}>;

export type TrusteeEvaluationKeyProofGenerationOutput = Readonly<{
    readonly statementHash: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
    readonly canonicalMaterial: CanonicalGeneratedSetupProofMaterial;
}>;

export type TrusteeEvaluationKeyProofGenerator = (
    input: Readonly<{
        readonly context: TrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly keys: readonly TrusteeEvaluationKeyStatementKey[];
        readonly sameSecretLinkage: Readonly<{
            readonly publicMatrixSeedHash: ProtocolHash;
            readonly commitments: readonly JsonRecord[];
        }>;
        readonly secretCoefficients: readonly number[];
        readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
        readonly negativeIndicatorCoefficients: readonly number[];
        readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }>,
) => Promise<TrusteeEvaluationKeyProofGenerationOutput>;

// One trustee's private witness for its batched evaluation-key statement: the
// shared ternary secret, per-key centered-binomial errors in statement key
// order (relinearization round-one levels ascending, round-two levels
// ascending, then the frozen Galois schedule), the binary negative-coefficient
// indicator, and the five ternary opening-randomness columns for the original
// source-limb-zero BDLOP constant commitment the schedule opens.
export type TrusteeEvaluationKeyWitnessInput = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly secretCoefficients: readonly number[];
    readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
    readonly negativeIndicatorCoefficients: readonly number[];
    readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
}>;

export type RelinearizationKeyRootReference = Readonly<{
    readonly level: number;
    readonly roundOneAggregateRoot: ProtocolHash;
    readonly roundTwoAggregateRoot: ProtocolHash;
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
}>;

export type GaloisKeyRootReference = Readonly<{
    readonly rotation: number;
    readonly level: number;
    readonly galoisKeyRoot: ProtocolHash;
    readonly contributingShareRoots: readonly GaloisKeyContributingShareRoot[];
}>;

export type PublicEvaluationKeySet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicEvaluationKeySet';
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
        readonly relinearizationKeyRoots: readonly RelinearizationKeyRootReference[];
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly galoisKeyShareBatchRoots: readonly GaloisKeyShareBatchRootReference[];
        readonly galoisKeyRoots: readonly GaloisKeyRootReference[];
        readonly publicEvaluationKeyMaterialRoot?: ProtocolHash;
        readonly evaluationKeySetHash: ProtocolHash;
    }
>;

export type TransportedEvaluationKeyShareProofMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof evaluationKeyShareProofTransportSetObjectType;
        readonly proofFamily: typeof trusteeEvaluationKeyProofFamily;
        readonly proofMaterials: readonly Readonly<
            JsonRecord & {
                readonly objectType: typeof evaluationKeyShareProofTransportObjectType;
                readonly proofFamily: typeof trusteeEvaluationKeyProofFamily;
                readonly proofMaterialRoot: ProtocolHash;
                readonly descriptorBytes: Uint8Array;
            }
        >[];
    }
>;

export type TransportedEvaluationKeyShareComponentMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof evaluationKeyShareComponentMaterialTransportSetObjectType;
        readonly componentMaterials: readonly JsonRecord[];
    }
>;

// A repeatable bounded source for one transported evaluation-key component
// material. The canonical descriptor remains on the component sidecar while
// the source supplies one requested chunk at a time.
export type EvaluationKeyShareComponentMaterialChunkSource = Readonly<{
    readonly keySwitchComponentMaterialRoot: ProtocolHash;
    readonly pullChunk: CanonicalProofMaterialChunkPull;
}>;

export type EvaluationKeyShareComponentMaterialWriter = (
    input: Readonly<{
        readonly keySwitchComponentMaterialRoot: ProtocolHash;
        readonly proofFamily: EvaluationKeyShareProofFamily;
        readonly totalByteLength: number;
        readonly pullChunk: CanonicalProofMaterialChunkPull;
    }>,
) => Promise<Uint8Array>;

// A repeatable bounded source for one canonical public evaluation-key
// material stream. The descriptor remains on the transported reference while
// the source is supplied separately to verification.
export type PublicEvaluationKeyMaterialChunkSource = Readonly<{
    readonly publicEvaluationKeyMaterialRoot: ProtocolHash;
    readonly pullChunk: CanonicalProofMaterialChunkPull;
}>;

export type PublicEvaluationKeyMaterialWriter = (
    input: Readonly<{
        readonly publicEvaluationKeyMaterialRoot: ProtocolHash;
        readonly totalByteLength: number;
        readonly pullChunk: CanonicalProofMaterialChunkPull;
    }>,
) => Promise<Uint8Array>;

export type TransportedPublicEvaluationKeyMaterial = Readonly<
    JsonRecord & {
        readonly objectType: typeof publicEvaluationKeyMaterialTransportObjectType;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupParametersHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly evaluationKeySetHash: ProtocolHash;
        readonly publicEvaluationKeyMaterialRoot: ProtocolHash;
        readonly descriptorBytes: Uint8Array;
    }
>;

export type TransportedPublicEvaluationKeyMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: typeof publicEvaluationKeyMaterialTransportSetObjectType;
        readonly publicEvaluationKeyMaterials: readonly TransportedPublicEvaluationKeyMaterial[];
        readonly componentMaterials?: readonly JsonRecord[];
    }
>;

export type BinaryChunkedPublicEvaluationKeyMaterialTransport = Readonly<{
    readonly evaluationKeys: PublicEvaluationKeySet;
    readonly transportedPublicEvaluationKeyMaterial: TransportedPublicEvaluationKeyMaterialSet;
}>;

export type BinaryChunkedEvaluationKeyShareMaterialTransport = Readonly<{
    readonly relinearizationRoundOneContributions: readonly RelinearizationRoundOneContribution[];
    readonly relinearizationRoundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    readonly galoisKeyShareBatchContributions: readonly GaloisKeyShareBatchContribution[];
    readonly transportedEvaluationKeyShareComponentMaterial: TransportedEvaluationKeyShareComponentMaterialSet;
}>;

export type EvaluationKeyShareMaterialTransportInput = Readonly<{
    readonly trusteeReferences: readonly EvaluationKeyTrusteeReference[];
    readonly relinearizationRoundOneContributions: readonly RelinearizationRoundOneContribution[];
    readonly relinearizationRoundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    readonly galoisKeyShareBatchContributions: readonly GaloisKeyShareBatchContribution[];
    readonly writeEvaluationKeyShareComponentMaterial: EvaluationKeyShareComponentMaterialWriter;
}>;

export type EvaluationKeyProofCommonInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly evaluatorKeySchedule: EvaluatorKeySchedule;
    readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
    readonly trusteeReferences: readonly EvaluationKeyTrusteeReference[];
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

export type TrusteeEvaluationKeyProofsInput = EvaluationKeyProofCommonInput &
    Readonly<{
        readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
        readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
        readonly trusteeWitnesses: readonly TrusteeEvaluationKeyWitnessInput[];
        readonly sameSecretBridgeStatementSet: VssSameSecretBridgeStatementSet;
        readonly trusteeEvaluationKeyProofGenerator: TrusteeEvaluationKeyProofGenerator;
        readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
        // Bounded component sources supplied out of band so the prover can
        // reconstruct transported public component vectors without retaining a
        // second whole-material byte representation.
        readonly evaluationKeyShareComponentMaterialChunkSources?: readonly EvaluationKeyShareComponentMaterialChunkSource[];
    }>;

export type PublicEvaluationKeySetInput = EvaluationKeyProofCommonInput &
    Readonly<{
        readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
        readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
        readonly publicEvaluationKeyMaterialRoot?: ProtocolHash;
    }>;

export type PublicEvaluationKeyMaterialTransportInput = Omit<
    PublicEvaluationKeySetInput,
    'publicEvaluationKeyMaterialRoot'
> &
    Readonly<{
        readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
        readonly writePublicEvaluationKeyMaterial: PublicEvaluationKeyMaterialWriter;
    }>;
