import type { ProtocolHash } from '@sealed-lattice/types';

import type { EvaluatorKeySchedule } from '../evaluator-key-schedule.js';
import type {
    CanonicalProofMaterialChunkPull,
    SetupProofMaterialStream,
    SetupProofMaterialStreamSet,
} from '../setup-proof-material-transport.js';
import type { SetupCommitmentValue } from '../vss-coefficient-commitments.js';
import type { VssSameSecretBridgeStatementSet } from '../vss-commitments/linkage-and-bridge.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

export type EvaluationKeyShareProofFamily =
    | 'relinearization-key-share'
    | 'galois-key-share';

export const evaluationKeyShareComponentMaterialMagic = new Uint8Array([
    0x53, 0x4c, 0x45, 0x4b, 0x43, 0x4d, 0x56, 0x32,
]);
export type EvaluationKeyTrusteeReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
}>;

export type RelinearizationRoundOneContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly keySwitchComponentMaterialRoot: ProtocolHash;
}>;

export type RelinearizationRoundTwoContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly keySwitchComponentMaterialRoot: ProtocolHash;
}>;

type GaloisKeyShareContribution = Readonly<{
    readonly rotation: number;
    readonly level: number;
    readonly keySwitchComponentMaterialRoot: ProtocolHash;
}>;

export type GaloisKeyShareBatchContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly galoisKeyShares: readonly GaloisKeyShareContribution[];
}>;

export type RelinearizationKeyShareRounds = Readonly<{
    readonly objectType: 'RelinearizationKeyShareRounds';
    readonly roundOneKeySwitchComponentMaterialRoots: readonly ProtocolHash[];
    readonly roundTwoKeySwitchComponentMaterialRoots: readonly ProtocolHash[];
}>;

export type GaloisKeyShareBatch = Readonly<{
    readonly objectType: 'GaloisKeyShareBatch';
    readonly keySwitchComponentMaterialRoots: readonly ProtocolHash[];
}>;

export type TrusteeEvaluationKeyProofSet = Readonly<{
    readonly objectType: 'TrusteeEvaluationKeyProofSet';
    readonly proofBytesHashes: readonly ProtocolHash[];
}>;

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
    readonly componentMaterialBytesHex: string;
    readonly roundOneAggregateDiagonal?: readonly (readonly number[])[];
}>;

type TrusteeEvaluationKeyStatementContext = Readonly<{
    readonly setupContextHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly evaluatorKeyScheduleRoot: ProtocolHash;
}>;

type TrusteeEvaluationKeyProofGenerationOutput = Readonly<{
    readonly proofBytesHash: ProtocolHash;
    readonly proofMaterialStream: SetupProofMaterialStream;
}>;

export type TrusteeEvaluationKeyProofGenerator = (
    input: Readonly<{
        readonly context: TrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly keys: readonly TrusteeEvaluationKeyStatementKey[];
        readonly sameSecretLinkage: Readonly<{
            readonly publicMatrixSeedHash: ProtocolHash;
            readonly commitments: readonly SetupCommitmentValue[];
        }>;
        readonly secretCoefficients: readonly number[];
        readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
        readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
        readonly proofRandomnessSeedHex: string;
    }>,
) => Promise<TrusteeEvaluationKeyProofGenerationOutput>;

export type TrusteeEvaluationKeyWitnessInput = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly secretCoefficients: readonly number[];
    readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
    readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
}>;

export type TransportedEvaluationKeyShareProofMaterialSet =
    SetupProofMaterialStreamSet;

export type EvaluationKeyShareComponentMaterialStream = Readonly<{
    readonly descriptorBytes: Uint8Array;
    readonly pullChunk: CanonicalProofMaterialChunkPull;
}>;

export type EvaluationKeyShareComponentMaterialWriter = (
    input: Readonly<{
        readonly keySwitchComponentMaterialRoot: ProtocolHash;
        readonly proofFamily: EvaluationKeyShareProofFamily;
        readonly totalByteLength: number;
        readonly pullChunk: CanonicalProofMaterialChunkPull;
    }>,
) => Promise<EvaluationKeyShareComponentMaterialStream>;

export type BinaryChunkedEvaluationKeyShareMaterialTransport = Readonly<{
    readonly relinearizationRoundOneContributions: readonly RelinearizationRoundOneContribution[];
    readonly relinearizationRoundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    readonly galoisKeyShareBatchContributions: readonly GaloisKeyShareBatchContribution[];
    readonly evaluationKeyShareComponentMaterialStreams: readonly EvaluationKeyShareComponentMaterialStream[];
}>;

export type EvaluationKeyShareMaterialTransportInput = Readonly<{
    readonly trusteeReferences: readonly EvaluationKeyTrusteeReference[];
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly evaluatorKeySchedule: EvaluatorKeySchedule;
    readonly relinearizationRoundOneContributions: readonly Readonly<{
        readonly trusteeRosterPosition: number;
        readonly level: number;
        readonly keySwitchComponentVectorsLittleEndianHexByDigitAndLimb: readonly string[];
    }>[];
    readonly relinearizationRoundTwoContributions: readonly Readonly<{
        readonly trusteeRosterPosition: number;
        readonly level: number;
        readonly keySwitchComponentVectorsLittleEndianHexByDigitAndLimb: readonly string[];
    }>[];
    readonly galoisKeyShareBatchContributions: readonly Readonly<{
        readonly trusteeRosterPosition: number;
        readonly galoisKeyShares: readonly Readonly<{
            readonly rotation: number;
            readonly level: number;
            readonly keySwitchComponentVectorsLittleEndianHexByDigitAndLimb: readonly string[];
        }>[];
    }>[];
    readonly writeEvaluationKeyShareComponentMaterial: EvaluationKeyShareComponentMaterialWriter;
}>;

export type EvaluationKeyProofCommonInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly evaluatorKeySchedule: EvaluatorKeySchedule;
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
        readonly evaluationKeyShareComponentMaterialStreams: readonly EvaluationKeyShareComponentMaterialStream[];
    }>;
