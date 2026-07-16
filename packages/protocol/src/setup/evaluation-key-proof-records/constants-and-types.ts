import type { ProtocolHash } from '@sealed-lattice/types';

import type { EvaluatorKeySchedule } from '../evaluator-key-schedule.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';
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
