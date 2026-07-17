import type { ProtocolHash } from '@sealed-lattice/types';

type RelinearizationLevelScheduleEntry = Readonly<{
    readonly level: number;
}>;

export type RequiredGaloisKeyScheduleEntry = Readonly<{
    readonly rotation: number;
    readonly level: number;
}>;

export type EvaluatorKeySchedule = Readonly<{
    readonly objectType: 'EvaluatorKeySchedule';
    readonly setupContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly publicKeyShareSetRoot: ProtocolHash;
    readonly relinearizationLevelSchedule: readonly RelinearizationLevelScheduleEntry[];
    readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
}>;
