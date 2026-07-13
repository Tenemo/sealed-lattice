import type {
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

import type { JsonRecord } from './common-fields.js';

type CommonRandomnessContextFields = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
}>;

type CommonRandomnessReveal = Readonly<
    JsonRecord &
        CommonRandomnessContextFields & {
            readonly objectType: 'CommonRandomnessReveal';
            readonly trusteeIdentity: string;
            readonly rosterPosition: number;
            readonly recoveryEpoch: number;
            readonly deviceEpoch: number;
            readonly revealHex: string;
            readonly signatureEnvelope: ProtocolSignatureEnvelope;
        }
>;

type CommonRandomnessCommit = Readonly<
    JsonRecord &
        CommonRandomnessContextFields & {
            readonly objectType: 'CommonRandomnessCommit';
            readonly trusteeIdentity: string;
            readonly rosterPosition: number;
            readonly recoveryEpoch: number;
            readonly deviceEpoch: number;
            readonly revealHash: ProtocolHash;
            readonly signatureEnvelope: ProtocolSignatureEnvelope;
        }
>;

export type SetupCommonRandomness = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupCommonRandomness';
        readonly commitRecords: readonly CommonRandomnessCommit[];
        readonly revealRecords: readonly CommonRandomnessReveal[];
        readonly publicMatrixSeedHash: ProtocolHash;
    }
>;
