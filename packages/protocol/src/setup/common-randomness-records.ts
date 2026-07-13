import type {
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

import type { JsonRecord } from './common-fields.js';

type CommonRandomnessReveal = Readonly<
    JsonRecord & {
        readonly objectType: 'CommonRandomnessReveal';
        readonly rosterPosition: number;
        readonly revealHex: string;
        readonly signatureEnvelope: ProtocolSignatureEnvelope;
    }
>;

type CommonRandomnessCommit = Readonly<
    JsonRecord & {
        readonly objectType: 'CommonRandomnessCommit';
        readonly rosterPosition: number;
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
