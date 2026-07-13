import type {
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

import type { JsonRecord } from './common-fields.js';

export type SetupPhaseParticipantObject = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupPhaseParticipantObject';
        readonly phaseId: string;
        readonly trusteeIdentity: string;
        readonly rosterPosition: number;
        readonly recoveryEpoch: number;
        readonly deviceEpoch: number;
        readonly signingPublicKeyHash: ProtocolHash;
        readonly privateVssMailboxPublicKeyHash?: ProtocolHash;
        readonly phaseObjectRoot: ProtocolHash;
        readonly signatureEnvelope: ProtocolSignatureEnvelope;
    }
>;

export type SetupPhaseRecord = Readonly<
    JsonRecord & {
        readonly phaseId: string;
        readonly previousPhaseRoot: ProtocolHash | null;
        readonly participantPhaseObjects: readonly SetupPhaseParticipantObject[];
        readonly phaseRoot: ProtocolHash;
    }
>;
