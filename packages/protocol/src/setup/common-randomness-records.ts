import type {
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

type CommonRandomnessParticipantRecord = Readonly<{
    readonly rosterPosition: number;
    readonly signatureEnvelope: ProtocolSignatureEnvelope;
}>;

type CommonRandomnessReveal = Readonly<
    CommonRandomnessParticipantRecord & {
        readonly objectType: 'CommonRandomnessReveal';
        readonly revealHex: string;
    }
>;

type CommonRandomnessCommit = Readonly<
    CommonRandomnessParticipantRecord & {
        readonly objectType: 'CommonRandomnessCommit';
        readonly revealHash: ProtocolHash;
    }
>;

export type SetupCommonRandomness = Readonly<{
    readonly objectType: 'SetupCommonRandomness';
    readonly commitRecords: readonly CommonRandomnessCommit[];
    readonly revealRecords: readonly CommonRandomnessReveal[];
    readonly publicMatrixSeedHash: ProtocolHash;
}>;
