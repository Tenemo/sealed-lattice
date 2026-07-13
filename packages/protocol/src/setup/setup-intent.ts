import type {
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

export type CollectiveBgvSetupIntentTrusteeRegistration = Readonly<{
    readonly objectType: 'CollectiveBgvSetupIntentTrusteeRegistration';
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signingPublicKeyHash: ProtocolHash;
    readonly privateVssMailboxPublicKeyHash: ProtocolHash;
    readonly signatureEnvelope: ProtocolSignatureEnvelope;
}>;

export type CollectiveBgvSetupIntent = Readonly<{
    readonly objectType: 'CollectiveBgvSetupIntent';
    readonly trusteeRegistrations: readonly CollectiveBgvSetupIntentTrusteeRegistration[];
}>;
