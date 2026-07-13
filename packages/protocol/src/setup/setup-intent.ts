import type {
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

export type CollectiveBgvSetupIntentTrusteeRegistration = Readonly<{
    readonly objectType: 'CollectiveBgvSetupIntentTrusteeRegistration';
    readonly privateVssMailboxPublicKeyHash: ProtocolHash;
    readonly signatureEnvelope: ProtocolSignatureEnvelope;
}>;

export type CollectiveBgvSetupIntent = Readonly<{
    readonly objectType: 'CollectiveBgvSetupIntent';
    readonly trusteeRegistrations: readonly CollectiveBgvSetupIntentTrusteeRegistration[];
}>;
