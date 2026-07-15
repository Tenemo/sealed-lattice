import type { ProtocolHash } from './protocol-hash.js';

export type SignedObjectType =
    | 'CommonRandomnessCommit'
    | 'CommonRandomnessReveal'
    | 'CollectiveBgvSetupIntentTrusteeRegistration'
    | 'VssShareAcceptance'
    | 'VssShareComplaint';

export type CanonicalSignedRootObject = {
    readonly objectType: SignedObjectType;
    readonly objectRoot: ProtocolHash;
};

export type ProtocolSignatureEnvelope = {
    readonly publicKeyHash: ProtocolHash;
    readonly publicKeyBytesHex: string;
    readonly signedRoot: CanonicalSignedRootObject;
    readonly signatureBytesHex: string;
};
