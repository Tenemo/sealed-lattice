import type { ProtocolHash } from './protocol-hash.js';

/** Setup object type that still uses the accepted-setup JSON signature envelope. */
export type SignedObjectType =
    | 'CommonRandomnessCommit'
    | 'CommonRandomnessReveal'
    | 'CollectiveBgvSetupIntentTrusteeRegistration'
    | 'VssShareAcceptance'
    | 'VssShareComplaint';

/** Role asserted by an accepted-setup signature envelope. */
export type SignerRole = 'Trustee';

/** Canonical root object covered by a protocol signature. */
export type CanonicalSignedRootObject = {
    readonly objectType: SignedObjectType;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly objectRoot: ProtocolHash;
    readonly signerRole: SignerRole;
    readonly signerIdentity: string;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly contextHash: ProtocolHash;
};

/** Signature envelope attached to signed protocol objects. */
export type ProtocolSignatureEnvelope = {
    readonly publicKeyHash: ProtocolHash;
    readonly publicKeyBytesHex: string;
    readonly signedRoot: CanonicalSignedRootObject;
    readonly signatureBytesHex: string;
};
