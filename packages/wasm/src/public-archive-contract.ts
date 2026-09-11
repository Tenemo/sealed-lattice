import type { ProtocolHash } from './foundation-contract.js';

export type ArchiveReference = Readonly<{
    identity: ProtocolHash;
    byteLength: number;
}>;

export type ArchiveRecord = Readonly<{
    context: ProtocolHash;
    purpose: string;
    dependencies: readonly ArchiveReference[];
    payload: Uint8Array;
}>;

export type ArchivePolicy = Readonly<{
    faultBound: number;
    verificationKeys: readonly Uint8Array[];
}>;

export type ArchiveAcknowledgement = Readonly<{
    replicaPosition: number;
    signature: Uint8Array;
}>;

export type PublicArchiveRuntime = Readonly<{
    encodeArchiveRecord(record: ArchiveRecord): Readonly<{
        reference: ArchiveReference;
        bytes: Uint8Array;
    }>;
    readArchiveRecord(
        context: ProtocolHash,
        reference: ArchiveReference,
        bytes: Uint8Array,
    ): ArchiveRecord;
    archiveReceiptMessage(
        policy: ArchivePolicy,
        context: ProtocolHash,
        root: ArchiveReference,
    ): Uint8Array;
    authenticateArchiveAcknowledgements(
        policy: ArchivePolicy,
        context: ProtocolHash,
        root: ArchiveReference,
        acknowledgements: readonly ArchiveAcknowledgement[],
    ): readonly number[];
}>;
