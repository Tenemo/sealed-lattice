import type { ProtocolHash } from './protocol-hash.js';

export type BgvTargetDecryptionShareProofMaterial = Readonly<
    Record<string, unknown> & {
        readonly objectType: 'BgvTargetDecryptionShareProofMaterial';
        readonly proofBytesHash: ProtocolHash;
    }
>;
