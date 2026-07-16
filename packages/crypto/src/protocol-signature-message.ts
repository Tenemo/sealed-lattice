import type { ProtocolSignatureEnvelope } from '@sealed-lattice/types';

import { canonicalJson } from './canonical-json.js';

const protocolSignatureMessageDomain =
    'sealed-lattice/protocol-signature' as const;
const textEncoder = new TextEncoder();

export const encodeCanonicalProtocolSignatureMessage = (
    signature: Pick<ProtocolSignatureEnvelope, 'publicKeyHash' | 'signedRoot'>,
): Uint8Array =>
    textEncoder.encode(
        canonicalJson({
            messageDomain: protocolSignatureMessageDomain,
            publicKeyHash: signature.publicKeyHash,
            signedRoot: signature.signedRoot,
        }),
    );
