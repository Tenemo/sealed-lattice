import { readFile } from 'node:fs/promises';
import path from 'node:path';

import type { ProtocolSignatureEnvelope } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { encodeCanonicalProtocolSignatureMessage } from '#packages/crypto/src/protocol-signature-message';

type ProtocolSignatureMessageVector = Readonly<{
    readonly canonicalMessageUtf8: string;
    readonly publicKeyHash: ProtocolSignatureEnvelope['publicKeyHash'];
    readonly signedRoot: ProtocolSignatureEnvelope['signedRoot'];
}>;

const readProtocolSignatureMessageVector =
    async (): Promise<ProtocolSignatureMessageVector> =>
        JSON.parse(
            await readFile(
                path.resolve('test-vectors', 'protocol-signature-message.json'),
                'utf8',
            ),
        ) as ProtocolSignatureMessageVector;

describe('Canonical protocol-signature message', () => {
    it('matches the shared Rust and TypeScript message vector', async () => {
        const vector = await readProtocolSignatureMessageVector();

        expect(
            new TextDecoder().decode(
                encodeCanonicalProtocolSignatureMessage({
                    publicKeyHash: vector.publicKeyHash,
                    signedRoot: vector.signedRoot,
                }),
            ),
        ).toBe(vector.canonicalMessageUtf8);
    });
});
