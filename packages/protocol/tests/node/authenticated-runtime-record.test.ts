import { describe, expect, it } from 'vitest';

import {
    createRuntimeRecordProtection,
    sealRuntimeRecord,
} from '#packages/protocol/src/runtime/authenticated-runtime-record';
import {
    generateRuntimeStorageEncryptionKey,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const repeatedNonceCryptoProvider = (): Crypto =>
    ({
        getRandomValues: <Value extends ArrayBufferView>(
            value: Value,
        ): Value => {
            new Uint8Array(
                value.buffer,
                value.byteOffset,
                value.byteLength,
            ).fill(0x5a);
            return value;
        },
        subtle: globalThis.crypto.subtle,
    }) as Crypto;

describe('authenticated runtime records', () => {
    it('rejects nonce reuse across protection instances sharing one key', async () => {
        const encryptionKey = await generateRuntimeStorageEncryptionKey();
        const firstProtection = createRuntimeRecordProtection({
            authorityContext: runtimeAuthorityContext(),
            cryptoProvider: repeatedNonceCryptoProvider(),
            encryptionKey,
            maximumRecordSealingCount: 2,
        });
        const secondProtection = createRuntimeRecordProtection({
            authorityContext: runtimeAuthorityContext(),
            cryptoProvider: repeatedNonceCryptoProvider(),
            encryptionKey,
            maximumRecordSealingCount: 2,
        });

        const sealed = await sealRuntimeRecord({
            logicalRecordKey: 'nonce-registry/first',
            operationDomain: 'sealed-lattice/test/runtime-record/v1',
            plaintext: new Uint8Array([1, 2, 3]),
            protection: firstProtection,
        });
        expect(sealed.byteLength).toBeGreaterThan(3);

        await expect(
            sealRuntimeRecord({
                logicalRecordKey: 'nonce-registry/second',
                operationDomain: 'sealed-lattice/test/runtime-record/v1',
                plaintext: new Uint8Array([4, 5, 6]),
                protection: secondProtection,
            }),
        ).rejects.toMatchObject({ code: 'EntropyFailure' });
    });
});
