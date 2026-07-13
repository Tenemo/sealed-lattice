import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';

const expectKernelCommandError = (
    command: () => unknown,
    code: TranscriptCoreKernelCommandError['code'],
    messagePattern: RegExp,
): void => {
    try {
        command();
        throw new Error('Expected a transcript-core kernel command error.');
    } catch (error) {
        expect(error).toBeInstanceOf(TranscriptCoreKernelCommandError);
        const commandError = error as TranscriptCoreKernelCommandError;
        expect(commandError.code).toBe(code);
        expect(commandError.message).toMatch(messagePattern);
    }
};

const expectProtocolHash = (value: string, label: string): void => {
    expect(value, label).toMatch(/^[a-f0-9]{128}$/u);
};

describe('BGV-RNS backend kernel commands', () => {
    it('encodes direct encrypted ballot aggregate slots and validates roots byte-identically', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const encoded = kernel.encodeBgvBatchPlaintext({
            slots: [0, 1, 65_536, 17, 99],
            level: 0,
            includeCanonicalBytesHex: true,
        });
        expect(encoded.canonicalBytesHex).toMatch(/^[a-f0-9]+$/u);
        expectProtocolHash(encoded.plaintextRoot, 'encoded plaintext root');
        expectProtocolHash(encoded.bgvParametersHash, 'BGV parameters hash');
        expect(encoded.sampledSlots).toEqual(
            expect.arrayContaining([
                { position: 0, value: 0 },
                { position: 1, value: 1 },
                { position: 2, value: 65_536 },
            ]),
        );

        const validated = kernel.validateBgvPlaintextObject({
            canonicalBytesHex: encoded.canonicalBytesHex ?? '',
            expectedPlaintextRoot: encoded.plaintextRoot,
        });

        expect(validated).toMatchObject({
            isValid: true,
            objectKind: 'plaintext',
            plaintextRoot: encoded.plaintextRoot,
        });
        expectKernelCommandError(
            () =>
                kernel.validateBgvPlaintextObject({
                    canonicalBytesHex: encoded.canonicalBytesHex ?? '',
                    expectedPlaintextRoot: '0'.repeat(128),
                }),
            'ComponentMismatch',
            /plaintext root/u,
        );
    });
});
