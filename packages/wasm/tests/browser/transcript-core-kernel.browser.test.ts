import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';
import {
    createFoundationTranscriptCoreFixture,
    createFoundationTranscriptFixture,
} from '#tests/support/foundation-transcript-fixture';

const foundationTranscriptFixture = createFoundationTranscriptFixture();
const foundationTranscriptCoreFixture = createFoundationTranscriptCoreFixture(
    foundationTranscriptFixture.expectedHashes,
);
const hash512Pattern = /^[a-f0-9]{128}$/u;

describe('transcript-core kernel in browsers', () => {
    it('loads the transcript-core module and exposes command exports', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.exportedFunctionNames).toEqual(
            expect.arrayContaining([
                'memory',
                'sealed_lattice_allocate',
                'sealed_lattice_deallocate',
                'sealed_lattice_transcript_core_command_with_length',
            ]),
        );
    });

    it('verifies the foundation transcript-core fixture', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.verifyFixture(foundationTranscriptCoreFixture)).toEqual({
            caseName: 'foundation-transcript-roots',
            objectHash512:
                foundationTranscriptCoreFixture.expectedObjectHash512,
            chunkRoot: foundationTranscriptCoreFixture.expectedChunkRoot,
        });
    });

    it('derives canonical object hash and field checks through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();

        const pollSpecHash = kernel.deriveCanonicalObjectHash({
            value: { objectType: 'PollSpec', poll: 'main' },
        });

        expect(pollSpecHash).toMatch(hash512Pattern);
        expect(pollSpecHash).toBe(
            kernel.deriveCanonicalObjectHash({
                value: { objectType: 'PollSpec', poll: 'main' },
            }),
        );
        expect(
            kernel.interpolateShamirConstantTerm({
                sharePoints: [
                    { rosterPosition: 1, value: 15 },
                    { rosterPosition: 2, value: 25 },
                ],
            }),
        ).toBe(5);
    });

    it('rejects malformed canonical bytes with the same error code', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() =>
            kernel.analyzeCanonicalObject({
                canonicalBytesHex: '42414421',
                chunkSize: 8,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('produces byte-identical BGV canonical roots through browser WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeBgvRnsParameters();
        const encodedResult = kernel.encodeBgvBatchPlaintext({
            slots: [0, 1, 65_536, 17, 99],
            level: 0,
            layoutBinding: parameters.batchLayoutBinding,
            includeCanonicalBytesHex: true,
        });

        expect(parameters.bgvParametersHash).toMatch(hash512Pattern);
        expect(encodedResult).not.toMatchObject({ ok: false });
        const encoded = encodedResult as {
            readonly canonicalBytesHex: string;
            readonly canonicalBytesHash512: string;
            readonly canonicalByteLength: number;
            readonly plaintextRoot: string;
        };

        expect(encoded.plaintextRoot).toMatch(hash512Pattern);
        expect(encoded.canonicalBytesHash512).toMatch(hash512Pattern);
        expect(encoded.canonicalByteLength).toBeGreaterThan(0);
        expect(
            kernel.validateBgvPlaintextObject({
                canonicalBytesHex: encoded.canonicalBytesHex,
                expectedPlaintextRoot: encoded.plaintextRoot,
            }),
        ).toMatchObject({
            ok: true,
            objectKind: 'plaintext',
            plaintextRoot: encoded.plaintextRoot,
        });
    });
});
