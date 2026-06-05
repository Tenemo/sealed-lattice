import type {
    GoldenTranscriptCoreFixture,
    MalformedObjectFixture,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';
import goldenTranscriptCoreFixturesJson from '#test-vectors/transcript-core/golden-transcript-core.json';
import malformedObjectFixturesJson from '#test-vectors/transcript-core/malformed-objects.json';

type NamedFixture = {
    readonly caseName: string;
};

const goldenTranscriptCoreFixtures =
    goldenTranscriptCoreFixturesJson as readonly GoldenTranscriptCoreFixture[];
const malformedObjectFixtures =
    malformedObjectFixturesJson as readonly MalformedObjectFixture[];

const findFixture = <Fixture extends NamedFixture>(
    fixtures: readonly Fixture[],
    caseName: string,
): Fixture => {
    const fixture = fixtures.find(
        (candidate) => candidate.caseName === caseName,
    );
    if (fixture === undefined) {
        throw new Error(`Missing fixture: ${caseName}`);
    }

    return fixture;
};

const fullyVerifiedPassiveMhePrototypeFixture = findFixture(
    goldenTranscriptCoreFixtures,
    'fully-verified-passive-mhe-prototype-transcript-core',
);
const invalidEnumFixture = findFixture(malformedObjectFixtures, 'invalid-enum');
const protocolHashPattern = /^[a-f0-9]{128}$/u;

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

    it('verifies the golden transcript-core fixture', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.verifyFixture(fullyVerifiedPassiveMhePrototypeFixture),
        ).toEqual({
            verified: true,
            caseName: 'fully-verified-passive-mhe-prototype-transcript-core',
            objectHash512:
                fullyVerifiedPassiveMhePrototypeFixture.expectedObjectHash512,
            chunkRoot:
                fullyVerifiedPassiveMhePrototypeFixture.expectedChunkRoot,
            statusLabels:
                fullyVerifiedPassiveMhePrototypeFixture.expectedStatusLabels,
        });
    });

    it('derives protocol hash and field checks through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();

        const pollSpecHash = kernel.deriveProtocolHash({
            namespace: 'PollSpecHash',
            value: { poll: 'main' },
        });

        expect(pollSpecHash).toMatch(protocolHashPattern);
        expect(pollSpecHash).toBe(
            kernel.deriveProtocolHash({
                namespace: 'PollSpecHash',
                value: { poll: 'main' },
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
                canonicalBytesHex: invalidEnumFixture.canonicalBytesHex,
                chunkSize: 8,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('produces byte-identical BGV canonical roots through browser WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeBgvRnsProfile();
        const encodedResult = kernel.encodeBgvBatchPlaintext({
            slots: [0, 1, 65_536, 17, 99],
            level: 0,
            layoutBinding: profile.batchLayoutBinding,
            includeCanonicalBytesHex: true,
        });

        expect(profile.profileHash).toMatch(protocolHashPattern);
        expect(profile.batchLayoutBindingHash).toMatch(protocolHashPattern);
        expect(encodedResult).not.toMatchObject({ ok: false });
        const encoded = encodedResult as {
            readonly canonicalBytesHex: string;
            readonly canonicalBytesHash512: string;
            readonly canonicalByteLength: number;
            readonly plaintextRoot: string;
        };

        expect(encoded.plaintextRoot).toMatch(protocolHashPattern);
        expect(encoded.canonicalBytesHash512).toMatch(protocolHashPattern);
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
