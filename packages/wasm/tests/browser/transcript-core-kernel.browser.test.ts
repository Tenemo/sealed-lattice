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
const browserBgvRnsVectors = {
    profileHash:
        '79a826f54f3863ec664b5b8cef4a2108c089e059560657fd102c4423d1329152bc0a0ecf09f7903cf7509f35da4bd8b6af7aa88c6532f3372be5d9c0c4e9025c',
    batchLayoutBindingHash:
        '0c615062a05d9b7182b6f069d5a6aca23b86c8eb1e986a9e7b12adf34061c4e96eb9e89a9030e517f331b8089c0ba50e0ba1eadd7490e3e608ea80288ad25853',
    encodedPlaintextRoot:
        '0ed438e393c879787b859758e3c975edf4520b0258d2b42690eeb336c5a72140e265e5e7404b868ade767ee3b29da3c669c9d8db382a8877bb032accd51f8a58',
    encodedPlaintextHash:
        'a6c247b2a549934dcf071cb48cb983194ea8ecf6d1c4021cae3750f5385e9fa3db08671d84568ca33614b5a1f581069d441b1fa4c426d266b1c04e8f4d39ee76',
} as const;

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

        expect(
            kernel.deriveProtocolHash({
                namespace: 'PollSpecHash',
                value: { poll: 'main' },
            }),
        ).toBe(
            '43b28c9a3dcb3e34d75c9936a9930b68fb9f2010b87d43a6a61cbaa85d343d9fd0be2b312a90f404367b9c68793b0dcf02c4dae7351f6e96ded894b92f898cb4',
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

        expect(profile.profileHash).toBe(browserBgvRnsVectors.profileHash);
        expect(profile.batchLayoutBindingHash).toBe(
            browserBgvRnsVectors.batchLayoutBindingHash,
        );
        expect(encodedResult).not.toMatchObject({ ok: false });
        const encoded = encodedResult as {
            readonly canonicalBytesHex: string;
            readonly canonicalBytesHash512: string;
            readonly canonicalByteLength: number;
            readonly plaintextRoot: string;
        };

        expect(encoded.plaintextRoot).toBe(
            browserBgvRnsVectors.encodedPlaintextRoot,
        );
        expect(encoded.canonicalBytesHash512).toBe(
            browserBgvRnsVectors.encodedPlaintextHash,
        );
        expect(encoded.canonicalByteLength).toBe(90_441);
        expect(
            kernel.validateBgvPlaintextObject({
                canonicalBytesHex: encoded.canonicalBytesHex,
                expectedPlaintextRoot: encoded.plaintextRoot,
            }),
        ).toMatchObject({
            ok: true,
            objectKind: 'plaintext',
            plaintextRoot: browserBgvRnsVectors.encodedPlaintextRoot,
        });
    });
});
