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
        '4a2efbb3218fcbde79d396688ebd4bf5f5ed7300f23316e6900aa0cb7dd0057bccc3892df183a6a4f628cc26c8163cf9b226e37f54519216067be5efd5ca743e',
    batchLayoutBindingHash:
        '2bdddaf7eba3787d244cb6622e252b6ee9391a8d3aa22a23fa9e46a777d036a7d8852e38f664dec7fd50e2308bec608f896cbd3b3ae925844bc77f673330baab',
    encodedPlaintextRoot:
        '58c345519637224053f85635ecd8493f74a42bc6b44fcd889571bf73e44ea0534de25677efec1b2efff76f64d17735debb527c787db0b8057a59458e004bfb3c',
    encodedPlaintextHash:
        '02dd5e48be07c2bc343db89c7566f907b0bc319b56feb4ea0d6fa9a40a9f65829346a2ea08a576342c8dccce1a098e31f553c60726b1a76c1a77ae4a57cf426e',
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
