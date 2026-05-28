import type {
    GoldenTranscriptCoreFixture,
    MalformedObjectFixture,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '../../src/index';

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

const fullyVerifiedDevelopmentIntegrationFixture = findFixture(
    goldenTranscriptCoreFixtures,
    'fully-verified-development-integration-transcript-core',
);
const invalidEnumFixture = findFixture(malformedObjectFixtures, 'invalid-enum');
const browserM7BgvVectors = {
    profileHash:
        '4a2efbb3218fcbde79d396688ebd4bf5f5ed7300f23316e6900aa0cb7dd0057bccc3892df183a6a4f628cc26c8163cf9b226e37f54519216067be5efd5ca743e',
    batchLayoutBindingHash:
        '3bb25a676dc61ef33169966d56979638fc95efa887339506919d0c1ba64ec881c96d98453a7f2cc1d31b5eca7ce8b132022a12d3b58a1fe22c4355beaee58d6e',
    encodedPlaintextRoot:
        '92cf108ea1bf78bf8b4acff606df99b2b5d342fe8caac81f1dbc3eaa166b31bf61b2453d57630109422b14e9cbdf8cf327ce56793cb676a10888c5f6c1c12edd',
    encodedPlaintextHash:
        'd77e7936e25849fa95ac455dd4b1e2502b9f502491d0657c41035b0c91aa625762f77bdd6e24c236417eeab50d7afdeea376cabf1d737df587de3932b9fc641e',
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
            kernel.verifyFixture(fullyVerifiedDevelopmentIntegrationFixture),
        ).toEqual({
            verified: true,
            caseName: 'fully-verified-development-integration-transcript-core',
            objectHash512:
                fullyVerifiedDevelopmentIntegrationFixture.expectedObjectHash512,
            chunkRoot:
                fullyVerifiedDevelopmentIntegrationFixture.expectedChunkRoot,
            statusLabels:
                fullyVerifiedDevelopmentIntegrationFixture.expectedStatusLabels,
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

        expect(profile.profileHash).toBe(browserM7BgvVectors.profileHash);
        expect(profile.batchLayoutBindingHash).toBe(
            browserM7BgvVectors.batchLayoutBindingHash,
        );
        expect(encodedResult).not.toMatchObject({ ok: false });
        const encoded = encodedResult as {
            readonly canonicalBytesHex: string;
            readonly canonicalBytesHash512: string;
            readonly canonicalByteLength: number;
            readonly plaintextRoot: string;
        };

        expect(encoded.plaintextRoot).toBe(
            browserM7BgvVectors.encodedPlaintextRoot,
        );
        expect(encoded.canonicalBytesHash512).toBe(
            browserM7BgvVectors.encodedPlaintextHash,
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
            plaintextRoot: browserM7BgvVectors.encodedPlaintextRoot,
        });
    });
});
