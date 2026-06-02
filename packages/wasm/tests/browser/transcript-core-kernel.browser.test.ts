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
        '7071099482aac9e76a6728bd47a3906d55a3d39dc86ba5376323c3cb099326a9bdf072e1189983d04e74b648567bf069b6844fd3c167f0b31df3c5eff4ebb58d',
    batchLayoutBindingHash:
        '0ff4161d3e74b6f02134e2c86240d8e61139889bad65ab2b5615d7919e7562c97c45fe4ed031076beea6f76e1c485257fb521f4eab65056c77f1cd06aa39b1c6',
    encodedPlaintextRoot:
        'ea3c780b8c7834f070b3d4bc70ef6715dc39abd5c10ce2cf4e503a16fafa98a4c0c3a25246d3227c448fb1005ef2bd26924c396e83ac9c74008c0387288b1208',
    encodedPlaintextHash:
        'be87cf264df69ed4379194ee0112dd903a58b4c2bf9e097fde0a1281175b6463d73fae17d35b5cfe2c6842ec2da9dac397452eb19b86944f3ff42673c288e99a',
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

    it('rejects malformed encrypted aggregate evaluation sweep requests before setup loading', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() =>
            kernel.runEncryptedAggregateTopKEvaluationSweep({
                topCounts: [1, 1],
            } as unknown as Parameters<
                typeof kernel.runEncryptedAggregateTopKEvaluationSweep
            >[0]),
        ).toThrow(
            new TranscriptCoreKernelCommandError({
                code: 'InvalidFixture',
                message: 'topCounts must not contain duplicate values',
            }),
        );
    });

    it('rejects accepted evaluator witness fields before setup loading', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const forbiddenFieldCases = [
            ['developmentKeySet', { keySeed: 'not-on-this-path' }],
            ['trustedDealerSecret', { secret: 'not-on-this-path' }],
            ['plaintextRanks', [0, 1]],
            ['decodedTargetIdSlots', [1, 0]],
            ['targetDecryptionShare', { share: 'not-yet-owned' }],
        ] as const;

        for (const [fieldName, fieldValue] of forbiddenFieldCases) {
            expect(() =>
                kernel.runEncryptedAggregateTopKEvaluation({
                    [fieldName]: fieldValue,
                } as unknown as Parameters<
                    typeof kernel.runEncryptedAggregateTopKEvaluation
                >[0]),
            ).toThrow(
                new TranscriptCoreKernelCommandError({
                    code: 'InvalidFixture',
                    message: `accepted encrypted aggregate evaluation rejects forbidden witness field ${fieldName}`,
                }),
            );

            expect(() =>
                kernel.runEncryptedAggregateTopKEvaluationSweep({
                    topCounts: [1],
                    [fieldName]: fieldValue,
                } as unknown as Parameters<
                    typeof kernel.runEncryptedAggregateTopKEvaluationSweep
                >[0]),
            ).toThrow(
                new TranscriptCoreKernelCommandError({
                    code: 'InvalidFixture',
                    message: `accepted encrypted aggregate evaluation rejects forbidden witness field ${fieldName}`,
                }),
            );
        }
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
