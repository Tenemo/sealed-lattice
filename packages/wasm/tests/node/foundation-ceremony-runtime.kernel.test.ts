import { foundationProfile, type ProtocolHash } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    loadFreshTranscriptCoreKernel,
    openFoundationCeremonyRuntime,
} from '#packages/wasm/src/index';
import {
    canonicalItem,
    canonicalTuple,
    concatenateBytes,
    hashItem,
    unsigned16Item,
    unsigned16LittleEndian,
    unsigned32LittleEndian,
    unsigned64Item,
} from '#packages/wasm/tests/canonical-tuple-test-helpers';
import { createStateVerifierTestVector } from '#packages/wasm/tests/state-verifier-test-vectors';

const dataPrimes = [
    140_700_980_543_489n,
    140_546_359_361_537n,
    140_507_704_066_049n,
    140_417_508_376_577n,
    140_396_033_212_417n,
    140_383_148_113_921n,
    140_365_967_982_593n,
    140_280_067_325_953n,
    140_061_020_651_521n,
    139_992_300_126_209n,
    139_880_629_272_577n,
    139_764_663_386_113n,
    139_708_827_959_297n,
    139_670_172_663_809n,
    139_541_321_678_849n,
    139_451_125_989_377n,
    139_399_585_595_393n,
] as const;

const unsigned32Item = (value: number): Uint8Array =>
    canonicalItem(0x04, unsigned32LittleEndian(value));

const unsigned64LittleEndian = (value: bigint): Uint8Array => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
};

const homogeneousListItem = (
    itemType: number,
    values: readonly Uint8Array[],
): Uint8Array =>
    canonicalItem(
        0x0e,
        concatenateBytes(
            unsigned16LittleEndian(itemType),
            unsigned32LittleEndian(values.length),
            ...values,
        ),
    );

const createCanonicalSuiteRecordBytes = (
    polynomialDegree = 32_768,
): Uint8Array => {
    const ternaryPurposes = new Set([1, 3, 8, 11, 12]);
    const distributions = Array.from({ length: 12 }, (_value, index) => {
        const purpose = index + 1;
        const isTernary = ternaryPurposes.has(purpose);
        return canonicalTuple(
            0x0116,
            unsigned16Item(purpose),
            unsigned16Item(isTernary ? 1 : 2),
            unsigned64Item(isTernary ? 0n : 2n),
        );
    });
    const artifacts = Array.from({ length: 6 }, (_value, index) => {
        const artifactKind = index + 1;
        return canonicalTuple(
            0x0117,
            unsigned16Item(artifactKind),
            unsigned64Item(1n),
            hashItem(new Uint8Array(64).fill(artifactKind)),
        );
    });

    return canonicalTuple(
        0x0118,
        unsigned16Item(1),
        unsigned16Item(10),
        unsigned16Item(3),
        unsigned16Item(4),
        unsigned16Item(7),
        unsigned32Item(polynomialDegree),
        unsigned64Item(65_537n),
        homogeneousListItem(0x05, dataPrimes.map(unsigned64LittleEndian)),
        homogeneousListItem(0x05, [
            unsigned64LittleEndian(140_737_471_512_577n),
        ]),
        homogeneousListItem(0x03, [0, 1].map(unsigned16LittleEndian)),
        homogeneousListItem(
            0x03,
            Array.from({ length: 17 }, (_value, index) =>
                unsigned16LittleEndian(index),
            ),
        ),
        unsigned16Item(1),
        unsigned16Item(1),
        unsigned16Item(1),
        unsigned16Item(3),
        unsigned16Item(10),
        unsigned32Item(64),
        unsigned32Item(128),
        unsigned32Item(20),
        unsigned32Item(100),
        unsigned64Item(3_000n),
        unsigned64Item(20_000n),
        unsigned64Item(5_000n),
        unsigned64Item(25_000n),
        unsigned64Item(50_000n),
        unsigned64Item(10_000n),
        unsigned64Item(100_000n),
        homogeneousListItem(0x09, distributions),
        homogeneousListItem(0x09, artifacts),
    );
};

const manifestInput = () => ({
    displayTitle: 'Wybór priorytetów',
    optionDefinitions: Array.from({ length: 20 }, (_value, optionIndex) => ({
        displayLabel:
            optionIndex === 4 ? 'Cafe\u0301' : `Option ${String(optionIndex)}`,
        optionIdentifier: `option-${String(optionIndex)}`,
        optionIndex,
    })),
});

const differentHash = (hash: ProtocolHash): ProtocolHash =>
    `${hash[0] === '0' ? '1' : '0'}${hash.slice(1)}`;

describe('foundation ceremony Rust/WASM boundary', () => {
    it('encodes normalized manifest bytes and refuses malformed canonical bytes', async () => {
        const runtime = openFoundationCeremonyRuntime(
            await loadFreshTranscriptCoreKernel(),
        );
        const manifest = runtime.encodeManifest(manifestInput());
        const verification = runtime.verifyManifest(manifest.canonicalBytes);

        expect(verification).toEqual({
            isValid: true,
            value: { manifestHash: manifest.manifestHash },
        });

        const malformed = manifest.canonicalBytes.slice();
        malformed[malformed.length - 1] ^= 0x80;
        expect(runtime.verifyManifest(malformed)).toEqual({
            isValid: false,
            refusalReason: 'malformedEncoding',
        });
        expect(() =>
            runtime.encodeManifest({
                ...manifestInput(),
                optionDefinitions: manifestInput().optionDefinitions.slice(
                    0,
                    19,
                ),
            }),
        ).toThrow();

        const boundaryOptionDefinitions = Array.from(
            { length: 20 },
            (_value, optionIndex) => ({
                displayLabel: `O${String(optionIndex)}`,
                optionIdentifier: `option-${String(optionIndex)}`,
                optionIndex,
            }),
        );
        const optionDisplayByteLength = boundaryOptionDefinitions.reduce(
            (total, option) => total + option.displayLabel.length,
            0,
        );
        const boundaryManifest = runtime.encodeManifest({
            displayTitle: 'Q'.repeat(
                foundationProfile.maximumCopiedBufferByteLength -
                    920 -
                    optionDisplayByteLength,
            ),
            optionDefinitions: boundaryOptionDefinitions,
        });
        expect(boundaryManifest.canonicalBytes).toHaveLength(
            foundationProfile.maximumCopiedBufferByteLength,
        );
        expect(() =>
            runtime.encodeManifest({
                displayTitle: `${'Q'.repeat(
                    foundationProfile.maximumCopiedBufferByteLength -
                        920 -
                        optionDisplayByteLength,
                )}Q`,
                optionDefinitions: boundaryOptionDefinitions,
            }),
        ).toThrow();
    });

    it('encodes action and board policy bytes under the fixed profile', async () => {
        const runtime = openFoundationCeremonyRuntime(
            await loadFreshTranscriptCoreKernel(),
        );
        const actionDefinition = runtime.encodeActionDefinition({
            submissionCutoffUnixMilliseconds: 1_893_456_000_000n,
            topCount: 7,
        });
        const boardPolicy = runtime.encodeBoardPolicy({
            boardOriginIdentifier: 'https://board.example.test',
        });

        expect(
            runtime.verifyActionDefinition(actionDefinition.canonicalBytes),
        ).toEqual({
            isValid: true,
            value: {
                actionDefinitionHash: actionDefinition.actionDefinitionHash,
            },
        });
        expect(runtime.verifyBoardPolicy(boardPolicy.canonicalBytes)).toEqual({
            isValid: true,
            value: { boardPolicyHash: boardPolicy.boardPolicyHash },
        });
        expect(() =>
            runtime.encodeActionDefinition({
                submissionCutoffUnixMilliseconds: 1n << 64n,
                topCount: 7,
            }),
        ).toThrow(RangeError);
        expect(() =>
            runtime.encodeBoardPolicy({
                boardOriginIdentifier: 'board\norigin',
            }),
        ).toThrow();
    });

    it('refuses suite profile drift and wrong ceremony or action contexts', async () => {
        const runtime = openFoundationCeremonyRuntime(
            await loadFreshTranscriptCoreKernel(),
        );
        const suiteBytes = createCanonicalSuiteRecordBytes();
        const suiteVerification = runtime.verifySuiteRecord(suiteBytes);
        expect(suiteVerification.isValid).toBe(true);
        if (!suiteVerification.isValid) {
            return;
        }
        expect(
            runtime.verifySuiteRecord(createCanonicalSuiteRecordBytes(16_384)),
        ).toEqual({
            isValid: false,
            refusalReason: 'unsupportedVersionOrSuite',
        });

        const manifest = runtime.encodeManifest(manifestInput());
        const canonicalRosterBytes =
            createStateVerifierTestVector().canonicalRosterBytes;
        const ceremonyContext = runtime.verifyCeremonyContext({
            canonicalManifestBytes: manifest.canonicalBytes,
            canonicalRosterBytes,
            canonicalSuiteRecordBytes: suiteBytes,
            ceremonyIdentifier: 'ceremony-2026',
            expectedSuiteId: suiteVerification.value.suiteId,
        });
        expect(ceremonyContext.isValid).toBe(true);
        if (!ceremonyContext.isValid) {
            return;
        }
        expect(
            runtime.verifyCeremonyContext({
                canonicalManifestBytes: manifest.canonicalBytes,
                canonicalRosterBytes,
                canonicalSuiteRecordBytes: suiteBytes,
                ceremonyIdentifier: 'ceremony-2026',
                expectedSuiteId: differentHash(suiteVerification.value.suiteId),
            }),
        ).toEqual({ isValid: false, refusalReason: 'wrongContext' });

        const actionDefinition = runtime.encodeActionDefinition({
            submissionCutoffUnixMilliseconds: 1_893_456_000_000n,
            topCount: 7,
        });
        const boardPolicy = runtime.encodeBoardPolicy({
            boardOriginIdentifier: 'board.example.test',
        });
        const actionContextInput = {
            actionIdentifier: 'ranking-action',
            canonicalActionDefinitionBytes: actionDefinition.canonicalBytes,
            canonicalBoardPolicyBytes: boardPolicy.canonicalBytes,
            canonicalManifestBytes: manifest.canonicalBytes,
            canonicalRosterBytes,
            canonicalSuiteRecordBytes: suiteBytes,
            ceremonyIdentifier: 'ceremony-2026',
            expectedCeremonyContextHash:
                ceremonyContext.value.ceremonyContextHash,
            expectedSuiteId: suiteVerification.value.suiteId,
        } as const;
        const actionContext = runtime.verifyActionContext(actionContextInput);
        expect(actionContext.isValid).toBe(true);
        expect(
            runtime.verifyActionContext({
                ...actionContextInput,
                expectedCeremonyContextHash: differentHash(
                    ceremonyContext.value.ceremonyContextHash,
                ),
            }),
        ).toEqual({ isValid: false, refusalReason: 'wrongContext' });
    });
});
