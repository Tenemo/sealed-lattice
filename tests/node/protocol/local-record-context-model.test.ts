import { describe, expect, it } from 'vitest';

import {
    compileIndependentLocalRecordCensus,
    encodeIndependentLocalRecordContext,
    enumerateAllAbstainLocalRecordSeals,
    enumerateFullTallyLocalRecordSeals,
    localRecordContextByteLength,
    localRecordContextKey,
    localRecordObjectKinds,
    parseIndependentLocalRecordContext,
} from '#tests/local-record-context-model.js';
import { compileIndependentPaddedTallyModel } from '#tests/padded-tally-transcript-model.js';

describe('independent local-record context model', () => {
    it('parses the exact fixed-width context grammar', () => {
        const seal = enumerateFullTallyLocalRecordSeals(
            compileIndependentPaddedTallyModel(1),
        )[0];
        if (seal === undefined)
            throw new Error('The context fixture is absent.');
        expect(localRecordContextByteLength).toBe(438);
        expect(seal.contextBytes).toHaveLength(localRecordContextByteLength);
        expect(parseIndependentLocalRecordContext(seal.contextBytes)).toEqual(
            seal.context,
        );
        expect(
            encodeIndependentLocalRecordContext(
                parseIndependentLocalRecordContext(seal.contextBytes),
            ),
        ).toEqual(seal.contextBytes);

        const wrongDomain = Uint8Array.from(seal.contextBytes);
        wrongDomain[0] ^= 1;
        expect(() => parseIndependentLocalRecordContext(wrongDomain)).toThrow(
            /domain/u,
        );
        expect(() =>
            parseIndependentLocalRecordContext(seal.contextBytes.subarray(1)),
        ).toThrow(/length/u);
    });

    it('enumerates every full-inventory reseal for every output width', () => {
        for (let topCount = 1; topCount <= 10; topCount += 1) {
            const tally = compileIndependentPaddedTallyModel(topCount);
            const seals = enumerateFullTallyLocalRecordSeals(tally);
            const census = compileIndependentLocalRecordCensus(seals);
            expect(census.storageVisibleSealCount).toBe(
                10 * (210 + 29 * tally.descriptors.length),
            );
            expect(census.distinctDerivationInputCount).toBe(
                10 * (32 + 4 * tally.descriptors.length),
            );
            expect(census.inventoryCommitCount).toBe(
                10 * (27 + 2 * tally.descriptors.length),
            );
            expect(census.retainedRecordCount).toBe(150);
            expect(census.maximumSealsPerExactContext).toBe(
                25 + 2 * tally.descriptors.length,
            );
            expect(
                new Set(
                    seals.map(({ contextBytes }) =>
                        localRecordContextKey(contextBytes),
                    ),
                ).size,
            ).toBe(census.distinctDerivationInputCount);
        }
    });

    it('regenerates the maximum-width storage-visible and retained record census', () => {
        const census = compileIndependentLocalRecordCensus(
            enumerateFullTallyLocalRecordSeals(
                compileIndependentPaddedTallyModel(10),
            ),
        );
        expect(census).toEqual({
            storageVisibleSealCount: 20_950,
            distinctDerivationInputCount: 2_920,
            inventoryCommitCount: 1_570,
            retainedRecordCount: 150,
            maximumSealsPerExactContext: 155,
            sameContextSealPairCount: 1_262_410n,
            objectKindCounts: {
                [localRecordObjectKinds.action]: 1_570,
                [localRecordObjectKinds.preparation]: 1_560,
                [localRecordObjectKinds.privatePreparationSlot]: 13_140,
                [localRecordObjectKinds.source]: 1_360,
                [localRecordObjectKinds.finality]: 1_340,
                [localRecordObjectKinds.tallyGeneration]: 1_320,
                [localRecordObjectKinds.tallyEvaluation]: 660,
            },
            retainedObjectKindCounts: {
                [localRecordObjectKinds.action]: 10,
                [localRecordObjectKinds.preparation]: 10,
                [localRecordObjectKinds.privatePreparationSlot]: 90,
                [localRecordObjectKinds.source]: 10,
                [localRecordObjectKinds.finality]: 10,
                [localRecordObjectKinds.tallyGeneration]: 10,
                [localRecordObjectKinds.tallyEvaluation]: 10,
            },
        });
        expect(census.storageVisibleSealCount).toBeLessThan(2 ** 30);
    });

    it('regenerates the all-abstain terminal schedule', () => {
        const census = compileIndependentLocalRecordCensus(
            enumerateAllAbstainLocalRecordSeals(),
        );
        expect(census).toEqual({
            storageVisibleSealCount: 1_954,
            distinctDerivationInputCount: 302,
            inventoryCommitCount: 261,
            retainedRecordCount: 131,
            maximumSealsPerExactContext: 25,
            sameContextSealPairCount: 14_285n,
            objectKindCounts: {
                [localRecordObjectKinds.action]: 261,
                [localRecordObjectKinds.preparation]: 251,
                [localRecordObjectKinds.privatePreparationSlot]: 1_359,
                [localRecordObjectKinds.source]: 51,
                [localRecordObjectKinds.finality]: 31,
                [localRecordObjectKinds.noResult]: 1,
            },
            retainedObjectKindCounts: {
                [localRecordObjectKinds.action]: 10,
                [localRecordObjectKinds.preparation]: 10,
                [localRecordObjectKinds.privatePreparationSlot]: 90,
                [localRecordObjectKinds.source]: 10,
                [localRecordObjectKinds.finality]: 10,
                [localRecordObjectKinds.noResult]: 1,
            },
        });
    });
});
