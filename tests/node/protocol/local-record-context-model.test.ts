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

    it('enumerates one successful seal per exact context for every output width', () => {
        for (let topCount = 1; topCount <= 10; topCount += 1) {
            const tally = compileIndependentPaddedTallyModel(topCount);
            const seals = enumerateFullTallyLocalRecordSeals(tally);
            const census = compileIndependentLocalRecordCensus(seals);
            expect(census.successfulSealCount).toBe(
                10 * (32 + 4 * tally.descriptors.length),
            );
            expect(census.retainedRecordCount).toBe(150);
            expect(census.maximumSealsPerExactContext).toBe(1);
            expect(
                new Set(
                    seals.map(({ contextBytes }) =>
                        localRecordContextKey(contextBytes),
                    ),
                ).size,
            ).toBe(seals.length);
        }
    });

    it('regenerates the maximum-width successful and retained record census', () => {
        const census = compileIndependentLocalRecordCensus(
            enumerateFullTallyLocalRecordSeals(
                compileIndependentPaddedTallyModel(10),
            ),
        );
        expect(census).toEqual({
            successfulSealCount: 2_920,
            retainedRecordCount: 150,
            maximumSealsPerExactContext: 1,
            objectKindCounts: {
                [localRecordObjectKinds.action]: 1_360,
                [localRecordObjectKinds.preparation]: 20,
                [localRecordObjectKinds.privatePreparationSlot]: 180,
                [localRecordObjectKinds.source]: 20,
                [localRecordObjectKinds.finality]: 20,
                [localRecordObjectKinds.tallyGeneration]: 660,
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
        expect(census.successfulSealCount).toBeLessThan(2 ** 30);
    });

    it('regenerates the all-abstain terminal schedule', () => {
        const census = compileIndependentLocalRecordCensus(
            enumerateAllAbstainLocalRecordSeals(),
        );
        expect(census).toEqual({
            successfulSealCount: 282,
            retainedRecordCount: 131,
            maximumSealsPerExactContext: 1,
            objectKindCounts: {
                [localRecordObjectKinds.action]: 41,
                [localRecordObjectKinds.preparation]: 20,
                [localRecordObjectKinds.privatePreparationSlot]: 180,
                [localRecordObjectKinds.source]: 20,
                [localRecordObjectKinds.finality]: 20,
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
