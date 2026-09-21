import { describe, expect, it } from 'vitest';

import { assertCompletedReleaseObservation } from '#tools/ci/protocol-release-observation.js';

const completed = () => ({
    entropyBytes: 0,
    entropyCalls: 0,
    entropyByModule: {},
    webCryptoRandomBytes: 0,
    webCryptoRandomCalls: 0,
    keyGenerationCalls: 0,
    operationCounts: { '3': 2, '4': 1, '6': 1 },
    operations: [
        { operation: 6, status: 0 },
        { operation: 4, status: 0 },
    ],
});

describe('completed release observer evidence', () => {
    it('accepts the complete import and digest check with no fresh work', () => {
        expect(() =>
            assertCompletedReleaseObservation(completed(), 2),
        ).not.toThrow();
        expect(() =>
            assertCompletedReleaseObservation(completed()),
        ).not.toThrow();
    });

    it('refuses new randomness even when the byte count is zero', () => {
        for (const field of [
            'entropyBytes',
            'entropyCalls',
            'webCryptoRandomBytes',
            'webCryptoRandomCalls',
            'keyGenerationCalls',
        ] as const) {
            const value = completed();
            value[field] = 1;
            expect(() => assertCompletedReleaseObservation(value)).toThrow(
                'randomness',
            );
        }
        expect(() =>
            assertCompletedReleaseObservation({
                ...completed(),
                entropyByModule: { enrollment: 0 },
            }),
        ).toThrow();
    });

    it('refuses generation, signing, incomplete imports and unsuccessful checks', () => {
        for (const operations of [
            [{ operation: 6, status: 0 }],
            [
                { operation: 6, status: 1 },
                { operation: 4, status: 0 },
            ],
            [
                { operation: 6, status: 0 },
                { operation: 4, status: 1 },
            ],
            [...completed().operations, { operation: 0, status: 0 }],
            [...completed().operations, { operation: 5, status: 0 }],
        ])
            expect(() =>
                assertCompletedReleaseObservation({
                    ...completed(),
                    operations,
                }),
            ).toThrow('sequence');
        const invalidCounts: Record<string, number>[] = [
            { '3': 0, '4': 1, '6': 1 },
            { '3': 2, '4': 1, '6': 2 },
            { '3': 2, '4': 1, '6': 1, '1': 1 },
        ];
        for (const operationCounts of invalidCounts)
            expect(() =>
                assertCompletedReleaseObservation({
                    ...completed(),
                    operationCounts,
                }),
            ).toThrow();
        expect(() =>
            assertCompletedReleaseObservation(completed(), 3),
        ).toThrow();
    });
});
