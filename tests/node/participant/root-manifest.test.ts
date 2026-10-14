import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { rootDataKeyBytes } from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import { isRootGeneration } from '#packages/sdk/src/participant/worker/storage/root-generation.js';
import { encodeManifest } from '#packages/sdk/src/participant/worker/storage/root.js';

// The SHA-256 digest of stored bytes, which pins their exact format.
const storedDigest = (bytes: Uint8Array) =>
    createHash('sha256').update(bytes).digest('hex');

const filled = (length: number, value: number) =>
    new Uint8Array(length).fill(value);
const references = [
    { kind: 0, offset: 0, length: 17, hash: filled(64, 5) },
    { kind: 1, offset: 0, length: 9, hash: filled(64, 6) },
];

describe('participant root manifest', () => {
    it('pins the bytes of an enrollment root and of a root with every suffix', () => {
        const enrollment = encodeManifest(
            {
                dataKeys: filled(96, 1),
                poll: filled(64, 2),
                references,
                suffixes: {},
            },
            1,
        );
        const complete = encodeManifest(
            {
                dataKeys: filled(64, 1),
                poll: filled(64, 2),
                references,
                suffixes: {
                    preparation: filled(3, 7),
                    ballot: filled(5, 8),
                    close: filled(2, 9),
                    target: filled(4, 10),
                    release: filled(6, 11),
                },
            },
            29,
        );
        expect([enrollment, complete].map(storedDigest)).toEqual([
            '5313d98cf0458953c71e98f836cda4ff7a6ef9d6258b0691d5ee672de5048e17',
            'ef16caa3d2f1242b87c69cd577f43474934503b47fb88559f65e00995a4e5782',
        ]);
    });

    it('holds exactly the root generations, each with every suffix from its first generation in order', () => {
        const firstGenerations = [
            ['preparation', 4],
            ['ballot', 12],
            ['close', 12],
            ['target', 23],
            ['release', 25],
        ] as const;
        const rootGenerations = [
            1, 2, 3, 4, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
            27, 29,
        ];
        // Each suffix holds its one-based position in the expected order.
        const encode = (generation: number, names: readonly string[]) =>
            encodeManifest(
                {
                    dataKeys: filled(rootDataKeyBytes(generation), 1),
                    poll: filled(64, 2),
                    references,
                    suffixes: Object.fromEntries(
                        names.map((name, index) => [
                            name,
                            Uint8Array.of(index + 1),
                        ]),
                    ),
                },
                generation,
            );
        const suffixesAt = (generation: number) =>
            firstGenerations
                .filter(([, first]) => generation >= first)
                .map(([name]) => name);
        const generations = Array.from(
            { length: 32 },
            (_unused, index) => index - 1,
        );
        expect(generations.filter(isRootGeneration)).toEqual(rootGenerations);
        for (const generation of generations.filter(
            (candidate) => !rootGenerations.includes(candidate),
        ))
            expect(() => encode(generation, suffixesAt(generation))).toThrow(
                'Invalid participant root generation.',
            );
        for (const generation of rootGenerations) {
            const names = suffixesAt(generation);
            const encoded = encode(generation, names);
            expect([
                ...encoded.subarray(encoded.length - 5 * names.length),
            ]).toEqual(
                names.flatMap((_name, index) => [1, 0, 0, 0, index + 1]),
            );
            // A suffix of a later phase, and a missing one, are refused.
            const later = firstGenerations
                .filter(([, first]) => generation < first)
                .slice(0, 1)
                .map(([name]) => [...names, name]);
            for (const extended of later)
                expect(() => encode(generation, extended)).toThrow(
                    'Participant root fields disagree with its generation.',
                );
            for (const shortened of names.length > 0 ? [names.slice(1)] : [])
                expect(() => encode(generation, shortened)).toThrow(
                    'A participant root suffix is missing.',
                );
        }
    });
});
