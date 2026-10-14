import { describe, expect, it } from 'vitest';

import {
    chunkBytes,
    rootDataKeyBytes,
    rootPrefixBytes,
} from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import {
    isRootGeneration,
    rootGeneration,
} from '#packages/sdk/src/participant/worker/storage/root-generation.js';
import {
    dataKind,
    decodeManifest,
    encodeManifest,
} from '#packages/sdk/src/participant/worker/storage/root.js';
import { rootManifestLayout } from '#packages/sdk/tests/node/participant-worker/stored-layouts.js';
import { compileParticipantRuntimeLimits } from '#tests/participant-runtime-bounds-model.js';

const filled = (length: number, value: number) =>
    new Uint8Array(length).fill(value);
const references = [
    { kind: 0, offset: 0, length: 17, hash: filled(64, 5) },
    { kind: 1, offset: 0, length: 9, hash: filled(64, 6) },
];

describe('participant root manifest', () => {
    it('stores an enrollment root and a root with every suffix in its layout', () => {
        const enrollment = {
            dataKeys: filled(96, 1),
            poll: filled(64, 2),
            references,
        };
        expect(
            Buffer.from(encodeManifest({ ...enrollment, suffixes: {} }, 1)),
        ).toEqual(rootManifestLayout({ ...enrollment, suffixes: [] }));
        const complete = {
            dataKeys: filled(64, 1),
            poll: filled(64, 2),
            references,
        };
        const suffixes = [
            ['preparation', filled(3, 7)],
            ['ballot', filled(5, 8)],
            ['close', filled(2, 9)],
            ['target', filled(4, 10)],
            ['release', filled(6, 11)],
        ] as const;
        expect(
            Buffer.from(
                encodeManifest(
                    { ...complete, suffixes: Object.fromEntries(suffixes) },
                    29,
                ),
            ),
        ).toEqual(
            rootManifestLayout({
                ...complete,
                suffixes: suffixes.map(([, bytes]) => bytes),
            }),
        );
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

describe('participant root manifest decoding', () => {
    const limits = compileParticipantRuntimeLimits();
    const { registration } = limits;
    // Each record kind's references: whole chunks, then the rest.
    const records = (lengths: readonly (readonly [number, number])[]) =>
        lengths.flatMap(([kind, length]) =>
            Array.from(
                { length: Math.ceil(length / chunkBytes) },
                (_unused, index) => ({
                    kind,
                    offset: index * chunkBytes,
                    length: Math.min(chunkBytes, length - index * chunkBytes),
                    hash: filled(64, kind + 1),
                }),
            ),
        );
    // Every record a registered participant retains.
    const enrollment = [
        [dataKind.publicKey, registration.publicKeyBytes],
        [dataKind.header, 76],
        [dataKind.signature, registration.signatureBytes],
        [dataKind.recipientCapsule, registration.recipientCapsuleBytes],
        [dataKind.signingCapsule, registration.signingCapsuleBytes],
        [dataKind.pollDefinition, 40],
        [dataKind.pollSignature, registration.signatureBytes],
        [dataKind.sourceCapsule, 1],
    ] as const;
    const manifestAt = (
        generation: number,
        inventory: ReturnType<typeof records>,
    ) => ({
        dataKeys: filled(rootDataKeyBytes(generation), 1),
        poll: filled(64, 2),
        references: inventory,
    });
    const stored = (
        manifest: ReturnType<typeof manifestAt>,
        suffixes: readonly Uint8Array[] = [],
    ) => new Uint8Array(rootManifestLayout({ ...manifest, suffixes }));
    const expectRefused = (
        bytes: Uint8Array,
        generation: number,
        message: string,
    ) =>
        expect(() => decodeManifest(bytes, generation, limits)).toThrow(
            message,
        );

    it('decodes a registered root and refuses a malformed frame or count', () => {
        const manifest = manifestAt(1, records(enrollment));
        expect(registration.publicKeyBytes).toBeGreaterThan(chunkBytes);
        const bytes = stored(manifest);
        expect(decodeManifest(bytes, 1, limits)).toEqual({
            ...manifest,
            suffixes: {},
        });
        const marker = bytes.slice();
        marker[3] ^= 1;
        for (const [input, generation] of [
            [bytes, 16],
            [marker, 1],
            [bytes.slice(0, rootPrefixBytes(1) - 1), 1],
        ] as const)
            expectRefused(
                input,
                generation,
                'Invalid participant root manifest.',
            );
        for (const count of [
            manifest.references.length + 1,
            limits.root.maximumRecords + 1,
        ]) {
            const counted = bytes.slice();
            new DataView(counted.buffer).setUint32(
                rootPrefixBytes(1) - 4,
                count,
                true,
            );
            expectRefused(counted, 1, 'Invalid participant record inventory.');
        }
        expectRefused(
            Uint8Array.of(...bytes, 0),
            1,
            'Participant root manifest has trailing bytes.',
        );
    });

    it('refuses a noncanonical inventory and one its generation does not hold', () => {
        const canonical = records(enrollment);
        const at = (kind: number) =>
            canonical.findIndex((reference) => reference.kind === kind);
        const header = canonical[at(dataKind.header)];
        const withHeader = (...replacement: (typeof header)[]) => [
            ...canonical.slice(0, at(dataKind.header)),
            ...replacement,
            ...canonical.slice(at(dataKind.header) + 1),
        ];
        const withoutKind = (kind: number) =>
            canonical.filter((reference) => reference.kind !== kind);
        for (const inventory of [
            [header, ...withoutKind(dataKind.header)],
            withHeader({ ...header, offset: 1 }),
            withHeader({ ...header, length: 0 }),
            withHeader({
                ...header,
                length: registration.maximumHeaderBytes + 1,
            }),
            withHeader(
                { ...header, length: 10 },
                { ...header, offset: 10, length: 10 },
            ),
            [...canonical, { ...header, kind: 12 }],
        ])
            expectRefused(
                stored(manifestAt(1, inventory)),
                1,
                'Noncanonical participant record inventory.',
            );
        const sourceCapsule = at(dataKind.sourceCapsule);
        for (const inventory of [
            withoutKind(dataKind.header),
            canonical.map((reference) =>
                reference.kind === dataKind.signature
                    ? { ...reference, length: reference.length - 1 }
                    : reference,
            ),
            withoutKind(dataKind.sourceCapsule),
            [
                ...canonical.slice(0, sourceCapsule),
                { ...header, kind: dataKind.proposal },
                ...canonical.slice(sourceCapsule),
            ],
        ])
            expectRefused(
                stored(manifestAt(1, inventory)),
                1,
                'Participant records do not match the generation.',
            );
    });

    it('decodes a preparation root and refuses a missing or truncated suffix', () => {
        const generation = rootGeneration.preparation;
        const manifest = manifestAt(
            generation,
            records([
                ...enrollment.slice(0, -1),
                [dataKind.proposal, 100],
                [dataKind.proposalSignature, registration.signatureBytes],
                enrollment[enrollment.length - 1],
            ]),
        );
        const bytes = stored(manifest, [filled(3, 7)]);
        expect(decodeManifest(bytes, generation, limits)).toEqual({
            ...manifest,
            suffixes: { preparation: filled(3, 7) },
        });
        expectRefused(
            stored(manifest),
            generation,
            'Missing participant root suffix.',
        );
        expectRefused(
            bytes.slice(0, -1),
            generation,
            'Truncated participant root suffix.',
        );
    });
});
