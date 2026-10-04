import { describe, expect, it } from 'vitest';

import {
    extractRegistrationGraphPrefix,
    hasRegistrationHashLayout,
    isRegistrationChallengeInput,
    parseRegistrationHashInput,
    registrationGraphHasCollision,
    registrationGraphPrefix,
    registrationGraphReferences,
    type RegistrationGraphEntry,
    type RegistrationGraphInput,
} from '#tests/registration-hash-domain-model.js';

// Independently maintained fixture operands from registration_relation(),
// context_parameters(), registration_proof_role() and the native hash framing.
// This builder shares no framing code with the recognizer under test.
const number = (value: number) => {
    const bytes = Buffer.alloc(4);
    bytes.writeUInt32LE(value);
    return bytes;
};
const role = Buffer.concat([
    Buffer.from('registered-recipient-key/1'),
    Buffer.alloc(64, 1),
    Buffer.alloc(64, 2),
    Buffer.from('ab'.repeat(64)),
]);
const fixedPrefix = Buffer.alloc(64);
fixedPrefix.write('sealed-lattice/fixed-hash/v1');
const frame = (fixed: boolean, name: string, fields: readonly Buffer[]) => {
    const parts = [Buffer.from(`bounded-proof/${name}`), role, ...fields];
    return Buffer.concat([
        ...(fixed ? [fixedPrefix] : []),
        ...parts.flatMap((part) => [number(part.length), part]),
    ]);
};
const context = Buffer.alloc(64, 11);
const state = Buffer.concat([
    Buffer.alloc(64, 12),
    Buffer.alloc(64, 13),
    Buffer.alloc(262144 - 128, 14),
]);
const contextFields = () => [
    Buffer.from('recipient-registration-key/1'),
    Buffer.alloc(16),
    Buffer.alloc(16),
    Buffer.alloc(16),
    Buffer.alloc(180),
    Buffer.alloc(16),
    Buffer.alloc(28 + 2 * 65536 * 21),
];

describe('registration hash domain correspondence model', () => {
    it('recognizes the six independently framed full-input families', () => {
        const fixtures = [
            [
                'leaf',
                frame(true, 'leaf', [
                    number(0),
                    number(9),
                    Buffer.alloc(128),
                    Buffer.alloc(144),
                ]),
                [],
            ],
            [
                'node',
                frame(true, 'node', [
                    number(2),
                    number(4),
                    Buffer.alloc(64, 21),
                    Buffer.alloc(64, 22),
                ]),
                [21, 22],
            ],
            [
                'message-root',
                frame(true, 'message-root', [
                    context,
                    number(2),
                    Buffer.alloc(128),
                    Buffer.alloc(64, 23),
                    Buffer.alloc(48),
                ]),
                [11, 23],
            ],
            ['statement', frame(true, 'statement', contextFields()), []],
            [
                'verifier-message',
                frame(false, 'verifier-message', [context, state, number(21)]),
                [11, 12, 13],
            ],
            [
                'chain-state',
                frame(false, 'chain-state', [
                    context,
                    state,
                    Buffer.alloc(64, 24),
                ]),
                [11, 12, 24],
            ],
        ] as const;
        for (const [family, input, referenceMarkers] of fixtures) {
            const parsed = parseRegistrationHashInput(input);
            expect(parsed?.family).toBe(family);
            expect(parsed?.owner).toBe('ab'.repeat(64));
            expect(parsed && hasRegistrationHashLayout(parsed)).toBe(true);
            expect(isRegistrationChallengeInput(input, new Set())).toBe(true);
            expect(
                isRegistrationChallengeInput(input, new Set(['ab'.repeat(64)])),
            ).toBe(false);
            const expectedReferences = referenceMarkers.map((marker) =>
                Buffer.alloc(64, marker),
            );
            expect(parsed?.references).toEqual(expectedReferences);
            // The independently enumerated labels occupy literal input bytes.
            for (const reference of expectedReferences)
                expect(input.indexOf(reference)).toBeGreaterThanOrEqual(0);
        }
    });

    it('covers every leaf width and the last stage and index boundaries', () => {
        for (const [stage, index, width] of [
            [0, 262143, 144],
            [1, 262143, 288],
            [2, 262143, 48],
            [18, 3, 48],
        ]) {
            const parsed = parseRegistrationHashInput(
                frame(true, 'leaf', [
                    number(stage),
                    number(index),
                    Buffer.alloc(128),
                    Buffer.alloc(width),
                ]),
            );
            expect(parsed).toBeDefined();
            expect(hasRegistrationHashLayout(parsed!)).toBe(true);
        }
        for (const [stage, index, width] of [
            [0, 262144, 144],
            [1, 0, 144],
            [18, 4, 48],
            [19, 0, 48],
        ]) {
            const parsed = parseRegistrationHashInput(
                frame(true, 'leaf', [
                    number(stage),
                    number(index),
                    Buffer.alloc(128),
                    Buffer.alloc(width),
                ]),
            );
            expect(parsed).toBeDefined();
            expect(hasRegistrationHashLayout(parsed!)).toBe(false);
        }
    });

    it('keeps opaque malformed fields inside the raw domain but rejects wrong layouts separately', () => {
        for (const input of [
            frame(true, 'leaf', [
                number(0xffffffff),
                number(0xffffffff),
                Buffer.alloc(128),
                Buffer.alloc(144, 255),
            ]),
            frame(true, 'node', [
                number(0),
                number(0),
                Buffer.alloc(64),
                Buffer.alloc(64),
            ]),
            frame(true, 'message-root', [
                context,
                number(2),
                Buffer.alloc(128),
                Buffer.alloc(64),
            ]),
            frame(false, 'verifier-message', [context, state, number(0)]),
        ]) {
            const parsed = parseRegistrationHashInput(input);
            expect(parsed).toBeDefined();
            expect(hasRegistrationHashLayout(parsed!)).toBe(false);
        }
        const terminal = parseRegistrationHashInput(
            frame(true, 'message-root', [
                context,
                number(20),
                Buffer.alloc(128),
                Buffer.alloc(48, 255),
            ]),
        );
        expect(terminal).toBeDefined();
        expect(hasRegistrationHashLayout(terminal!)).toBe(true);
        expect(terminal?.references).toEqual([context]);
        // Layout acceptance does not assert that these all-ones scalars decode.
    });

    it('routes partial contexts to the auxiliary function even though a generic verifier can hash them', () => {
        const complete = frame(true, 'statement', contextFields());
        const prefixBytes = complete.length - (28 + 2 * 65536 * 21);
        for (const suffixLength of [0, 1, 1275, 28 + 2 * 65536 * 21 - 1]) {
            const partial = complete.subarray(0, prefixBytes + suffixLength);
            expect(parseRegistrationHashInput(partial)).toBeUndefined();
        }
        const changedDeclaration = contextFields();
        changedDeclaration[6] = Buffer.alloc(1275);
        expect(
            parseRegistrationHashInput(
                frame(true, 'statement', changedDeclaration),
            ),
        ).toBeUndefined();
        // A recipient-key API name cannot change the classification of bytes
        // imitating a partial context, and cannot make it a resolved instance.
        const keyDigestInput = complete.subarray(0, 64 + 65536 * 21);
        expect(isRegistrationChallengeInput(keyDigestInput, new Set())).toBe(
            false,
        );
    });

    it('refuses framing and ASCII aliases without interpreting their caller', () => {
        const good = frame(true, 'leaf', [
            number(0),
            number(0),
            Buffer.alloc(128),
            Buffer.alloc(144),
        ]);
        const uppercaseOwner = Buffer.from(good);
        const ownerOffset = good.indexOf(Buffer.from('ab'.repeat(64)));
        uppercaseOwner[ownerOffset] = 'A'.charCodeAt(0);
        const highDomainBit = Buffer.from(good);
        highDomainBit[68] |= 128;
        const changedLength = Buffer.from(good);
        changedLength.writeUInt32LE(0xffffffff, 64);
        for (const input of [
            uppercaseOwner,
            highDomainBit,
            changedLength,
            Buffer.concat([good, Buffer.from([0])]),
            good.subarray(1),
            frame(false, 'leaf', [
                number(0),
                number(0),
                Buffer.alloc(128),
                Buffer.alloc(144),
            ]),
            frame(true, 'leaf', [
                number(0),
                number(0),
                Buffer.alloc(128),
                Buffer.alloc(145),
            ]),
        ])
            expect(parseRegistrationHashInput(input)).toBeUndefined();
        expect(parseRegistrationHashInput(Buffer.from(good))).toEqual(
            parseRegistrationHashInput(good),
        );
    });

    it('keeps the signing-key and participant-identity dependency inputs auxiliary', () => {
        // FIPS204 Algorithms 6, 32 and 33: seed, secret-vector and pk hash.
        for (const length of [34, 66, 1952])
            for (const pattern of [0, 1, 255])
                expect(
                    parseRegistrationHashInput(Buffer.alloc(length, pattern)),
                ).toBeUndefined();
        // The foundation tuple starts with its schema/version, not a proof tag.
        const participantIdentity = Buffer.alloc(2100);
        participantIdentity.set([1, 0, 1, 0]);
        expect(parseRegistrationHashInput(participantIdentity)).toBeUndefined();
        // This is a raw-domain control, not a native key-generation trace.
    });

    it('exposes the exact chain references rather than the hexadecimal owner encoding', () => {
        const verifier = parseRegistrationHashInput(
            frame(false, 'verifier-message', [context, state, number(4)]),
        )!;
        expect(verifier.references.map((value) => value[0])).toEqual([
            11, 12, 13,
        ]);
        const chain = parseRegistrationHashInput(
            frame(false, 'chain-state', [context, state, Buffer.alloc(64, 24)]),
        )!;
        expect(chain.references.map((value) => value[0])).toEqual([11, 12, 24]);
    });
});

const alphabet = 32;
const word = (prefix: number, tail = 0) => prefix * alphabet + tail;
const entry = (
    input: RegistrationGraphInput,
    prefix: number,
    tail = 0,
): RegistrationGraphEntry => ({ input, output: word(prefix, tail) });
const firstQuery: RegistrationGraphInput = {
    kind: 'verifier',
    role: 'corrupt-a',
    context: 1,
    state: [0, 0],
    round: 1,
};
const nextQuery: RegistrationGraphInput = {
    kind: 'verifier',
    role: 'corrupt-a',
    context: 1,
    state: [3, 7],
    round: 2,
};
const graph = (): RegistrationGraphEntry[] => [
    entry(
        {
            kind: 'context',
            role: 'corrupt-a',
            instance: 'false-a',
            canonical: true,
        },
        1,
    ),
    entry(firstQuery, 2, 3),
    entry(
        { kind: 'message', role: 'corrupt-a', context: 1, round: 1, tree: 4 },
        3,
        7,
    ),
    entry(
        {
            kind: 'node',
            role: 'corrupt-a',
            stage: 0,
            level: 1,
            left: 5,
            right: 6,
        },
        4,
        4,
    ),
    entry(
        {
            kind: 'leaf',
            role: 'corrupt-a',
            stage: 0,
            index: 0,
            value: 7,
            canonical: true,
        },
        5,
        2,
    ),
    entry(
        {
            kind: 'leaf',
            role: 'corrupt-a',
            stage: 0,
            index: 1,
            value: 9,
            canonical: true,
        },
        6,
        1,
    ),
    entry(
        {
            kind: 'chain',
            role: 'corrupt-a',
            context: 1,
            message: word(2, 3),
            root: 3,
        },
        7,
        11,
    ),
    entry(nextQuery, 8, 0),
];
const without = (database: readonly RegistrationGraphEntry[], prefix: number) =>
    database.filter(
        (record) => registrationGraphPrefix(record.output, alphabet) !== prefix,
    );

describe('reduced registration reference closure', () => {
    it('extracts the fixed instance, complete challenge and indexed partial oracle', () => {
        expect(
            extractRegistrationGraphPrefix(graph(), nextQuery, alphabet),
        ).toEqual({ instance: 'false-a', messages: [67], oracles: [[7, 9]] });
        expect(
            extractRegistrationGraphPrefix(
                without(graph(), 5),
                nextQuery,
                alphabet,
            ),
        ).toEqual({
            instance: 'false-a',
            messages: [67],
            oracles: [[null, 9]],
        });
        expect(
            [...registrationGraphReferences(graph(), nextQuery, alphabet)].sort(
                (a, b) => a - b,
            ),
        ).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    });

    it('requires a complete canonical context and every prior challenge link', () => {
        for (const missing of [1, 2, 3, 7])
            expect(
                extractRegistrationGraphPrefix(
                    without(graph(), missing),
                    nextQuery,
                    alphabet,
                ),
            ).toBeUndefined();
        const malformed = graph();
        malformed[0] = entry(
            {
                kind: 'context',
                role: 'corrupt-a',
                instance: 'false-a',
                canonical: false,
            },
            1,
        );
        expect(
            extractRegistrationGraphPrefix(malformed, nextQuery, alphabet),
        ).toBeUndefined();
        const unresolved = without(graph(), 1);
        // An input naming the context is insufficient: this would be the
        // erroneous label-only resolver that accepts an auxiliary preimage.
        expect(
            unresolved.some(
                (record) =>
                    record.input.kind === 'verifier' &&
                    record.input.context === 1,
            ),
        ).toBe(true);
        expect(
            extractRegistrationGraphPrefix(unresolved, nextQuery, alphabet),
        ).toBeUndefined();
    });

    it('checks role, context, round, complete message and initial state bindings', () => {
        const changes: [number, RegistrationGraphInput][] = [
            [1, { ...graph()[1].input, role: 'corrupt-b' }],
            [1, { ...firstQuery, context: 9 }],
            [1, { ...firstQuery, round: 2 }],
            [1, { ...firstQuery, state: [0, 1] }],
            [
                2,
                {
                    kind: 'message',
                    role: 'corrupt-a',
                    context: 1,
                    round: 2,
                    tree: 4,
                },
            ],
            [
                6,
                {
                    kind: 'chain',
                    role: 'corrupt-a',
                    context: 1,
                    message: word(2, 4),
                    root: 3,
                },
            ],
        ];
        for (const [index, input] of changes) {
            const database = graph();
            database[index] = { input, output: database[index].output };
            expect(
                extractRegistrationGraphPrefix(database, nextQuery, alphabet),
            ).toBeUndefined();
        }
    });

    it('cannot replace an indexed leaf with another role, stage or position', () => {
        for (const input of [
            { ...graph()[4].input, role: 'corrupt-b' },
            {
                kind: 'leaf',
                role: 'corrupt-a',
                stage: 1,
                index: 0,
                value: 7,
                canonical: true,
            },
            {
                kind: 'leaf',
                role: 'corrupt-a',
                stage: 0,
                index: 1,
                value: 7,
                canonical: true,
            },
            {
                kind: 'leaf',
                role: 'corrupt-a',
                stage: 0,
                index: 0,
                value: 7,
                canonical: false,
            },
        ] satisfies RegistrationGraphInput[]) {
            const database = graph();
            database[4] = { input, output: database[4].output };
            // A prefix-only lookup finds the hostile record; typed extraction
            // must refuse to use it at the requested original leaf position.
            expect(
                database.find(
                    (record) =>
                        registrationGraphPrefix(record.output, alphabet) === 5,
                ),
            ).toBeDefined();
            expect(
                extractRegistrationGraphPrefix(database, nextQuery, alphabet)
                    ?.oracles,
            ).toEqual([[null, 9]]);
        }
        const wrongLevel = graph();
        wrongLevel[3] = entry(
            {
                kind: 'node',
                role: 'corrupt-a',
                stage: 0,
                level: 2,
                left: 5,
                right: 6,
            },
            4,
            4,
        );
        expect(
            extractRegistrationGraphPrefix(wrongLevel, nextQuery, alphabet)
                ?.oracles,
        ).toEqual([[null, null]]);
    });

    it('permits cross-role prefix reuse but detects ambiguity inside one role', () => {
        const foreign = entry(
            {
                kind: 'context',
                role: 'corrupt-b',
                instance: 'false-b',
                canonical: true,
            },
            1,
        );
        expect(
            registrationGraphHasCollision([...graph(), foreign], alphabet),
        ).toBe(false);
        expect(
            extractRegistrationGraphPrefix(
                [...graph(), foreign],
                nextQuery,
                alphabet,
            ),
        ).toEqual(extractRegistrationGraphPrefix(graph(), nextQuery, alphabet));
        const collision = {
            ...foreign,
            input: { ...foreign.input, role: 'corrupt-a' },
        };
        expect(
            registrationGraphHasCollision([...graph(), collision], alphabet),
        ).toBe(true);
        expect(
            extractRegistrationGraphPrefix(
                [...graph(), collision],
                nextQuery,
                alphabet,
            ),
        ).toBeUndefined();
    });

    it('exhausts every new output word and preserves all earlier extractions outside references', () => {
        const databases = [
            [],
            graph(),
            ...[1, 2, 3, 4, 5, 7].map((prefix) => without(graph(), prefix)),
        ];
        const additions: RegistrationGraphInput[] = [
            ...graph().map((record) => record.input),
            {
                kind: 'context',
                role: 'corrupt-a',
                instance: 'false-b',
                canonical: true,
            },
            {
                kind: 'context',
                role: 'corrupt-b',
                instance: 'false-a',
                canonical: true,
            },
            {
                kind: 'verifier',
                role: 'corrupt-a',
                context: 19,
                state: [0, 0],
                round: 1,
            },
            {
                kind: 'verifier',
                role: 'corrupt-a',
                context: 1,
                state: [3, 7],
                round: 3,
            },
            {
                kind: 'message',
                role: 'corrupt-a',
                context: 1,
                round: 2,
                tree: 19,
            },
            {
                kind: 'chain',
                role: 'corrupt-a',
                context: 1,
                message: word(19, 2),
                root: 20,
            },
            {
                kind: 'node',
                role: 'corrupt-a',
                stage: 1,
                level: 1,
                left: 19,
                right: 20,
            },
            {
                kind: 'leaf',
                role: 'corrupt-a',
                stage: 0,
                index: 0,
                value: 17,
                canonical: true,
            },
            {
                kind: 'leaf',
                role: 'corrupt-a',
                stage: 0,
                index: 0,
                value: 17,
                canonical: false,
            },
        ];
        const violations: unknown[] = [];
        let compared = 0,
            changedOnReference = 0;
        for (const database of databases)
            for (const input of additions) {
                if (
                    database.some(
                        (record) =>
                            JSON.stringify(record.input) ===
                            JSON.stringify(input),
                    )
                )
                    continue;
                const references = registrationGraphReferences(
                    database,
                    input,
                    alphabet,
                );
                for (let output = 0; output < alphabet ** 2; output++) {
                    const extended = [...database, { input, output }];
                    if (registrationGraphHasCollision(extended, alphabet))
                        continue;
                    for (const query of database
                        .map((record) => record.input)
                        .filter((candidate) => candidate.kind === 'verifier')) {
                        const before = extractRegistrationGraphPrefix(
                            database,
                            query,
                            alphabet,
                        );
                        const after = extractRegistrationGraphPrefix(
                            extended,
                            query,
                            alphabet,
                        );
                        if (
                            references.has(
                                registrationGraphPrefix(output, alphabet),
                            )
                        ) {
                            if (
                                JSON.stringify(before) !== JSON.stringify(after)
                            )
                                changedOnReference++;
                        } else {
                            if (
                                JSON.stringify(before) !== JSON.stringify(after)
                            )
                                violations.push({
                                    input,
                                    output,
                                    before,
                                    after,
                                });
                            compared++;
                        }
                    }
                }
            }
        expect(violations).toEqual([]);
        expect(compared).toBeGreaterThan(0);
        expect(changedOnReference).toBeGreaterThan(0);
    });
});
