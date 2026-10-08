import { describe, expect, it } from 'vitest';

import {
    extractProofGraphPrefix,
    hasProofHashLayout,
    isProofChallengeInput,
    parseProofHashInput,
    proofGraphHasCollision,
    proofGraphPrefix,
    proofGraphReferences,
    type ProofGraphEntry,
    type ProofGraphInput,
} from '#tests/proof-hash-domain-model.js';

// Independently maintained completion-profile ballot operands from the Rust relation descriptor,
// original-PID role and native hash framing.
// This builder shares no framing code with the recognizer under test.
const number = (value: number) => {
    const bytes = Buffer.alloc(4);
    bytes.writeUInt32LE(value);
    return bytes;
};
const item = (type: number, value: Buffer) => {
    const header = Buffer.alloc(6);
    header.writeUInt16LE(type);
    header.writeUInt32LE(value.length, 2);
    return Buffer.concat([header, value]);
};
const ascii = (value: string) =>
    item(2, Buffer.concat([number(value.length), Buffer.from(value)]));
const roleHeader = Buffer.alloc(8);
roleHeader.writeUInt16LE(1);
roleHeader.writeUInt16LE(1, 2);
roleHeader.writeUInt32LE(5, 4);
const role = Buffer.concat([
    roleHeader,
    ascii('sealed-lattice/ballot-proof/v2'),
    ascii('ab'.repeat(64)),
    item(6, Buffer.alloc(64, 1)),
    item(6, Buffer.alloc(64, 2)),
    item(3, Buffer.alloc(2)),
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
    Buffer.from('linked-scored-ballot/1'),
    Buffer.alloc(16),
    Buffer.alloc(16),
    Buffer.alloc(16),
    Buffer.alloc(776),
    Buffer.alloc(16),
    Buffer.alloc(28672136),
];

describe('ballot hash domain correspondence model', () => {
    it('recognizes the six independently framed full-input families', () => {
        const fixtures = [
            [
                'leaf',
                frame(true, 'leaf', [
                    number(0),
                    number(9),
                    Buffer.alloc(128),
                    Buffer.alloc(576),
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
            const parsed = parseProofHashInput(input);
            expect(parsed?.family).toBe(family);
            expect(parsed?.owner).toBe('ab'.repeat(64));
            expect(parsed && hasProofHashLayout(parsed)).toBe(true);
            expect(isProofChallengeInput(input, new Set())).toBe(true);
            expect(
                isProofChallengeInput(input, new Set(['ab'.repeat(64)])),
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
            [0, 262143, 576],
            [1, 262143, 1632],
            [2, 262143, 48],
            [18, 3, 48],
        ]) {
            const parsed = parseProofHashInput(
                frame(true, 'leaf', [
                    number(stage),
                    number(index),
                    Buffer.alloc(128),
                    Buffer.alloc(width),
                ]),
            );
            expect(parsed).toBeDefined();
            expect(hasProofHashLayout(parsed!)).toBe(true);
        }
        for (const [stage, index, width] of [
            [0, 262144, 576],
            [1, 0, 576],
            [18, 4, 48],
            [19, 0, 48],
        ]) {
            const parsed = parseProofHashInput(
                frame(true, 'leaf', [
                    number(stage),
                    number(index),
                    Buffer.alloc(128),
                    Buffer.alloc(width),
                ]),
            );
            expect(parsed).toBeDefined();
            expect(hasProofHashLayout(parsed!)).toBe(false);
        }
    });

    it('keeps opaque malformed fields inside the raw domain but rejects wrong layouts separately', () => {
        for (const input of [
            frame(true, 'leaf', [
                number(0xffffffff),
                number(0xffffffff),
                Buffer.alloc(128),
                Buffer.alloc(576, 255),
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
            const parsed = parseProofHashInput(input);
            expect(parsed).toBeDefined();
            expect(hasProofHashLayout(parsed!)).toBe(false);
        }
        const terminal = parseProofHashInput(
            frame(true, 'message-root', [
                context,
                number(20),
                Buffer.alloc(128),
                Buffer.alloc(48, 255),
            ]),
        );
        expect(terminal).toBeDefined();
        expect(hasProofHashLayout(terminal!)).toBe(true);
        expect(terminal?.references).toEqual([context]);
        // Layout acceptance does not assert that these all-ones scalars decode.
    });

    it('routes partial contexts to the auxiliary function even though a generic verifier can hash them', () => {
        const complete = frame(true, 'statement', contextFields());
        const prefixBytes = complete.length - 28672136;
        for (const suffixLength of [0, 1, 1275, 28672136 - 1]) {
            const partial = complete.subarray(0, prefixBytes + suffixLength);
            expect(parseProofHashInput(partial)).toBeUndefined();
        }
        const changedDeclaration = contextFields();
        changedDeclaration[6] = Buffer.alloc(1275);
        expect(
            parseProofHashInput(frame(true, 'statement', changedDeclaration)),
        ).toBeUndefined();
        // A recipient-key API name cannot change the classification of bytes
        // imitating a partial context, and cannot make it a resolved instance.
        const keyDigestInput = complete.subarray(0, 64 + 65536 * 21);
        expect(isProofChallengeInput(keyDigestInput, new Set())).toBe(false);
    });

    it('refuses framing and ASCII aliases without interpreting their caller', () => {
        const good = frame(true, 'leaf', [
            number(0),
            number(0),
            Buffer.alloc(128),
            Buffer.alloc(576),
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
                Buffer.alloc(576),
            ]),
            frame(true, 'leaf', [
                number(0),
                number(0),
                Buffer.alloc(128),
                Buffer.alloc(145),
            ]),
        ])
            expect(parseProofHashInput(input)).toBeUndefined();
        expect(parseProofHashInput(Buffer.from(good))).toEqual(
            parseProofHashInput(good),
        );
    });

    it('keeps the signing-key and participant-identity dependency inputs auxiliary', () => {
        // FIPS204 Algorithms 6, 32 and 33: seed, secret-vector and pk hash.
        for (const length of [34, 66, 1952])
            for (const pattern of [0, 1, 255])
                expect(
                    parseProofHashInput(Buffer.alloc(length, pattern)),
                ).toBeUndefined();
        // The foundation tuple starts with its schema/version, not a proof tag.
        const participantIdentity = Buffer.alloc(2100);
        participantIdentity.set([1, 0, 1, 0]);
        expect(parseProofHashInput(participantIdentity)).toBeUndefined();
        // This is a raw-domain control, not a native key-generation trace.
    });

    it('exposes the exact chain references rather than the hexadecimal owner encoding', () => {
        const verifier = parseProofHashInput(
            frame(false, 'verifier-message', [context, state, number(4)]),
        )!;
        expect(verifier.references.map((value) => value[0])).toEqual([
            11, 12, 13,
        ]);
        const chain = parseProofHashInput(
            frame(false, 'chain-state', [context, state, Buffer.alloc(64, 24)]),
        )!;
        expect(chain.references.map((value) => value[0])).toEqual([11, 12, 24]);
    });
});

const alphabet = 32;
const word = (prefix: number, tail = 0) => prefix * alphabet + tail;
const entry = (
    input: ProofGraphInput,
    prefix: number,
    tail = 0,
): ProofGraphEntry => ({ input, output: word(prefix, tail) });
const firstQuery: ProofGraphInput = {
    kind: 'verifier',
    role: 'corrupt-a',
    context: 1,
    state: [0, 0],
    round: 1,
};
const nextQuery: ProofGraphInput = {
    kind: 'verifier',
    role: 'corrupt-a',
    context: 1,
    state: [3, 7],
    round: 2,
};
const graph = (): ProofGraphEntry[] => [
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
const without = (database: readonly ProofGraphEntry[], prefix: number) =>
    database.filter(
        (record) => proofGraphPrefix(record.output, alphabet) !== prefix,
    );

describe('reduced ballot reference closure', () => {
    it('extracts the fixed instance, complete challenge and indexed partial oracle', () => {
        expect(extractProofGraphPrefix(graph(), nextQuery, alphabet)).toEqual({
            instance: 'false-a',
            messages: [67],
            oracles: [[7, 9]],
        });
        expect(
            extractProofGraphPrefix(without(graph(), 5), nextQuery, alphabet),
        ).toEqual({
            instance: 'false-a',
            messages: [67],
            oracles: [[null, 9]],
        });
        expect(
            [...proofGraphReferences(graph(), nextQuery, alphabet)].sort(
                (a, b) => a - b,
            ),
        ).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8]);
    });

    it('requires a complete canonical context and every prior challenge link', () => {
        for (const missing of [1, 2, 3, 7])
            expect(
                extractProofGraphPrefix(
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
            extractProofGraphPrefix(malformed, nextQuery, alphabet),
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
            extractProofGraphPrefix(unresolved, nextQuery, alphabet),
        ).toBeUndefined();
    });

    it('checks role, context, round, complete message and initial state bindings', () => {
        const changes: [number, ProofGraphInput][] = [
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
                extractProofGraphPrefix(database, nextQuery, alphabet),
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
        ] satisfies ProofGraphInput[]) {
            const database = graph();
            database[4] = { input, output: database[4].output };
            // A prefix-only lookup finds the hostile record; typed extraction
            // must refuse to use it at the requested original leaf position.
            expect(
                database.find(
                    (record) => proofGraphPrefix(record.output, alphabet) === 5,
                ),
            ).toBeDefined();
            expect(
                extractProofGraphPrefix(database, nextQuery, alphabet)?.oracles,
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
            extractProofGraphPrefix(wrongLevel, nextQuery, alphabet)?.oracles,
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
        expect(proofGraphHasCollision([...graph(), foreign], alphabet)).toBe(
            false,
        );
        expect(
            extractProofGraphPrefix([...graph(), foreign], nextQuery, alphabet),
        ).toEqual(extractProofGraphPrefix(graph(), nextQuery, alphabet));
        const collision = {
            ...foreign,
            input: { ...foreign.input, role: 'corrupt-a' },
        };
        expect(proofGraphHasCollision([...graph(), collision], alphabet)).toBe(
            true,
        );
        expect(
            extractProofGraphPrefix(
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
        const additions: ProofGraphInput[] = [
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
                const references = proofGraphReferences(
                    database,
                    input,
                    alphabet,
                );
                for (let output = 0; output < alphabet ** 2; output++) {
                    const extended = [...database, { input, output }];
                    if (proofGraphHasCollision(extended, alphabet)) continue;
                    for (const query of database
                        .map((record) => record.input)
                        .filter((candidate) => candidate.kind === 'verifier')) {
                        const before = extractProofGraphPrefix(
                            database,
                            query,
                            alphabet,
                        );
                        const after = extractProofGraphPrefix(
                            extended,
                            query,
                            alphabet,
                        );
                        if (
                            references.has(proofGraphPrefix(output, alphabet))
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

describe('mixed-width finite-family reference closure', () => {
    const maximumTags = 3;
    const shortGraph = () =>
        graph().map((record) => ({
            ...record,
            output: record.output * alphabet,
        }));
    const longGraph = () =>
        shortGraph().map((record, index) => {
            let input: ProofGraphInput = {
                ...record.input,
                role: 'corrupt-long',
            };
            if (input.kind === 'context')
                input = {
                    ...input,
                    messageTags: 3,
                    arithmeticKey: 'long-relation',
                };
            if (input.kind === 'verifier')
                input = {
                    ...input,
                    state: input.round === 1 ? [0, 0, 0] : [3, 7, 11],
                };
            if (input.kind === 'chain')
                input = { ...input, message: word(2, 3) * alphabet + 4 };
            return { input, output: record.output + (index === 1 ? 4 : 0) };
        });
    const query = (database: readonly ProofGraphEntry[]) =>
        database[database.length - 1].input;

    it('compares the complete relation word and chain tail, ignoring only unused maximum-word suffixes', () => {
        const short = shortGraph(),
            long = longGraph();
        expect(
            extractProofGraphPrefix(short, query(short), alphabet, maximumTags)
                ?.messages,
        ).toEqual([word(2, 3)]);
        expect(
            extractProofGraphPrefix(long, query(long), alphabet, maximumTags)
                ?.messages,
        ).toEqual([word(2, 3) * alphabet + 4]);
        short[1].output += 9;
        expect(
            extractProofGraphPrefix(short, query(short), alphabet, maximumTags),
        ).toBeDefined();
        long[1].output += 1;
        expect(
            extractProofGraphPrefix(long, query(long), alphabet, maximumTags),
        ).toBeUndefined();
        const changedTail = longGraph();
        changedTail[6].output += alphabet;
        expect(
            extractProofGraphPrefix(
                changedTail,
                query(changedTail),
                alphabet,
                maximumTags,
            ),
        ).toBeUndefined();
        // The role's first tag is insufficient to replace a relation-sized word.
        expect(proofGraphPrefix(long[1].output, alphabet, maximumTags)).toBe(2);
    });

    it('resolves the width only from a complete context, including a late-arriving context', () => {
        const database = longGraph();
        const unresolved = database.slice(1);
        expect(
            extractProofGraphPrefix(
                unresolved,
                query(database),
                alphabet,
                maximumTags,
            ),
        ).toBeUndefined();
        expect(
            proofGraphReferences(
                unresolved,
                database[0].input,
                alphabet,
                maximumTags,
            ).has(1),
        ).toBe(true);
        expect(
            extractProofGraphPrefix(
                [...unresolved, database[0]],
                query(database),
                alphabet,
                maximumTags,
            ),
        ).toEqual(
            extractProofGraphPrefix(
                database,
                query(database),
                alphabet,
                maximumTags,
            ),
        );
        const incompatible = [...database];
        incompatible[0] = {
            ...database[0],
            input: {
                kind: 'context',
                role: 'corrupt-long',
                instance: 'false-a',
                canonical: true,
                messageTags: 2,
            },
        };
        expect(
            extractProofGraphPrefix(
                incompatible,
                query(database),
                alphabet,
                maximumTags,
            ),
        ).toBeUndefined();
        expect(
            proofGraphReferences(
                [],
                query(database),
                alphabet,
                maximumTags,
            ).has(0),
        ).toBe(true);
    });

    it('keeps duplicate queries idempotent and counts collisions only between distinct inputs in one role', () => {
        const database = longGraph();
        expect(
            proofGraphHasCollision(
                [...database, database[0]],
                alphabet,
                maximumTags,
            ),
        ).toBe(false);
        expect(() =>
            proofGraphHasCollision(
                [
                    ...database,
                    { ...database[0], output: database[0].output + 1 },
                ],
                alphabet,
                maximumTags,
            ),
        ).toThrow('two different output words');
        const alias = {
            ...database[0],
            input: {
                kind: 'context',
                role: 'corrupt-long',
                instance: 'different',
                canonical: true,
            } satisfies ProofGraphInput,
        };
        expect(
            proofGraphHasCollision([...database, alias], alphabet, maximumTags),
        ).toBe(true);
        expect(
            proofGraphHasCollision(
                [...database, ...shortGraph()],
                alphabet,
                maximumTags,
            ),
        ).toBe(false);
    });

    it('exhausts mixed-width words and covers both gain and loss of a fixed bad-prefix predicate', () => {
        // A finite mathematical state, not a proof verifier: a false instance
        // crosses from state zero to one at the second challenge iff a
        // resolved queried leaf equals 7 and the relation word ends in zero.
        const bad = (database: readonly ProofGraphEntry[]) =>
            !proofGraphHasCollision(database, alphabet, maximumTags) &&
            database.some(
                ({ input, output }) =>
                    input.kind === 'verifier' &&
                    proofGraphPrefix(
                        output,
                        alphabet,
                        maximumTags,
                        input.state.length,
                    ) %
                        alphabet ===
                        0 &&
                    extractProofGraphPrefix(
                        database,
                        input,
                        alphabet,
                        maximumTags,
                    )?.oracles.some((oracle) => oracle[0] === 7),
            );
        const complete = [...shortGraph(), ...longGraph()];
        const missing = complete.filter(
            (record) =>
                record.input.kind !== 'leaf' || record.input.index !== 0,
        );
        expect(bad(missing)).toBe(false);
        expect(bad(complete)).toBe(true);
        const changedChallenge = shortGraph();
        changedChallenge[changedChallenge.length - 1].output += alphabet;
        expect(bad(shortGraph())).toBe(true);
        expect(bad(changedChallenge)).toBe(false);
        const collision = {
            input: {
                kind: 'context',
                role: 'corrupt-a',
                instance: 'different',
                canonical: true,
            } satisfies ProofGraphInput,
            output: complete[0].output,
        };
        expect(bad([...complete, collision])).toBe(false);
        expect(
            proofGraphHasCollision(
                [...complete, collision],
                alphabet,
                maximumTags,
            ),
        ).toBe(true);
        const violations: number[] = [];
        let comparisons = 0,
            referenceChanges = 0;
        for (const database of [
            complete,
            missing,
            complete.filter((record) => record.input.kind !== 'context'),
        ]) {
            const input: ProofGraphInput = {
                kind: 'leaf',
                role: 'corrupt-a',
                stage: 0,
                index: 0,
                value: 7,
                canonical: true,
            };
            if (
                database.some(
                    (record) =>
                        JSON.stringify(record.input) === JSON.stringify(input),
                )
            )
                continue;
            const references = proofGraphReferences(
                database,
                input,
                alphabet,
                maximumTags,
            );
            for (let output = 0; output < alphabet ** maximumTags; output++) {
                const extended = [...database, { input, output }];
                if (proofGraphHasCollision(extended, alphabet, maximumTags))
                    continue;
                if (
                    references.has(
                        proofGraphPrefix(output, alphabet, maximumTags),
                    )
                ) {
                    if (bad(database) !== bad(extended)) referenceChanges++;
                } else {
                    if (bad(extended) !== bad(database))
                        violations.push(output);
                    comparisons++;
                }
            }
        }
        expect(violations).toEqual([]);
        expect(comparisons).toBeGreaterThan(0);
        expect(referenceChanges).toBeGreaterThan(0);
    });
});
