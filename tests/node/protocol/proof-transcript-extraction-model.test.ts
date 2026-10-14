import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
    ascii,
    item,
    itemType,
    tuple,
    unsigned,
    variable,
} from '#tests/node/protocol/reference/canonical-tuple.js';
import {
    proofRelationCatalogueEntry,
    type ProofRelationCatalogueEntry,
} from '#tests/proof-relation-catalogue-model.js';
import {
    extractRawProofPrefix as extractWithOwners,
    rawProofHashHasCollision,
    type RawProofHashRecord,
} from '#tests/proof-transcript-extraction-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import { protocolHashPrefix } from '#tests/word-proof-reference/transcript.js';

// These are raw hash transcripts, not proof fixtures. The zero polynomial
// statements have canonical encodings; no arithmetic truth or protocol
// authentication is supplied, and no verifier is called or overridden.
const domains = {
    setup: 'sealed-lattice/setup-contribution/v3',
    ballot: 'sealed-lattice/ballot-proof/v3',
    release: 'sealed-lattice/certified-release/v3',
};
const originalRole = (purpose: keyof typeof domains, owner = 'ab'.repeat(64)) =>
    tuple([
        ascii(domains[purpose]),
        ascii(owner),
        ...Array.from({ length: purpose === 'release' ? 3 : 2 }, (_, index) =>
            item(itemType.hash512, Buffer.alloc(64, index + 1)),
        ),
        item(itemType.unsigned16, unsigned(0, 2)),
    ]);
const frame = (
    role: Buffer,
    fixed: boolean,
    family: string,
    fields: readonly Buffer[],
) => {
    return Buffer.concat([
        ...(fixed ? [protocolHashPrefix] : []),
        ...[Buffer.from(`bounded-proof/${family}`), role, ...fields].map(
            (field) => variable(field),
        ),
    ]);
};
const field = compileSmallLimbProofFieldCensus();
const descriptors = proofRelationCatalogueEntry(deriveSupportedProfile(3, 2));

// These fixture owners are corrupt unless a control supplies the original
// honest-owner set explicitly. No active-role or accepted-log set is used.
const extractRawProofPrefix = (
    records: readonly RawProofHashRecord[],
    input: Buffer,
) => extractWithOwners(records, input, new Set());
const sameMessages = (
    actual: readonly Buffer[] | undefined,
    expected: readonly Buffer[],
) =>
    actual !== undefined &&
    actual.length === expected.length &&
    actual.every((value, index) => value.equals(expected[index]));

const fixture = (entry: ProofRelationCatalogueEntry, rounds = 21) => {
    // Bound this small-profile corpus before allocating the canonical input
    // and relation-sized transcript. Larger setup bodies are not needed.
    expect(entry.statementBytes).toBeLessThan(256n * 1024n * 1024n);
    const statement = Buffer.alloc(Number(entry.statementBytes));
    entry.header.copy(statement);
    if (entry.role === 'ballot') {
        statement[134] = 2;
        statement[135] = 1;
    }
    const role = originalRole(entry.role);
    const records: RawProofHashRecord[] = [];
    const record = (
        fixed: boolean,
        name: string,
        fields: readonly Buffer[],
        outputLength = 64,
    ) => {
        const input = frame(role, fixed, name, fields);
        const output = createHash('shake256', { outputLength })
            .update(input)
            .digest();
        const value = { input, output };
        records.push(value);
        return value;
    };
    // The statement's digest is the fixed hash of its raw bytes.
    const statementInput = Buffer.concat([protocolHashPrefix, statement]);
    const statementRecord = {
        input: statementInput,
        output: createHash('shake256', { outputLength: 64 })
            .update(statementInput)
            .digest(),
    };
    records.push(statementRecord);
    const context = record(true, 'statement', [
        Buffer.from(entry.relationTag),
        unsigned(2, 16),
        unsigned(field.transformRoot, 16),
        unsigned(7, 16),
        entry.encodedParameters,
        unsigned(field.modulus - 1n, 16),
        statementRecord.output,
    ]);
    const leaves: {
        stage: number;
        position: number;
        data: Buffer;
        record: RawProofHashRecord;
        parent: RawProofHashRecord;
    }[] = [];
    const tree = (stage: number, position: number, width: number) => {
        const data = Buffer.alloc(width);
        unsigned(field.modulus - 1n, 16).copy(data);
        const leaf = record(true, 'leaf', [
            unsigned(stage, 4),
            unsigned(position, 4),
            Buffer.alloc(128, 19),
            data,
        ]);
        let digest = leaf.output;
        let node = 262144 + position;
        let parent = leaf;
        for (let level = 1; node > 1; level++, node = Math.floor(node / 2)) {
            const sibling = Buffer.alloc(64, level + stage + 31);
            const pair = node % 2 === 0 ? [digest, sibling] : [sibling, digest];
            const next = record(true, 'node', [
                unsigned(stage, 4),
                unsigned(level, 4),
                ...pair,
            ]);
            if (level === 1) parent = next;
            digest = next.output;
        }
        leaves.push({ stage, position, data, record: leaf, parent });
        return digest;
    };
    const firstRoot = tree(0, 9, Number(entry.firstWidth));
    const secondRoot = tree(1, 131081, Number(entry.secondWidth));
    const messageBytes = Number(entry.messageBytes);
    let state = Buffer.alloc(messageBytes);
    const messages: Buffer[] = [];
    const responses: Buffer[][] = [];
    const verifiers: RawProofHashRecord[] = [];
    const chains: RawProofHashRecord[] = [];
    const messageRoots: RawProofHashRecord[] = [];
    for (let round = 1; round <= rounds; round++) {
        // Longer XOF reads retain a suffix unused by this relation.
        const verifier = record(
            false,
            'verifier-message',
            [context.output, state, unsigned(round, 4)],
            524288,
        );
        verifiers.push(verifier);
        if (round === rounds) break;
        const message = verifier.output.subarray(0, messageBytes);
        const parts =
            round === 1
                ? [firstRoot]
                : round === 2
                  ? [secondRoot, Buffer.alloc(48)]
                  : round === 20
                    ? [Buffer.alloc(48)]
                    : [Buffer.alloc(64, round + 79)];
        const response = record(true, 'message-root', [
            context.output,
            unsigned(round, 4),
            Buffer.alloc(128, round),
            ...parts,
        ]);
        const chain = record(
            false,
            'chain-state',
            [context.output, message, response.output],
            524288,
        );
        state = Buffer.concat([
            response.output,
            chain.output.subarray(0, messageBytes - 64),
        ]);
        messages.push(message);
        responses.push(parts);
        chains.push(chain);
        messageRoots.push(response);
    }
    return {
        records,
        query: verifiers[rounds - 1].input,
        statement,
        statementRecord,
        context,
        role,
        messages,
        responses,
        verifiers,
        chains,
        messageRoots,
        leaves,
        entry,
    };
};

describe('raw proof transcript backward extraction', () => {
    it('distinguishes complete raw inputs sharing their length and end bytes', () => {
        const role = originalRole('setup');
        const records = [3, 4].map((value) => {
            const input = frame(role, true, 'node', [
                unsigned(0, 4),
                unsigned(1, 4),
                Buffer.alloc(64, value),
                Buffer.alloc(64, 11),
            ]);
            const output = createHash('shake256', { outputLength: 64 })
                .update(input)
                .digest();
            return { input, output };
        });
        expect(records[0].input.length).toBe(records[1].input.length);
        expect(
            records[0].input
                .subarray(0, 64)
                .equals(records[1].input.subarray(0, 64)),
        ).toBe(true);
        expect(
            records[0].input
                .subarray(-64)
                .equals(records[1].input.subarray(-64)),
        ).toBe(true);
        expect(rawProofHashHasCollision(records, new Set())).toBe(false);
        expect(
            rawProofHashHasCollision(
                [
                    ...records,
                    {
                        input: Buffer.from(records[0].input),
                        output: Buffer.from(records[0].output),
                    },
                ],
                new Set(),
            ),
        ).toBe(false);
        const conflicting = Buffer.from(records[0].output);
        conflicting[0] ^= 1;
        expect(() =>
            rawProofHashHasCollision(
                [...records, { input: records[0].input, output: conflicting }],
                new Set(),
            ),
        ).toThrow('Inconsistent');
        expect(
            rawProofHashHasCollision(
                [
                    records[0],
                    { input: records[1].input, output: records[0].output },
                ],
                new Set(),
            ),
        ).toBe(true);
    });

    it('reconstructs every full native-shaped chain and its available leaves for all three purposes', () => {
        for (const entry of descriptors) {
            const value = fixture(entry);
            const result = extractRawProofPrefix(value.records, value.query);
            expect(result).toBeDefined();
            expect(sameMessages(result!.messages, value.messages)).toBe(true);
            expect(result!.responses).toEqual(value.responses);
            expect(result!.relation.arithmeticKey).toBe(entry.arithmeticKey);
            expect(result!.statement.equals(value.statement)).toBe(true);
            expect(result!.oracles).toHaveLength(19);
            for (const leaf of value.leaves) {
                expect(result!.oracles[leaf.stage].leaf(leaf.position)).toEqual(
                    leaf.data,
                );
                expect(
                    result!.oracles[leaf.stage].leaf(leaf.position + 1),
                ).toBeUndefined();
            }
            expect(result!.oracles[18].leaf(0)).toBeUndefined();
            expect(
                extractRawProofPrefix(value.records, value.verifiers[0].input)
                    ?.messages,
            ).toEqual([]);
        }
    });

    it('requires the context, its statement, complete messages and chain tails without demanding unused suffixes', () => {
        const value = fixture(descriptors[2]);
        const replace = (
            original: RawProofHashRecord,
            replacement: RawProofHashRecord,
        ) =>
            value.records.map((record) =>
                record === original ? replacement : record,
            );
        for (const missing of [
            value.statementRecord,
            value.context,
            value.verifiers[3],
            value.chains[3],
            value.messageRoots[3],
        ])
            expect(
                extractRawProofPrefix(
                    value.records.filter((record) => record !== missing),
                    value.query,
                ),
            ).toBeUndefined();
        for (const original of [value.verifiers[3], value.chains[3]]) {
            const usedBytes =
                Number(value.entry.messageBytes) -
                (original === value.chains[3] ? 64 : 0);
            const changed = Buffer.from(original.output);
            changed[usedBytes - 1] ^= 1; // The tag stays equal; the last used byte does not.
            expect(
                extractRawProofPrefix(
                    replace(original, { ...original, output: changed }),
                    value.query,
                ),
            ).toBeUndefined();
            expect(
                extractRawProofPrefix(
                    replace(original, {
                        ...original,
                        output: original.output.subarray(0, 64),
                    }),
                    value.query,
                ),
            ).toBeUndefined();
            const unused = Buffer.from(original.output);
            unused[usedBytes] ^= 1;
            expect(
                sameMessages(
                    extractRawProofPrefix(
                        replace(original, { ...original, output: unused }),
                        value.query,
                    )?.messages,
                    value.messages,
                ),
            ).toBe(true);
        }
        const extended = [
            ...value.records.map((record) => ({
                ...record,
                output: record.output.subarray(0, 64),
            })),
            ...value.records,
        ];
        expect(
            sameMessages(
                extractRawProofPrefix(extended, value.query)?.messages,
                value.messages,
            ),
        ).toBe(true);
        const conflict = Buffer.from(value.verifiers[2].output);
        conflict[200] ^= 1;
        expect(() =>
            extractRawProofPrefix(
                [...value.records, { ...value.verifiers[2], output: conflict }],
                value.query,
            ),
        ).toThrow('Inconsistent');
    });

    it('resolves the statement only through the unique canonical input with its digest', () => {
        const value = fixture(descriptors[1], 3);
        const withStatement = (input: Buffer) =>
            value.records.map((record) =>
                record === value.statementRecord
                    ? { input, output: record.output }
                    : record,
            );
        // Another statement under the same digest is a collision, whichever
        // of the two the context meant.
        const other = Buffer.from(value.statementRecord.input);
        other[other.length - 1] ^= 1;
        const colliding = [
            ...value.records,
            { input: other, output: value.statementRecord.output },
        ];
        expect(rawProofHashHasCollision(colliding, new Set())).toBe(true);
        expect(extractRawProofPrefix(colliding, value.query)).toBeUndefined();
        expect(
            rawProofHashHasCollision(colliding, new Set(['ab'.repeat(64)])),
        ).toBe(true);
        // A digest whose input is no canonical statement of the relation
        // resolves no instance.
        const changedHeader = Buffer.from(value.statementRecord.input);
        changedHeader[64] ^= 1;
        const truncated = value.statementRecord.input.subarray(0, -1);
        for (const input of [changedHeader, truncated])
            expect(
                extractRawProofPrefix(withStatement(input), value.query),
            ).toBeUndefined();
        // The digest of another statement leaves the context unresolved.
        const otherOutput = Buffer.from(value.statementRecord.output);
        otherOutput[0] ^= 1;
        expect(
            extractRawProofPrefix(
                value.records.map((record) =>
                    record === value.statementRecord
                        ? { input: record.input, output: otherOutput }
                        : record,
                ),
                value.query,
            ),
        ).toBeUndefined();
        expect(
            extractRawProofPrefix(value.records, value.query)?.statement.equals(
                value.statement,
            ),
        ).toBe(true);
    });

    it('binds every chain edge to its original role, context, round and canonical response', () => {
        const value = fixture(descriptors[2], 4);
        const width = Number(value.entry.messageBytes);
        const replace = (original: RawProofHashRecord, input: Buffer) =>
            value.records.map((record) =>
                record === original
                    ? { input, output: original.output }
                    : record,
            );
        const stateBeforeSecond = Buffer.concat([
            value.messageRoots[0].output,
            value.chains[0].output.subarray(0, width - 64),
        ]);
        const nonzeroInitial = Buffer.alloc(width);
        nonzeroInitial[width - 1] = 1;
        const scalar = Buffer.concat([
            unsigned(field.modulus, 16),
            Buffer.alloc(32),
        ]);
        const changed: [RawProofHashRecord, Buffer][] = [
            [
                value.chains[1],
                frame(value.role, false, 'chain-state', [
                    Buffer.alloc(64, 77),
                    value.messages[1],
                    value.messageRoots[1].output,
                ]),
            ],
            [
                value.chains[1],
                frame(
                    originalRole('release', 'cd'.repeat(64)),
                    false,
                    'chain-state',
                    [
                        value.context.output,
                        value.messages[1],
                        value.messageRoots[1].output,
                    ],
                ),
            ],
            [
                value.chains[1],
                frame(value.role, false, 'chain-state', [
                    value.context.output,
                    value.messages[1],
                    Buffer.alloc(64, 78),
                ]),
            ],
            [
                value.verifiers[1],
                frame(value.role, false, 'verifier-message', [
                    value.context.output,
                    stateBeforeSecond,
                    unsigned(3, 4),
                ]),
            ],
            [
                value.verifiers[0],
                frame(value.role, false, 'verifier-message', [
                    value.context.output,
                    nonzeroInitial,
                    unsigned(1, 4),
                ]),
            ],
            [
                value.messageRoots[1],
                frame(value.role, true, 'message-root', [
                    value.context.output,
                    unsigned(1, 4),
                    Buffer.alloc(128, 2),
                    ...value.responses[1],
                ]),
            ],
            [
                value.messageRoots[1],
                frame(value.role, true, 'message-root', [
                    value.context.output,
                    unsigned(2, 4),
                    Buffer.alloc(128, 2),
                    value.responses[1][0],
                ]),
            ],
            [
                value.messageRoots[1],
                frame(value.role, true, 'message-root', [
                    value.context.output,
                    unsigned(2, 4),
                    Buffer.alloc(128, 2),
                    value.responses[1][0],
                    scalar,
                ]),
            ],
        ];
        for (const [original, input] of changed)
            expect(
                extractRawProofPrefix(replace(original, input), value.query),
            ).toBeUndefined();
    });

    it('uses the fixed original honest-owner partition for both collision and extraction', () => {
        const value = fixture(descriptors[2], 2);
        const honestOwner = 'cd'.repeat(64);
        const honestRole = originalRole('release', honestOwner);
        const collision = [0, 1].map((stage) => ({
            input: frame(honestRole, true, 'node', [
                unsigned(stage, 4),
                unsigned(1, 4),
                Buffer.alloc(64),
                Buffer.alloc(64),
            ]),
            output: Buffer.alloc(64, 101),
        }));
        const records = [...value.records, ...collision];
        expect(rawProofHashHasCollision(records, new Set())).toBe(true);
        expect(rawProofHashHasCollision(records, new Set([honestOwner]))).toBe(
            false,
        );
        expect(
            sameMessages(
                extractWithOwners(records, value.query, new Set([honestOwner]))
                    ?.messages,
                value.messages,
            ),
        ).toBe(true);
        expect(
            extractWithOwners(
                value.records,
                value.query,
                new Set(['ab'.repeat(64)]),
            ),
        ).toBeUndefined();
    });

    it('keeps typed tree failures partial and refuses collisions even for unusable raw members', () => {
        const value = fixture(descriptors[2]);
        const leaf = value.leaves[0];
        const replaceInput = (original: RawProofHashRecord, input: Buffer) =>
            value.records.map((record) =>
                record === original
                    ? { input, output: original.output }
                    : record,
            );
        const leafWith = (stage: number, position: number, data: Buffer) =>
            frame(value.role, true, 'leaf', [
                unsigned(stage, 4),
                unsigned(position, 4),
                Buffer.alloc(128, 19),
                data,
            ]);
        const noncanonical = Buffer.from(leaf.data);
        unsigned(field.modulus, 16).copy(noncanonical);
        for (const input of [
            leafWith(1, leaf.position, leaf.data),
            leafWith(0, leaf.position + 1, leaf.data),
            leafWith(0, leaf.position, noncanonical),
        ]) {
            const result = extractRawProofPrefix(
                replaceInput(leaf.record, input),
                value.query,
            );
            expect(result).toBeDefined();
            expect(result!.oracles[0].leaf(leaf.position)).toBeUndefined();
        }
        const wrongLevel = Buffer.from(leaf.parent.input);
        // Locate the node's independently framed level after its stage.
        const levelOffset =
            64 +
            4 +
            Buffer.byteLength('bounded-proof/node') +
            4 +
            value.role.length +
            8 +
            4;
        wrongLevel.writeUInt32LE(2, levelOffset);
        expect(
            extractRawProofPrefix(
                replaceInput(leaf.parent, wrongLevel),
                value.query,
            )?.oracles[0].leaf(leaf.position),
        ).toBeUndefined();
        const unusable = frame(value.role, true, 'node', [
            unsigned(0xffffffff, 4),
            unsigned(0, 4),
            Buffer.alloc(64),
            Buffer.alloc(64),
        ]);
        expect(
            extractRawProofPrefix(
                [
                    ...value.records,
                    { input: unusable, output: leaf.record.output },
                ],
                value.query,
            ),
        ).toBeUndefined();
        const otherRole = frame(
            originalRole('release', 'cd'.repeat(64)),
            true,
            'node',
            [
                unsigned(0, 4),
                unsigned(1, 4),
                Buffer.alloc(64),
                Buffer.alloc(64),
            ],
        );
        expect(
            extractRawProofPrefix(
                [
                    ...value.records,
                    { input: otherRole, output: leaf.record.output },
                ],
                value.query,
            ),
        ).toBeDefined();
    });
});
