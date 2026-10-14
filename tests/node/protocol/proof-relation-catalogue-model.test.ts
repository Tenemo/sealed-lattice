import { readFileSync } from 'node:fs';

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
    compileProofHashDomainCensus,
    hasProofHashLayout,
    isProofChallengeInput,
    parseProofHashInput,
} from '#tests/proof-hash-domain-model.js';
import {
    proofCatalogueInteger,
    proofRelationCatalogue,
    proofRelationCatalogueEntry,
    resolveProofContext,
} from '#tests/proof-relation-catalogue-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import { protocolHashPrefix } from '#tests/word-proof-reference/transcript.js';

const field = compileSmallLimbProofFieldCensus();
const owner = 'ab'.repeat(64);
const role = (purpose: string, release = false) =>
    tuple([
        ascii(purpose),
        ascii(owner),
        ...Array.from({ length: release ? 3 : 2 }, () =>
            item(itemType.hash512, Buffer.alloc(64)),
        ),
        item(itemType.unsigned16, unsigned(1, 2)),
    ]);
const roles = {
    setup: role('sealed-lattice/setup-contribution/v3'),
    ballot: role('sealed-lattice/ballot-proof/v3'),
    release: role('sealed-lattice/certified-release/v3', true),
};
const frame = (
    purpose: keyof typeof roles,
    fixed: boolean,
    domain: string,
    parts: Buffer[],
) => {
    return Buffer.concat([
        ...(fixed ? [protocolHashPrefix] : []),
        ...[
            Buffer.from(`bounded-proof/${domain}`),
            roles[purpose],
            ...parts,
        ].map((part) => variable(part)),
    ]);
};

describe('fixed three-purpose raw-domain catalogue', () => {
    it('uses the independently pinned original-PID role widths and complete state widths', () => {
        expect(Object.values(roles).map((value) => value.length)).toEqual([
            340, 334, 409,
        ]);
        const shapes = [
            [3, 2, 131072],
            [10, 10, 262144],
            [20, 20, 524288],
        ];
        for (const [participants, options, setupWidth] of shapes) {
            const entries = proofRelationCatalogueEntry(
                deriveSupportedProfile(participants, options),
            );
            expect(entries.map((entry) => Number(entry.messageBytes))).toEqual([
                setupWidth,
                262144,
                262144,
            ]);
            for (const entry of entries) {
                const input = frame(entry.role, false, 'verifier-message', [
                    Buffer.alloc(64),
                    Buffer.alloc(Number(entry.messageBytes)),
                    unsigned(1, 4),
                ]);
                const parsed = parseProofHashInput(input)!;
                expect(parsed.purpose).toBe(entry.role);
                expect(parsed.owner).toBe(owner);
                expect(hasProofHashLayout(parsed)).toBe(true);
                expect(isProofChallengeInput(input, new Set([owner]))).toBe(
                    false,
                );
                expect(isProofChallengeInput(input, new Set())).toBe(true);
                expect(
                    parseProofHashInput(input.subarray(0, -1)),
                ).toBeUndefined();
                const wrongPurpose = Buffer.from(input);
                const index = wrongPurpose.indexOf(Buffer.from(owner));
                wrongPurpose[index] = 65;
                expect(parseProofHashInput(wrongPurpose)).toBeUndefined();
            }
        }
    });

    it('does not identify a setup relation from a width alias without its context', () => {
        const input = frame('setup', false, 'chain-state', [
            Buffer.alloc(64),
            Buffer.alloc(262144),
            Buffer.alloc(64),
        ]);
        const parsed = parseProofHashInput(input)!;
        expect(
            new Set(parsed.candidates.map((entry) => entry.arithmeticKey)).size,
        ).toBeGreaterThan(1);
        expect(resolveProofContext(parsed.fields, Buffer.alloc(0))).toEqual([]);
        expect(
            parseProofHashInput(
                frame('ballot', false, 'chain-state', [
                    Buffer.alloc(64),
                    Buffer.alloc(131072),
                    Buffer.alloc(64),
                ]),
            ),
        ).toBeUndefined();
        // A malformed numeric round is still in the raw challenged namespace.
        const malformed = parseProofHashInput(
            frame('release', false, 'verifier-message', [
                Buffer.alloc(64),
                Buffer.alloc(262144),
                unsigned(0xffffffff, 4),
            ]),
        )!;
        expect(hasProofHashLayout(malformed)).toBe(false);
    });

    it('bounds every static framed family in bits and reuses the source-linked verifier expansion', () => {
        const census = compileProofHashDomainCensus();
        expect(census.rows).toHaveLength(342 * 3);
        expect(census.sentinelCount).toBe(1n);
        expect(census.maximumAcceptedExpansionQueries).toBe(97828n);
        expect(census.minimumMessageBits).toBe(8n * 131072n);
        expect(census.maximumMessageBits).toBe(8n * 524288n);
        // The maximum is a full setup statement, which its digest hashes.
        const maximum = census.rows.find(
            (row) => row.maximumInputBits === census.maximumInputBits,
        )!;
        expect(maximum.purpose).toBe('setup');
        expect(census.maximumInputBits).toBeGreaterThan(
            census.maximumMessageBits,
        );
        for (const length of [34, 66, 1952])
            expect(parseProofHashInput(Buffer.alloc(length))).toBeUndefined();
    });

    it('binds the independent parameter encoder to the immutable source catalogue, excluding generic Relation mutation', () => {
        const source = readFileSync(
            'crates/protocol-research/supported-profile/src/relation.rs',
            'utf8',
        );
        for (const tag of [
            'complete-setup-words/2',
            'linked-scored-ballot/1',
            'linked-threshold-release/1',
        ])
            expect(source).toContain(`tag: b"${tag}"`);
        // Independent completion operands pinned by the Rust descriptor's
        // existing full-profile tests, rather than copied from this encoder.
        const completion = proofRelationCatalogueEntry(
            deriveSupportedProfile(10, 10),
        );
        expect(completion[0].encodedParameters.subarray(0, 72)).toEqual(
            Buffer.concat(
                [
                    65536, 704, 1409, 262144, 131071, 2, 262144, 65536, 331, 24,
                    375, 1024, 256, 112, 96, 16, 7, 32,
                ].map((value) => unsigned(value, 4)),
            ),
        );
        expect(completion[1].encodedParameters.subarray(28, 80)).toEqual(
            Buffer.concat(
                [
                    27, 5, 32, 1024, 256, 32768, 65536, 27, 28, 29, 30, 20, 31,
                ].map((value) => unsigned(value, 4)),
            ),
        );
        expect(completion[2].encodedParameters.subarray(28, 128)).toEqual(
            Buffer.concat(
                [
                    59,
                    2,
                    68,
                    256,
                    96,
                    48,
                    4,
                    4,
                    16,
                    16,
                    7,
                    120,
                    24,
                    16,
                    30,
                    144,
                    144,
                    72,
                    72,
                    72,
                    72,
                    72,
                    998244353,
                    20,
                    Number((field.modulus * 998244353n) & 0xffffffffn),
                ].map((value) => unsigned(value, 4)),
            ),
        );
        expect(source).toContain('pub zero_product_pairs: Vec<(usize, usize)>');
        expect(source).toContain('pub narrow: Vec<(usize, u128)>');
        expect(
            completion[0].encodedParameters.subarray(-44 * 8, -43 * 8),
        ).toEqual(Buffer.concat([unsigned(30, 4), unsigned(512, 4)]));
        // Those generic fields are not a public constructor input here.
        expect(
            new Set(proofRelationCatalogue().map((entry) => entry.role)),
        ).toEqual(new Set(Object.keys(roles)));
        const effectiveAliases = new Map<string, Set<string>>();
        for (const entry of proofRelationCatalogue()) {
            const key = [
                entry.relationTag,
                entry.encodedParameters.toString('hex'),
                entry.statementBytes,
                entry.header.toString('hex'),
                entry.role === 'ballot' ? entry.optionCount : '',
            ].join(':');
            const arithmeticKeys =
                effectiveAliases.get(key) ?? new Set<string>();
            arithmeticKeys.add(entry.arithmeticKey);
            effectiveAliases.set(key, arithmeticKeys);
        }
        expect(
            [...effectiveAliases.values()].every((keys) => keys.size === 1),
        ).toBe(true);
    });

    it('resolves canonical contexts and statements, retains profile aliases and refuses field/header/encoding changes', () => {
        const entries = proofRelationCatalogueEntry(
            deriveSupportedProfile(3, 2),
        );
        for (const entry of entries) {
            const statement = Buffer.alloc(Number(entry.statementBytes));
            entry.header.copy(statement);
            if (entry.role === 'ballot') {
                statement[134] = 2;
                statement[135] = 1;
            }
            const fields = [
                Buffer.from(entry.relationTag),
                proofCatalogueInteger(2n, 16),
                proofCatalogueInteger(field.transformRoot, 16),
                proofCatalogueInteger(7n, 16),
                entry.encodedParameters,
                proofCatalogueInteger(field.modulus - 1n, 16),
                Buffer.alloc(64, 25),
            ];
            const aliases = resolveProofContext(fields, statement);
            expect(
                new Set(aliases.map((candidate) => candidate.arithmeticKey)),
            ).toEqual(new Set([entry.arithmeticKey]));
            expect(
                parseProofHashInput(
                    frame(entry.role, true, 'statement', fields),
                )?.purpose,
            ).toBe(entry.role);
            const changedParameters = Buffer.from(entry.encodedParameters);
            changedParameters[changedParameters.length - 1] ^= 1;
            expect(
                resolveProofContext(
                    fields.map((value, index) =>
                        index === 4 ? changedParameters : value,
                    ),
                    statement,
                ),
            ).toEqual([]);
            expect(
                resolveProofContext(
                    fields.map((value, index) =>
                        index === 6 ? value.subarray(0, -1) : value,
                    ),
                    statement,
                ),
            ).toEqual([]);
            expect(
                resolveProofContext(fields, statement.subarray(0, -1)),
            ).toEqual([]);
            const coefficientOffset =
                entry.role === 'ballot'
                    ? 136
                    : entry.role === 'release'
                      ? 198
                      : entry.header.length;
            statement[coefficientOffset] = 1; // Negative zero is not canonical.
            expect(resolveProofContext(fields, statement)).toEqual([]);
            statement[coefficientOffset] = 2;
            expect(resolveProofContext(fields, statement)).toEqual([]);
            statement[coefficientOffset] = 0;
            statement[0] ^= 1;
            expect(resolveProofContext(fields, statement)).toEqual([]);
        }
    });

    it.each(['ballot', 'release'] as const)(
        'resolves the same %s context under compatible n aliases without inventing the omitted count',
        (purpose) => {
            const aliases = proofRelationCatalogue().filter(
                (entry) => entry.role === purpose,
            );
            const first = aliases.find((entry, index) =>
                aliases
                    .slice(index + 1)
                    .some(
                        (other) =>
                            entry.arithmeticKey === other.arithmeticKey &&
                            entry.participantCount < other.participantCount,
                    ),
            )!;
            const other = aliases.find(
                (entry) =>
                    entry.arithmeticKey === first.arithmeticKey &&
                    entry.participantCount > first.participantCount,
            )!;
            expect(
                first.encodedParameters.equals(other.encodedParameters),
            ).toBe(true);
            expect(first.statementBytes).toBe(other.statementBytes);
            const statement = Buffer.alloc(Number(first.statementBytes));
            first.header.copy(statement);
            statement.writeUInt16LE(
                first.participantCount,
                purpose === 'ballot' ? 132 : 196,
            );
            if (purpose === 'ballot') {
                statement[134] = first.optionCount;
                statement[135] = 1;
            }
            const fields = [
                Buffer.from(first.relationTag),
                proofCatalogueInteger(2n, 16),
                proofCatalogueInteger(field.transformRoot, 16),
                proofCatalogueInteger(7n, 16),
                first.encodedParameters,
                proofCatalogueInteger(field.modulus - 1n, 16),
                Buffer.alloc(64),
            ];
            const resolved = resolveProofContext(fields, statement);
            expect(
                resolved.some((entry) => entry.profile === first.profile),
            ).toBe(false);
            expect(
                resolved.some((entry) => entry.profile === other.profile),
            ).toBe(true);
            expect(
                new Set(resolved.map((entry) => entry.arithmeticKey)),
            ).toEqual(new Set([first.arithmeticKey]));
        },
    );
});
