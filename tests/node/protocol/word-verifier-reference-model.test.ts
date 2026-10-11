import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { proofRelationCatalogue } from '#tests/proof-relation-catalogue-model.js';
import { compileSetupContributionColumnLayout } from '#tests/setup-contribution-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import {
    catalogueWordRelation,
    evaluateSystematicColumns,
    type Extension,
    lookupTableCoefficients,
    productionWordProofDomain,
    proveWordRelation,
    verifyWordProof,
    wordContextParameters,
    wordFieldArithmetic as arithmetic,
    type WordProofInput,
    wordProofDomain,
    type WordProverMode,
    type WordRelation,
    wordRelationShape,
    type WordStatementParser,
} from '#tests/word-verifier-reference-model.js';

const census = compileSmallLimbProofFieldCensus();
const prime = census.modulus;
const domain = wordProofDomain(64, 15);
const systematic = domain.systematic;
const lastStage = 3 + domain.folds - 2;
const role = Buffer.from('reference-word-proof/role');

// A toy relation over the reduced domain: two full words, a word below
// eight through a scaled lookup, and two disjoint Boolean columns. Row h
// states w0 + 2*w1 - w2 - 5*b3 = t_h, and one support row states that b3
// sums to s. The statement is its magic, every t_h and s as field words.
const statementMagic = Buffer.from('TOY1');
const statementBytes = 4 + 16 * systematic + 16;
const relation: WordRelation = (() => {
    const shape = {
        tag: Buffer.from('reference-toy/1'),
        magic: Buffer.from('TPR1'),
        words: 3,
        booleans: 2,
        lookups: [
            { column: 0, factor: 1n },
            { column: 1, factor: 1n },
            { column: 2, factor: 1n },
            { column: 2, factor: 8n },
        ],
        zeroProducts: [[3, 4]] as const,
        statementBytes,
        parameters: [3, 2, 4],
    };
    const oracles = wordRelationShape(
        { ...shape, messageBytes: 0 },
        domain,
    ).oracles;
    return { ...shape, messageBytes: 96 * (2 * oracles + 1) };
})();

type Toy = {
    columns: bigint[][];
    targets: bigint[];
    support: bigint;
};
const modulo = (value: bigint) => ((value % prime) + prime) % prime;
const rowValue = (toy: Toy, position: number) =>
    toy.columns[0][position] +
    2n * toy.columns[1][position] -
    toy.columns[2][position] -
    5n * toy.columns[3][position];
// Restates every row and the support sum for the toy's columns.
const satisfy = (toy: Toy): Toy => ({
    ...toy,
    targets: toy.columns[0].map((_, position) =>
        modulo(rowValue(toy, position)),
    ),
    support: toy.columns[3].reduce((sum, value) => sum + value, 0n),
});
const toyWitness = (seed: number): Toy => {
    let state = BigInt(seed) + 1n;
    const random = (bound: number) => {
        state =
            (state * 6364136223846793005n + 1442695040888963407n) % 2n ** 64n;
        return (state >> 32n) % BigInt(bound);
    };
    const columns = [
        Array.from({ length: systematic }, () => random(64)),
        Array.from({ length: systematic }, () => random(64)),
        Array.from({ length: systematic }, () => random(8)),
        Array.from({ length: systematic }, () => 0n),
        Array.from({ length: systematic }, () => 0n),
    ];
    for (const [column, count] of [
        [3, 3],
        [4, 2],
    ])
        for (let placed = 0; placed < count;) {
            const position = Number(random(systematic));
            if (columns[3][position] + columns[4][position] !== 0n) continue;
            columns[column][position] = 1n;
            placed++;
        }
    return satisfy({ columns, targets: [], support: 0n });
};
const encodeStatement = (toy: Toy) =>
    Buffer.concat([
        statementMagic,
        ...[...toy.targets, toy.support].map((value) => {
            const bytes = Buffer.alloc(16);
            bytes.writeBigUInt64LE(value & (2n ** 64n - 1n));
            bytes.writeBigUInt64LE(value >> 64n, 8);
            return bytes;
        }),
    ]);
const chunks = (bytes: Buffer, size: number) =>
    Array.from({ length: Math.ceil(bytes.length / size) }, (_, index) =>
        bytes.subarray(size * index, size * (index + 1)),
    );

// The affine operator over the systematic positions: row h weighs alpha^h,
// the support row alpha^H and the lookup sum alpha^(H+1).
const toyOperator = (affine: Extension, targets: bigint[], support: bigint) => {
    const powers: Extension[] = [arithmetic.one];
    while (powers.length <= systematic + 1)
        powers.push(arithmetic.multiply(powers[powers.length - 1], affine));
    const weighted = (factor: bigint) =>
        powers
            .slice(0, systematic)
            .map((value) => arithmetic.scale(value, modulo(factor)));
    return {
        coefficients: [
            weighted(1n),
            weighted(2n),
            weighted(-1n),
            weighted(-5n).map((value) =>
                arithmetic.add(value, powers[systematic]),
            ),
            weighted(0n),
        ],
        target: arithmetic.add(
            targets.reduce(
                (sum, value, position) =>
                    arithmetic.add(
                        sum,
                        arithmetic.scale(powers[position], value),
                    ),
                arithmetic.zero,
            ),
            arithmetic.scale(powers[systematic], support),
        ),
        lookupWeight: powers[systematic + 1],
    };
};
// The verifier's parser of the toy statement: it refuses bytes beyond the
// statement, then a wrong length, magic or noncanonical field word.
const toyParser = (
    affine: Extension,
    positions: readonly number[],
): WordStatementParser => {
    const received: Buffer[] = [];
    let length = 0;
    return {
        push: (chunk) => {
            length += chunk.length;
            received.push(Buffer.from(chunk));
            return length <= statementBytes;
        },
        finish: () => {
            const bytes = Buffer.concat(received);
            if (
                bytes.length !== statementBytes ||
                !bytes.subarray(0, 4).equals(statementMagic)
            )
                return undefined;
            const words = Array.from(
                { length: systematic + 1 },
                (_, index) =>
                    bytes.readBigUInt64LE(4 + 16 * index) +
                    (bytes.readBigUInt64LE(12 + 16 * index) << 64n),
            );
            if (words.some((value) => value >= prime)) return undefined;
            const operator = toyOperator(
                affine,
                words.slice(0, systematic),
                words[systematic],
            );
            return {
                positions,
                coefficients: evaluateSystematicColumns(
                    domain,
                    operator.coefficients,
                    positions,
                ),
                target: operator.target,
                lookupWeight: operator.lookupWeight,
            };
        },
    };
};

const prove = (
    toy: Toy,
    options: Readonly<{
        seed?: string;
        mode?: WordProverMode;
        statement?: Buffer;
    }> = {},
) => {
    const statement = options.statement ?? encodeStatement(toy);
    const digest = createHash('sha3-512').update(statement).digest();
    const proof = proveWordRelation({
        relation,
        domain,
        role,
        statement: {
            bytes: chunks(statement, 97),
            operator: (affine) => toyOperator(affine, toy.targets, toy.support),
        },
        statementDigest: digest,
        columns: toy.columns,
        seed: Buffer.from(options.seed ?? 'reference-seed'),
        mode: options.mode ?? 'honest',
    });
    return { ...proof, statement, digest };
};
type ToyProof = ReturnType<typeof prove>;
const verify = (proof: ToyProof, overrides: Partial<WordProofInput> = {}) =>
    verifyWordProof({
        relation,
        domain,
        role,
        expectedStatement: proof.digest,
        header: proof.header,
        statement: chunks(proof.statement, 101),
        openStatement: toyParser,
        proof: proof.proof,
        ...overrides,
    });
const changed = (bytes: Buffer, change: (copy: Buffer) => void) => {
    const copy = Buffer.from(bytes);
    change(copy);
    return copy;
};
const littleEndianPrime = () => {
    const bytes = Buffer.alloc(16);
    bytes.writeBigUInt64LE(prime & (2n ** 64n - 1n));
    bytes.writeBigUInt64LE(prime >> 64n, 8);
    return bytes;
};

describe('reference word verifier', () => {
    it('derives the production domain from the census and refuses unsupported domains', () => {
        expect(productionWordProofDomain()).toEqual({
            systematic: 65536,
            queries: 704,
            masks: 1409,
            domain: 262144,
            folds: 17,
            maximumDegree: 131071,
            witnessDegree: 66944,
            headerBytes: 4004,
        });
        for (const [size, queries] of [
            [63, 1],
            [2, 1],
            [64, 0],
            // Masks of 33 would raise a residual above the code degree.
            [64, 16],
            [2 ** 19, 1],
        ])
            expect(() => wordProofDomain(size, queries)).toThrow(RangeError);
        expect(wordProofDomain(64, 15).masks).toBe(31);
    });

    it('encodes every supported relation exactly as its catalogue does', () => {
        const production = productionWordProofDomain();
        const source = readFileSync(
            'crates/protocol-research/supported-profile/src/relation.rs',
            'utf8',
        );
        const catalogue = proofRelationCatalogue();
        expect(catalogue).toHaveLength(3 * 342);
        for (const entry of catalogue) {
            const supported = catalogueWordRelation(entry);
            expect(
                wordContextParameters(supported, production).equals(
                    entry.encodedParameters,
                ),
                `${entry.role} ${entry.profile}`,
            ).toBe(true);
            const shape = wordRelationShape(supported, production);
            expect(BigInt(shape.firstWidth)).toBe(entry.firstWidth);
            expect(BigInt(shape.secondWidth)).toBe(entry.secondWidth);
            // Every product pair ends at a Boolean column after its left
            // column: a sparse sign pair, or the ballot's plaintext word and
            // its high bit.
            for (const [left, right] of supported.zeroProducts) {
                expect(left).toBeLessThan(right);
                expect(right).toBeGreaterThanOrEqual(supported.words);
                expect(right).toBeLessThan(
                    supported.words + supported.booleans,
                );
            }
            expect(source).toContain(
                `proof_magic: b"${Buffer.from(supported.magic).toString('ascii')}"`,
            );
        }
        for (const [participants, options] of [
            [3, 2],
            [16, 2],
            [20, 20],
        ]) {
            const profile = deriveSupportedProfile(participants, options);
            const setup = catalogue.find(
                (entry) =>
                    entry.role === 'setup' &&
                    entry.participantCount === participants &&
                    entry.optionCount === options,
            )!;
            expect(catalogueWordRelation(setup).zeroProducts).toEqual(
                compileSetupContributionColumnLayout(profile)
                    .disjointBooleanPairs,
            );
        }
    });

    it('takes every systematic index to itself through the lookup table polynomial', () => {
        const coefficients = lookupTableCoefficients(domain);
        const omega = (() => {
            let result = 1n;
            let base = census.prothWitness;
            for (
                let exponent = (prime - 1n) / BigInt(systematic);
                exponent > 0n;
                exponent >>= 1n
            ) {
                if ((exponent & 1n) === 1n) result = (result * base) % prime;
                base = (base * base) % prime;
            }
            return result;
        })();
        for (let index = 0; index < systematic; index++) {
            let value = 0n;
            let power = 1n;
            let point = 1n;
            for (let step = 0; step < index; step++)
                point = (point * omega) % prime;
            for (const coefficient of coefficients) {
                value = (value + coefficient * power) % prime;
                power = (power * point) % prime;
            }
            expect(value).toBe(BigInt(index));
        }
    });

    it('accepts honest proofs of varied witnesses and statement chunkings, deterministically for a seed', () => {
        for (const seed of [0, 1, 7]) {
            const proof = prove(toyWitness(seed), { seed: `honest-${seed}` });
            expect(verify(proof)).toEqual({ accepted: true });
            expect(
                verify(proof, { statement: chunks(proof.statement, 1) }),
            ).toEqual({ accepted: true });
            expect(verify(proof, { statement: [proof.statement] })).toEqual({
                accepted: true,
            });
            const again = prove(toyWitness(seed), { seed: `honest-${seed}` });
            expect(again.header.equals(proof.header)).toBe(true);
            expect(again.proof.equals(proof.proof)).toBe(true);
        }
        const other = prove(toyWitness(0), { seed: 'another-seed' });
        expect(other.proof.equals(prove(toyWitness(0)).proof)).toBe(false);
        expect(verify(other)).toEqual({ accepted: true });
    });

    it('refuses malformed headers and contexts before the openings', () => {
        const proof = prove(toyWitness(3));
        const refused = (refusal: string, stage: string | number) => ({
            accepted: false,
            refusal,
            stage,
        });
        expect(verify(proof, { role: Buffer.alloc(0) })).toEqual(
            refused('Context', 'open'),
        );
        expect(verify(proof, { role: Buffer.alloc(1025, 1) })).toEqual(
            refused('Context', 'open'),
        );
        expect(verify(proof, { header: proof.header.subarray(0, -1) })).toEqual(
            refused('Length', 'open'),
        );
        expect(
            verify(proof, {
                header: changed(proof.header, (copy) => (copy[0] ^= 1)),
            }),
        ).toEqual(refused('Encoding', 'open'));
        // The mask sum follows the magic, both digests and three roots; the
        // terminal ends the header.
        for (const offset of [4 + 64 + 64 + 3 * 64, domain.headerBytes - 48])
            expect(
                verify(proof, {
                    header: changed(proof.header, (copy) =>
                        littleEndianPrime().copy(copy, offset),
                    ),
                }),
            ).toEqual(refused('Encoding', 'open'));
        expect(
            verify(proof, {
                expectedStatement: changed(
                    proof.digest,
                    (copy) => (copy[0] ^= 1),
                ),
            }),
        ).toEqual(refused('Context', 'open'));
        expect(verify(proof, { openStatement: () => undefined })).toEqual(
            refused('Context', 'open'),
        );
        expect(
            verify(proof, {
                statement: [proof.statement, Buffer.alloc(1)],
            }),
        ).toEqual(refused('Encoding', 'statement'));
        expect(
            verify(proof, {
                statement: [
                    changed(proof.statement, (copy) => (copy[10] ^= 1)),
                ],
            }),
        ).toEqual(refused('Context', 'statement'));
        expect(
            verify(proof, { role: Buffer.from('another-word-proof/role') }),
        ).toEqual(refused('Context', 'statement'));
        expect(
            verify(proof, {
                header: changed(proof.header, (copy) => (copy[4 + 64] ^= 1)),
            }),
        ).toEqual(refused('Context', 'statement'));
        // A changed root draws other challenges, so the openings name
        // positions the verifier did not request.
        expect(
            verify(proof, {
                header: changed(proof.header, (copy) => (copy[4 + 128] ^= 1)),
            }),
        ).toEqual(refused('Encoding', 0));
        // A statement whose context matches but which its parser refuses.
        const toy = toyWitness(3);
        const noncanonical = encodeStatement(toy);
        littleEndianPrime().copy(noncanonical, 4);
        expect(verify(prove(toy, { statement: noncanonical }))).toEqual(
            refused('Encoding', 'statement'),
        );
    });

    it('refuses malformed, unauthenticated and incomplete openings at their stage', () => {
        const proof = prove(toyWitness(4));
        const shape = wordRelationShape(relation, domain);
        const opening = (stage: number) => proof.stages[stage];
        const withProof = (change: (copy: Buffer) => void) =>
            verify(proof, { proof: changed(proof.proof, change) });
        const refused = (refusal: string, stage: string | number) => ({
            accepted: false,
            refusal,
            stage,
        });
        expect(
            withProof((copy) =>
                copy.writeUInt32LE(copy.readUInt32LE(0) + 1, 0),
            ),
        ).toEqual(refused('Encoding', 0));
        expect(withProof((copy) => (copy[4] ^= 1))).toEqual(
            refused('Encoding', 0),
        );
        expect(withProof((copy) => littleEndianPrime().copy(copy, 8))).toEqual(
            refused('Encoding', 0),
        );
        // The first opening's salt, then a sibling of a later stage's first
        // opening, which authenticates its whole path.
        expect(withProof((copy) => (copy[8 + shape.firstWidth] ^= 1))).toEqual(
            refused('Authentication', 0),
        );
        expect(
            withProof((copy) => (copy[opening(4) + 8 + 48 + 128] ^= 1)),
        ).toEqual(refused('Authentication', 4));
        expect(
            withProof(
                (copy) => (copy[opening(1) + 8 + shape.secondWidth] ^= 1),
            ),
        ).toEqual(refused('Authentication', 1));
        expect(verify(proof, { proof: proof.proof.subarray(0, -1) })).toEqual(
            refused('Incomplete', lastStage),
        );
        expect(
            verify(proof, { proof: proof.proof.subarray(0, opening(5)) }),
        ).toEqual(refused('Incomplete', 5));
        expect(
            verify(proof, {
                proof: Buffer.concat([proof.proof, Buffer.alloc(1)]),
            }),
        ).toEqual(refused('Length', lastStage));
    });

    it('refuses authenticated proofs of false statements and invalid witnesses by their algebra', () => {
        const refused = (stage: number) => ({
            accepted: false,
            refusal: 'Relation',
            stage,
        });
        // A target the witness misses: the verifier's affine remainder differs
        // from the prover's at every point, so the first fold fails.
        const toy = toyWitness(5);
        const falseTarget = { ...toy, targets: [...toy.targets] };
        falseTarget.targets[0] = modulo(falseTarget.targets[0] + 1n);
        expect(verify(prove(falseTarget, { mode: 'false-statement' }))).toEqual(
            refused(3),
        );
        // A word outside its table that every row still states: no
        // multiplicity counts it, so the lookup sum misses the target.
        const outside = {
            ...toy,
            columns: toy.columns.map((column) => [...column]),
        };
        outside.columns[0][1] = 64n;
        expect(
            verify(prove(satisfy(outside), { mode: 'false-statement' })),
        ).toEqual(refused(3));
        // A degree mask above the largest code degree leaves a nonconstant
        // final fold.
        expect(verify(prove(toy, { mode: 'excess-degree' }))).toEqual(
            refused(lastStage),
        );
        // A Boolean column holding two, and both product columns set at one
        // position, keep every affine row but leave a residual that is not a
        // polynomial, which the final fold exposes.
        const twice = {
            ...toy,
            columns: toy.columns.map((column) => [...column]),
        };
        twice.columns[3][toy.columns[3].findIndex((value) => value === 1n)] =
            2n;
        expect(verify(prove(satisfy(twice)))).toEqual(refused(lastStage));
        const overlapping = {
            ...toy,
            columns: toy.columns.map((column) => [...column]),
        };
        overlapping.columns[4][
            toy.columns[3].findIndex((value) => value === 1n)
        ] = 1n;
        expect(verify(prove(satisfy(overlapping)))).toEqual(refused(lastStage));
        // The honest procedure refuses a false target outside its hostile mode.
        expect(() => prove(falseTarget)).toThrow(RangeError);
    });
});
