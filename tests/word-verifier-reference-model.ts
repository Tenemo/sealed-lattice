import { createHash } from 'node:crypto';

import { compileBallotEncryptionColumnLayout } from '#tests/ballot-encryption-relation-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileLinkedReleaseColumnLayout } from '#tests/linked-release-relation-model.js';
import type { ProofRelationCatalogueEntry } from '#tests/proof-relation-catalogue-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

// An independent reading of the bounded word proof from the protocol's
// description: its header, the salted wide verifier-message chain, the
// salted Merkle openings of every stage, the combined rational word at
// every queried point, and each fold down to the terminal constant. The
// statement parser is an input: it receives the affine challenge and the
// queried positions, consumes the statement, and yields the affine operator
// at those positions. A small-domain reference prover exercises the same
// grammar with honest and hostile proofs.

const field = compileSmallLimbProofFieldCensus();
const modulus = field.modulus;
const nonresidue = field.cubicNonresidue;
const shift = field.prothWitness;

export type Extension = readonly [bigint, bigint, bigint];

const reduce = (value: bigint) => {
    const result = value % modulus;
    return result < 0n ? result + modulus : result;
};
const power = (base: bigint, exponent: bigint) => {
    let result = 1n;
    let current = reduce(base);
    for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
        if ((remaining & 1n) === 1n) result = (result * current) % modulus;
        current = (current * current) % modulus;
    }
    return result;
};
const inverse = (value: bigint) => {
    if (reduce(value) === 0n) throw new RangeError('Zero has no inverse.');
    return power(value, modulus - 2n);
};
// The inverses of nonzero values with one exponentiation.
const inverses = (values: readonly bigint[]) => {
    const prefixes: bigint[] = [];
    let product = 1n;
    for (const value of values) {
        prefixes.push(product);
        product = (product * value) % modulus;
    }
    let suffix = inverse(product);
    const output = new Array<bigint>(values.length);
    for (let index = values.length - 1; index >= 0; index--) {
        output[index] = (prefixes[index] * suffix) % modulus;
        suffix = (suffix * values[index]) % modulus;
    }
    return output;
};
const zero: Extension = [0n, 0n, 0n];
const one: Extension = [1n, 0n, 0n];
const base = (value: bigint): Extension => [reduce(value), 0n, 0n];
const add = (left: Extension, right: Extension): Extension => [
    reduce(left[0] + right[0]),
    reduce(left[1] + right[1]),
    reduce(left[2] + right[2]),
];
const subtract = (left: Extension, right: Extension): Extension => [
    reduce(left[0] - right[0]),
    reduce(left[1] - right[1]),
    reduce(left[2] - right[2]),
];
const scale = (value: Extension, factor: bigint): Extension => [
    reduce(value[0] * factor),
    reduce(value[1] * factor),
    reduce(value[2] * factor),
];
// The cubic extension by a root of X^3 minus the census nonresidue.
const multiply = (left: Extension, right: Extension): Extension => {
    const [a0, a1, a2] = left;
    const [b0, b1, b2] = right;
    return [
        reduce(a0 * b0 + nonresidue * (a1 * b2 + a2 * b1)),
        reduce(a0 * b1 + a1 * b0 + nonresidue * a2 * b2),
        reduce(a0 * b2 + a1 * b1 + a2 * b0),
    ];
};
// The norm map gives an extension element's inverse through the base field.
const invertExtension = (value: Extension): Extension => {
    const [a0, a1, a2] = value;
    const c0 = reduce(a0 * a0 - nonresidue * a1 * a2);
    const c1 = reduce(nonresidue * a2 * a2 - a0 * a1);
    const c2 = reduce(a1 * a1 - a0 * a2);
    const norm = reduce(a0 * c0 + nonresidue * (a1 * c2 + a2 * c1));
    return scale([c0, c1, c2], inverse(norm));
};
const equal = (left: Extension, right: Extension) =>
    left[0] === right[0] && left[1] === right[1] && left[2] === right[2];
export const wordFieldArithmetic = {
    modulus,
    zero,
    one,
    base,
    add,
    subtract,
    multiply,
    scale,
    equal,
};

// The proof's code and domain sizes for a systematic subgroup of size H and
// q query pairs: the evaluation domain is the coset of the field's Proth
// witness by the subgroup of size 4H, and every declared degree stays at
// most the largest code degree 2H-1.
export const wordProofDomain = (systematic: number, queries: number) => {
    const masks = 2 * queries + 1;
    if (
        !Number.isSafeInteger(systematic) ||
        systematic < 4 ||
        (systematic & (systematic - 1)) !== 0 ||
        4 * systematic > 2 ** 20 ||
        !Number.isSafeInteger(queries) ||
        queries < 1 ||
        2 * masks > systematic + 1
    )
        throw new RangeError('Unsupported word proof domain.');
    const domain = 4 * systematic;
    const folds = Math.log2(domain / 2);
    return {
        systematic,
        queries,
        masks,
        domain,
        folds,
        maximumDegree: 2 * systematic - 1,
        witnessDegree: systematic + masks - 1,
        headerBytes:
            4 +
            64 +
            64 +
            3 * 64 +
            48 +
            (folds + 3) * 128 +
            (folds - 1) * 64 +
            48,
    };
};
export type WordProofDomain = ReturnType<typeof wordProofDomain>;

export const productionWordProofDomain = () => {
    const agreement = compileCommonAgreementDegreeCensus();
    const domain = wordProofDomain(agreement.systematicSize, agreement.queries);
    if (
        domain.domain !== agreement.domainSize ||
        domain.masks !== agreement.maskDimension ||
        domain.witnessDegree !== agreement.witnessDegree ||
        domain.maximumDegree !== agreement.maximumCodeDegree
    )
        throw new Error('The word proof domain differs from its census.');
    return domain;
};

// A relation as the verifier reads it: its word and Boolean columns, every
// lookup's column and scale, whole words first, its zero-product column
// pairs, its proof magic, and the byte encodings its proofs bind.
export type WordRelation = Readonly<{
    tag: Uint8Array;
    magic: Uint8Array;
    words: number;
    booleans: number;
    lookups: readonly Readonly<{ column: number; factor: bigint }>[];
    zeroProducts: readonly (readonly [number, number])[];
    messageBytes: number;
    statementBytes: number;
    // The relation parameters after the shared proof parameters.
    parameters: readonly (number | bigint)[];
}>;

// The proof magic of each supported purpose's proofs.
const supportedProofMagic = {
    setup: 'SWP3',
    ballot: 'LBP1',
    release: 'LRP1',
} as const;

// A supported relation from its catalogue entry. Setup's positive and
// negative sparse-support columns lead its Boolean columns, one pair for
// the FHE secret, one for its auxiliary secret and one per recipient; the
// ballot and release layouts own their pairs.
export const catalogueWordRelation = (
    entry: ProofRelationCatalogueEntry,
): WordRelation => {
    const profile = deriveSupportedProfile(
        entry.participantCount,
        entry.optionCount,
    );
    let zeroProducts: (readonly [number, number])[];
    if (entry.role === 'setup')
        zeroProducts = Array.from(
            { length: entry.participantCount + 2 },
            (_, pair) =>
                [
                    entry.wordColumns + 2 * pair,
                    entry.wordColumns + 2 * pair + 1,
                ] as const,
        );
    else if (entry.role === 'ballot')
        zeroProducts = compileBallotEncryptionColumnLayout(
            profile,
        ).zeroProducts.map(([left, right]) => [left, right] as const);
    else {
        const layout = compileLinkedReleaseColumnLayout(profile);
        zeroProducts = [
            [layout.positiveSecretColumn, layout.negativeSecretColumn],
        ];
    }
    return {
        tag: Buffer.from(entry.relationTag, 'ascii'),
        magic: Buffer.from(supportedProofMagic[entry.role], 'ascii'),
        words: entry.wordColumns,
        booleans: entry.booleanColumns,
        lookups: entry.lookups,
        zeroProducts,
        messageBytes: Number(entry.messageBytes),
        statementBytes: Number(entry.statementBytes),
        parameters: entry.relationParameters,
    };
};

// The committed oracles are the columns, the multiplicities, every lookup's
// reciprocals, the table reciprocals, the sum mask and the affine quotient.
// The virtual oracles that follow are every Boolean, zero-product and lookup
// residual, the table residual and the affine remainder.
export const wordRelationShape = (
    relation: WordRelation,
    domain: WordProofDomain,
) => {
    const columns = relation.words + relation.booleans;
    const lookups = relation.lookups.length;
    const original = columns + lookups + 4;
    const oracles =
        original +
        relation.booleans +
        relation.zeroProducts.length +
        lookups +
        2;
    const degrees = Array.from({ length: oracles }, (_, index) => {
        if (index < original - 1) return domain.witnessDegree;
        if (index === original - 1 || index === oracles - 2)
            return domain.witnessDegree - 1;
        if (index === oracles - 1) return domain.systematic - 2;
        return 2 * domain.witnessDegree - domain.systematic;
    });
    return {
        columns,
        lookups,
        original,
        oracles,
        degrees,
        firstWidth: (columns + 1) * 16 + 48,
        secondWidth: (lookups + 2) * 48,
    };
};

const littleEndian = (value: number | bigint, bytes: number) => {
    const output = Buffer.alloc(bytes);
    let remaining = BigInt(value);
    if (remaining < 0n || remaining >= 1n << BigInt(8 * bytes))
        throw new RangeError('Value exceeds its encoding.');
    for (let index = 0; index < bytes; index++) {
        output[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return output;
};
const word32 = (value: number | bigint) => littleEndian(value, 4);
const readLittleEndian = (bytes: Uint8Array) => {
    let value = 0n;
    for (let index = bytes.length - 1; index >= 0; index--)
        value = (value << 8n) | BigInt(bytes[index]);
    return value;
};
const framed = (parts: readonly Uint8Array[]) =>
    Buffer.concat(parts.flatMap((part) => [word32(part.length), part]));

// The fixed-length protocol digest: 64 bytes of SHAKE256 after a 64-byte
// domain prefix.
const protocolPrefix = Buffer.alloc(64);
protocolPrefix.write('sealed-lattice/fixed-hash/v1', 'ascii');
const protocolHash = (domain: string, parts: readonly Uint8Array[]) =>
    createHash('shake256', { outputLength: 64 })
        .update(protocolPrefix)
        .update(framed([Buffer.from(domain, 'ascii'), ...parts]))
        .digest();
const wideHash = (
    domain: string,
    parts: readonly Uint8Array[],
    length: number,
) =>
    createHash('shake256', { outputLength: length })
        .update(framed([Buffer.from(domain, 'ascii'), ...parts]))
        .digest();

// The shared proof parameters, the relation parameters, every oracle's
// declared degree and every lookup's column and scale.
export const wordContextParameters = (
    relation: WordRelation,
    domain: WordProofDomain,
) =>
    Buffer.concat([
        ...[
            domain.systematic,
            domain.queries,
            domain.masks,
            domain.domain,
            domain.maximumDegree,
            2,
            relation.messageBytes,
            ...relation.parameters,
            ...wordRelationShape(relation, domain).degrees,
        ].map(word32),
        ...relation.lookups.flatMap(({ column, factor }) => [
            word32(column),
            word32(factor),
        ]),
    ]);

// The protocol digest of a statement's complete public input, which a proof
// header binds as its context.
const contextHash = (
    relation: WordRelation,
    domain: WordProofDomain,
    role: Uint8Array,
) =>
    createHash('shake256', { outputLength: 64 })
        .update(protocolPrefix)
        .update(
            framed([
                Buffer.from('bounded-proof/statement', 'ascii'),
                role,
                relation.tag,
                littleEndian(2n, 16),
                littleEndian(power(shift, (modulus - 1n) / (1n << 20n)), 16),
                littleEndian(shift, 16),
                wordContextParameters(relation, domain),
                littleEndian(modulus - 1n, 16),
            ]),
        )
        .update(word32(relation.statementBytes));
const wordStatementContext = (
    relation: WordRelation,
    domain: WordProofDomain,
    role: Uint8Array,
    statement: Iterable<Uint8Array>,
) => {
    const hash = contextHash(relation, domain, role);
    for (const chunk of statement) hash.update(chunk);
    return hash.digest();
};

// A field element from 32 uniform bytes, little-endian, reduced modulo the
// prime; a lookup challenge's last coordinate is reduced modulo p-1 and
// incremented so that it is never a base-field element.
const sample = (
    message: Uint8Array,
    index: number,
    nonbase: boolean,
): Extension => {
    const coordinate = (position: number) => {
        const bytes = message.subarray(
            96 * index + 32 * position,
            96 * index + 32 * (position + 1),
        );
        if (bytes.length !== 32)
            throw new RangeError('The verifier message is too short.');
        const value = readLittleEndian(bytes);
        return nonbase && position === 2
            ? (value % (modulus - 1n)) + 1n
            : value % modulus;
    };
    return [coordinate(0), coordinate(1), coordinate(2)];
};

type Header = Readonly<{
    statement: Buffer;
    context: Buffer;
    roots: readonly Buffer[];
    maskSum: Extension;
    salts: readonly Buffer[];
    foldRoots: readonly Buffer[];
    terminal: Extension;
}>;

type WordVerifierRefusal =
    'Encoding' | 'Length' | 'Context' | 'Authentication' | 'Relation';
// Where a verification stopped: opening the proof, streaming its statement,
// or reading the opening stage with this index.
type WordVerifierStage = 'open' | 'statement' | number;
export type WordVerifierVerdict =
    | Readonly<{ accepted: true }>
    | Readonly<{
          accepted: false;
          refusal: WordVerifierRefusal | 'Incomplete';
          stage: WordVerifierStage;
      }>;

class Refused extends Error {
    constructor(
        readonly refusal: WordVerifierRefusal | 'Incomplete',
        readonly stage: WordVerifierStage,
    ) {
        super(refusal);
    }
}

const canonical = (bytes: Uint8Array, stage: WordVerifierStage) => {
    const value = readLittleEndian(bytes);
    if (value >= modulus) throw new Refused('Encoding', stage);
    return value;
};
const readExtension = (
    bytes: Uint8Array,
    stage: WordVerifierStage,
): Extension => [
    canonical(bytes.subarray(0, 16), stage),
    canonical(bytes.subarray(16, 32), stage),
    canonical(bytes.subarray(32, 48), stage),
];

const parseHeader = (
    bytes: Uint8Array,
    magic: Uint8Array,
    domain: WordProofDomain,
): Header => {
    if (bytes.length !== domain.headerBytes)
        throw new Refused('Length', 'open');
    let position = 0;
    const take = (length: number) =>
        Buffer.from(bytes.subarray(position, (position += length)));
    if (!take(4).equals(Buffer.from(magic)))
        throw new Refused('Encoding', 'open');
    const statement = take(64);
    const context = take(64);
    const roots = [take(64), take(64), take(64)];
    const maskSum = readExtension(take(48), 'open');
    const salts = Array.from({ length: domain.folds + 3 }, () => take(128));
    const foldRoots = Array.from({ length: domain.folds - 1 }, () => take(64));
    const terminal = readExtension(take(48), 'open');
    return { statement, context, roots, maskSum, salts, foldRoots, terminal };
};

const encodeExtension = (value: Extension) =>
    Buffer.concat(value.map((coordinate) => littleEndian(coordinate, 16)));

// Each round's verifier message hashes the role, context, previous state
// and round; a salted short root commits that round's prover message; and
// the next state is that root followed by a wide hash of the message and
// the root. The prover's responses supply the committed parts of a round.
type Transcript = Readonly<{
    message: (round: number) => Buffer;
    respond: (round: number, salt: Uint8Array, parts: Uint8Array[]) => void;
}>;
const transcript = (
    role: Uint8Array,
    context: Uint8Array,
    length: number,
): Transcript => {
    let state = Buffer.alloc(length);
    const message = (round: number) =>
        wideHash(
            'bounded-proof/verifier-message',
            [role, context, state, word32(round)],
            length,
        );
    return {
        message,
        respond: (round, salt, parts) => {
            const current = message(round);
            const root = protocolHash('bounded-proof/message-root', [
                role,
                context,
                word32(round),
                salt,
                ...parts,
            ]);
            const digest = wideHash(
                'bounded-proof/chain-state',
                [role, context, current, root],
                length,
            );
            state = Buffer.concat([root, digest.subarray(0, length - 64)]);
        },
    };
};
const committedParts = (header: Header, round: number, folds: number) =>
    round === 1
        ? [header.roots[0]]
        : round === 2
          ? [header.roots[1], encodeExtension(header.maskSum)]
          : round === 3
            ? [header.roots[2]]
            : round === folds + 3
              ? [encodeExtension(header.terminal)]
              : [header.foldRoots[round - 4]];

// The lookup challenge, the affine and mask challenges, the degree
// combination weights, every fold challenge and the query draws.
const challengesFrom = (
    oracles: number,
    folds: number,
    queries: number,
    domainLength: number,
    message: (round: number) => Buffer,
    respond: (round: number) => void,
) => {
    let lookup = zero;
    let affine = zero;
    let mask = zero;
    let combination: Extension[] = [];
    const foldChallenges: Extension[] = [];
    for (let round = 1; round <= folds + 3; round++) {
        const current = message(round);
        if (round === 2) lookup = sample(current, 0, true);
        if (round === 3) {
            affine = sample(current, 0, false);
            mask = sample(current, 1, false);
        }
        if (round === 4)
            combination = Array.from({ length: 2 * oracles }, (_, index) =>
                sample(current, index, false),
            );
        if (round >= 4)
            foldChallenges.push(
                sample(current, round === 4 ? 2 * oracles : 0, false),
            );
        respond(round);
    }
    const final = message(folds + 4);
    return {
        lookup,
        affine,
        mask,
        combination,
        folds: foldChallenges,
        queries: Array.from(
            { length: queries },
            (_, index) => final.readUInt32LE(4 * index) % (domainLength / 2),
        ),
    };
};
const deriveWordProofChallenges = (
    relation: WordRelation,
    domain: WordProofDomain,
    role: Uint8Array,
    header: Header,
) => {
    const chain = transcript(role, header.context, relation.messageBytes);
    return challengesFrom(
        wordRelationShape(relation, domain).oracles,
        domain.folds,
        domain.queries,
        domain.domain,
        chain.message,
        (round) =>
            chain.respond(
                round,
                header.salts[round - 1],
                committedParts(header, round, domain.folds),
            ),
    );
};

// Each query opens a point and its negation; a stage of the given length
// opens their sorted distinct positions.
const requestedPositions = (queries: readonly number[], length: number) =>
    [
        ...new Set(
            queries.flatMap((query) => [
                query % (length / 2),
                (query % (length / 2)) + length / 2,
            ]),
        ),
    ].sort((left, right) => left - right);

// The statement's affine operator at the queried points of the first
// stage: each column's interpolated coefficient at every point, the target
// and the lookup sum's weight.
type WordStatementOperator = Readonly<{
    positions: readonly number[];
    coefficients: readonly (readonly Extension[])[];
    target: Extension;
    lookupWeight: Extension;
}>;
// A statement parser opened at the affine challenge and queried positions.
export type WordStatementParser = Readonly<{
    // Consumes the next statement chunk; false when it refuses the chunk.
    push: (chunk: Uint8Array) => boolean;
    // The operator, or undefined when the complete statement is refused.
    finish: () => WordStatementOperator | undefined;
}>;

const domainRoot = (length: number) =>
    power(shift, (modulus - 1n) / BigInt(length));
const point = (domain: WordProofDomain, position: number) =>
    reduce(shift * power(domainRoot(domain.domain), BigInt(position)));

// A radix-two transform of a power-of-two vector at the powers of a root of
// that order, in natural order.
const transform = (values: readonly bigint[], root: bigint) => {
    const size = values.length;
    const output = [...values];
    for (let index = 1, reversed = 0; index < size; index++) {
        let bit = size >> 1;
        for (; (reversed & bit) !== 0; bit >>= 1) reversed ^= bit;
        reversed ^= bit;
        if (index < reversed)
            [output[index], output[reversed]] = [
                output[reversed],
                output[index],
            ];
    }
    for (let length = 2; length <= size; length <<= 1) {
        const step = power(root, BigInt(size / length));
        const twiddles = [1n];
        for (let offset = 1; offset < length / 2; offset++)
            twiddles.push((twiddles[offset - 1] * step) % modulus);
        for (let start = 0; start < size; start += length)
            for (let offset = 0; offset < length / 2; offset++) {
                const even = output[start + offset];
                const odd =
                    (output[start + offset + length / 2] * twiddles[offset]) %
                    modulus;
                output[start + offset] = (even + odd) % modulus;
                output[start + offset + length / 2] = reduce(even - odd);
            }
    }
    return output;
};
// Coefficients from values on the subgroup of the vector's size.
const interpolate = (values: readonly bigint[]) => {
    const size = values.length;
    const scaleBack = inverse(BigInt(size));
    return transform(values, inverse(domainRoot(size))).map(
        (value) => (value * scaleBack) % modulus,
    );
};
// Values at every point of the evaluation coset.
const evaluateOnCoset = (
    coefficients: readonly bigint[],
    domain: WordProofDomain,
) => {
    if (coefficients.length > domain.domain)
        throw new RangeError('The polynomial exceeds its evaluation domain.');
    const twisted = new Array<bigint>(domain.domain).fill(0n);
    let twist = 1n;
    coefficients.forEach((coefficient, degree) => {
        twisted[degree] = (coefficient * twist) % modulus;
        twist = (twist * shift) % modulus;
    });
    return transform(twisted, domainRoot(domain.domain));
};

// Extension-valued vectors by coordinate.
const extensionCoordinates = (values: readonly Extension[]) =>
    [0, 1, 2].map((index) => values.map((value) => value[index]));
const fromCoordinates = (coordinates: readonly (readonly bigint[])[]) =>
    coordinates[0].map((value, index): Extension => [
        value,
        coordinates[1][index],
        coordinates[2][index],
    ]);
const interpolateExtension = (values: readonly Extension[]) =>
    fromCoordinates(extensionCoordinates(values).map(interpolate));
const evaluateExtensionOnCoset = (
    coefficients: readonly Extension[],
    domain: WordProofDomain,
) =>
    fromCoordinates(
        extensionCoordinates(coefficients).map((coordinate) =>
            evaluateOnCoset(coordinate, domain),
        ),
    );
// Each column's interpolant over the systematic subgroup, whose element of
// index h carries the column's value h, at the given evaluation positions.
export const evaluateSystematicColumns = (
    domain: WordProofDomain,
    columns: readonly (readonly Extension[])[],
    positions: readonly number[],
) =>
    columns.map((column) => {
        if (column.length !== domain.systematic)
            throw new RangeError('A column does not cover the subgroup.');
        const values = fromCoordinates(
            extensionCoordinates(column).map((coordinate) =>
                evaluateOnCoset(interpolate(coordinate), domain),
            ),
        );
        return positions.map((position) => values[position]);
    });

// The lookup table polynomial takes the systematic subgroup's element of
// each index to that index. Its coefficients are (H-1)/2 at degree zero and
// 1/(omega^-k - 1) at each degree k, for the subgroup's root omega.
export const lookupTableCoefficients = (domain: WordProofDomain) => {
    const inverseOmega = inverse(domainRoot(domain.systematic));
    const denominators: bigint[] = [];
    for (
        let degree = 1, current = inverseOmega;
        degree < domain.systematic;
        degree++, current = (current * inverseOmega) % modulus
    )
        denominators.push(reduce(current - 1n));
    return [
        reduce(BigInt(domain.systematic - 1) * inverse(2n)),
        ...inverses(denominators),
    ];
};
const tables = new Map<number, readonly bigint[]>();
const tableOnDomain = (domain: WordProofDomain) => {
    let table = tables.get(domain.domain);
    if (table === undefined) {
        table = evaluateOnCoset(lookupTableCoefficients(domain), domain);
        tables.set(domain.domain, table);
    }
    return table;
};

const merkleLeaf = (
    role: Uint8Array,
    stage: number,
    position: number,
    salt: Uint8Array,
    data: Uint8Array,
) =>
    protocolHash('bounded-proof/leaf', [
        role,
        word32(stage),
        word32(position),
        salt,
        data,
    ]);
const merkleNode = (
    role: Uint8Array,
    stage: number,
    level: number,
    left: Uint8Array,
    right: Uint8Array,
) =>
    protocolHash('bounded-proof/node', [
        role,
        word32(stage),
        word32(level),
        left,
        right,
    ]);

export type WordProofInput = Readonly<{
    relation: WordRelation;
    domain: WordProofDomain;
    role: Uint8Array;
    expectedStatement: Uint8Array;
    header: Uint8Array;
    // The statement's complete public input, in chunks.
    statement: Iterable<Uint8Array>;
    // Undefined when the parser refuses the challenge or positions.
    openStatement: (
        affine: Extension,
        positions: readonly number[],
    ) => WordStatementParser | undefined;
    proof: Uint8Array;
}>;

// Verifies one proof. Refusals follow the order of the stages: the header
// and its statement, the statement's chunks and context, then the proof's
// opening stages.
export const verifyWordProof = (input: WordProofInput): WordVerifierVerdict => {
    try {
        verifyStages(input);
        return { accepted: true };
    } catch (error) {
        if (error instanceof Refused)
            return {
                accepted: false,
                refusal: error.refusal,
                stage: error.stage,
            };
        throw error;
    }
};

// The degree-combination weight of an oracle at a point: its own weight
// plus its shifted weight times the point raised to the gap between the
// largest degree and the oracle's degree.
const combinationWeights = (
    combination: readonly Extension[],
    degrees: readonly number[],
    maximumDegree: number,
    x: bigint,
) => {
    const corrections = new Map<number, bigint>();
    return (oracle: number): Extension => {
        const degree = degrees[oracle];
        let correction = corrections.get(degree);
        if (correction === undefined) {
            correction = power(x, BigInt(maximumDegree - degree));
            corrections.set(degree, correction);
        }
        return add(
            combination[2 * oracle],
            scale(combination[2 * oracle + 1], correction),
        );
    };
};

// One point's committed values: the column values, multiplicity, degree
// mask, every lookup reciprocal, the table reciprocal, the sum mask and the
// affine quotient.
type PointValues = Readonly<{
    words: readonly bigint[];
    multiplicity: bigint;
    degreeMask: Extension;
    reciprocals: readonly Extension[];
    tableReciprocal: Extension;
    sumMask: Extension;
    quotient: Extension;
}>;
type PointContext = Readonly<{
    relation: WordRelation;
    shape: ReturnType<typeof wordRelationShape>;
    domain: WordProofDomain;
    challenges: Readonly<{
        lookup: Extension;
        mask: Extension;
        combination: readonly Extension[];
    }>;
    coefficients: readonly Extension[];
    target: Extension;
    lookupWeight: Extension;
    maskSum: Extension;
    // The point, its inverse, its vanishing value's inverse and the table.
    x: bigint;
    inverseX: bigint;
    inverseVanishing: bigint;
    table: bigint;
    // The affine remainder's numerator constant: the claimed sum over H for
    // the verifier, the prover's own remainder constant for the prover.
    remainderConstant?: Extension;
}>;
// The combined rational word at one point.
const combinedValue = (at: PointContext, values: PointValues) => {
    const { relation, shape, domain, challenges } = at;
    const weight = combinationWeights(
        challenges.combination,
        shape.degrees,
        domain.maximumDegree,
        at.x,
    );
    let combined = values.degreeMask;
    let linear = zero;
    values.words.forEach((value, column) => {
        linear = add(linear, scale(at.coefficients[column], value));
        combined = add(combined, scale(weight(column), value));
    });
    combined = add(combined, scale(weight(shape.columns), values.multiplicity));
    for (let index = 0; index < relation.booleans; index++) {
        const value = values.words[relation.words + index];
        combined = add(
            combined,
            scale(
                weight(shape.original + index),
                reduce(value * (value - 1n) * at.inverseVanishing),
            ),
        );
    }
    relation.zeroProducts.forEach(([left, right], pair) => {
        combined = add(
            combined,
            scale(
                weight(shape.original + relation.booleans + pair),
                reduce(
                    values.words[left] *
                        values.words[right] *
                        at.inverseVanishing,
                ),
            ),
        );
    });
    let reciprocalSum = zero;
    relation.lookups.forEach(({ column, factor }, index) => {
        const reciprocal = values.reciprocals[index];
        reciprocalSum = add(reciprocalSum, reciprocal);
        combined = add(
            combined,
            multiply(weight(shape.columns + 1 + index), reciprocal),
        );
        // The reciprocal times (beta - scaled word) is one on H.
        const residual = scale(
            subtract(
                multiply(
                    reciprocal,
                    subtract(
                        challenges.lookup,
                        base(values.words[column] * factor),
                    ),
                ),
                one,
            ),
            at.inverseVanishing,
        );
        combined = add(
            combined,
            multiply(
                weight(
                    shape.original +
                        relation.booleans +
                        relation.zeroProducts.length +
                        index,
                ),
                residual,
            ),
        );
    });
    combined = add(
        combined,
        multiply(
            weight(shape.columns + 1 + shape.lookups),
            values.tableReciprocal,
        ),
    );
    combined = add(
        combined,
        multiply(weight(shape.columns + 2 + shape.lookups), values.sumMask),
    );
    // The table reciprocal times (beta - T) is the multiplicity on H.
    const tableResidual = scale(
        subtract(
            multiply(
                subtract(challenges.lookup, base(at.table)),
                values.tableReciprocal,
            ),
            base(values.multiplicity),
        ),
        at.inverseVanishing,
    );
    combined = add(
        combined,
        multiply(weight(shape.oracles - 2), tableResidual),
    );
    // The affine remainder (c*(F + lookup sum) + G - claimed/H - Z_H*h)/X,
    // with the quotient h opened in the third tree.
    linear = add(
        linear,
        multiply(
            at.lookupWeight,
            subtract(reciprocalSum, values.tableReciprocal),
        ),
    );
    const constant =
        at.remainderConstant ??
        scale(
            add(multiply(challenges.mask, at.target), at.maskSum),
            inverse(BigInt(domain.systematic)),
        );
    const vanishing = reduce(power(at.x, BigInt(domain.systematic)) - 1n);
    const numerator = subtract(
        subtract(
            add(multiply(challenges.mask, linear), values.sumMask),
            constant,
        ),
        scale(values.quotient, vanishing),
    );
    combined = add(
        combined,
        multiply(weight(shape.oracles - 1), scale(numerator, at.inverseX)),
    );
    return add(combined, multiply(weight(shape.original - 1), values.quotient));
};

// A fold of the pair at x and -x: (f(x)+f(-x))/2 + z*(f(x)-f(-x))/(2x).
const fold = (
    left: Extension,
    right: Extension,
    challenge: Extension,
    inverseX: bigint,
) => {
    const half = inverse(2n);
    return add(
        scale(add(left, right), half),
        multiply(
            challenge,
            scale(subtract(left, right), (half * inverseX) % modulus),
        ),
    );
};

const verifyStages = (input: WordProofInput) => {
    const { relation, domain, role } = input;
    if (role.length === 0 || role.length > 1024)
        throw new Refused('Context', 'open');
    const header = parseHeader(input.header, relation.magic, domain);
    if (!header.statement.equals(Buffer.from(input.expectedStatement)))
        throw new Refused('Context', 'open');
    const shape = wordRelationShape(relation, domain);
    const challenges = deriveWordProofChallenges(
        relation,
        domain,
        role,
        header,
    );
    const firstPositions = requestedPositions(
        challenges.queries,
        domain.domain,
    );
    const parser = input.openStatement(challenges.affine, firstPositions);
    if (parser === undefined) throw new Refused('Context', 'open');
    const context = contextHash(relation, domain, role);
    for (const chunk of input.statement) {
        context.update(chunk);
        if (!parser.push(chunk)) throw new Refused('Encoding', 'statement');
    }
    if (!context.digest().equals(header.context))
        throw new Refused('Context', 'statement');
    const operator = parser.finish();
    if (operator === undefined) throw new Refused('Encoding', 'statement');
    if (
        operator.positions.length !== firstPositions.length ||
        operator.positions.some(
            (position, index) => position !== firstPositions[index],
        ) ||
        operator.coefficients.length !== shape.columns ||
        operator.coefficients.some(
            (column) => column.length !== firstPositions.length,
        )
    )
        throw new Error('The operator does not cover the queried positions.');
    const table = tableOnDomain(domain);
    const proof = Buffer.from(
        input.proof.buffer,
        input.proof.byteOffset,
        input.proof.byteLength,
    );
    let offset = 0;
    let stage = 0;
    const take = (length: number) => {
        if (offset + length > proof.length)
            throw new Refused('Incomplete', stage);
        return proof.subarray(offset, (offset += length));
    };

    // The first-stage rows and, from the second stage on, the values of the
    // current stage's word at its opened positions.
    type FirstRow = { words: bigint[]; multiplicity: bigint; mask: Extension };
    const firstRows: FirstRow[] = [];
    const secondRows: Extension[][] = [];
    let expected = new Map<number, Extension>();
    const stages = 3 + (domain.folds - 1);
    for (; stage < stages; stage++) {
        const length = stage < 3 ? domain.domain : domain.domain >> (stage - 2);
        const width =
            stage === 0
                ? shape.firstWidth
                : stage === 1
                  ? shape.secondWidth
                  : 48;
        const root =
            stage < 3 ? header.roots[stage] : header.foldRoots[stage - 3];
        const positions = requestedPositions(challenges.queries, length);
        if (readLittleEndian(take(4)) !== BigInt(positions.length))
            throw new Refused('Encoding', stage);
        const authenticated = new Map<number, Buffer>();
        const values = new Map<number, Extension>();
        positions.forEach((position, row) => {
            // The proof supplies a sibling label for every level whose node and
            // sibling are not yet authenticated, up to the first authenticated
            // ancestor or the root.
            let missing = 0;
            for (
                let node = length + position;
                node > 1 && !authenticated.has(node);
                node >>= 1
            )
                if (!authenticated.has(node ^ 1)) missing++;
            const opening = take(4 + width + 128 + 64 * missing);
            if (opening.readUInt32LE(0) !== position)
                throw new Refused('Encoding', stage);
            const data = opening.subarray(4, 4 + width);
            const fields = Array.from({ length: width / 16 }, (_, index) =>
                canonical(data.subarray(16 * index, 16 * (index + 1)), stage),
            );
            const salt = opening.subarray(4 + width, 4 + width + 128);
            let sibling = 4 + width + 128;
            let digest = merkleLeaf(role, stage, position, salt, data);
            let node = length + position;
            const pending: [number, Buffer][] = [];
            for (let level = 1; node > 1 && !authenticated.has(node); level++) {
                pending.push([node, digest]);
                let label = authenticated.get(node ^ 1);
                if (label === undefined) {
                    label = Buffer.from(
                        opening.subarray(sibling, (sibling += 64)),
                    );
                    pending.push([node ^ 1, label]);
                }
                digest =
                    node % 2 === 0
                        ? merkleNode(role, stage, level, digest, label)
                        : merkleNode(role, stage, level, label, digest);
                node >>= 1;
            }
            if (!digest.equals(authenticated.get(node) ?? root))
                throw new Refused('Authentication', stage);
            for (const [index, label] of pending)
                authenticated.set(index, label);
            if (stage === 0)
                firstRows.push({
                    words: fields.slice(0, shape.columns),
                    multiplicity: fields[shape.columns],
                    mask: [
                        fields[shape.columns + 1],
                        fields[shape.columns + 2],
                        fields[shape.columns + 3],
                    ],
                });
            else if (stage === 1)
                secondRows.push(
                    Array.from({ length: width / 48 }, (_, index) => [
                        fields[3 * index],
                        fields[3 * index + 1],
                        fields[3 * index + 2],
                    ]),
                );
            else {
                const value: Extension = [fields[0], fields[1], fields[2]];
                if (stage > 2) {
                    const folded = expected.get(position);
                    if (folded !== undefined && !equal(folded, value))
                        throw new Refused('Relation', stage);
                    values.set(position, value);
                } else {
                    const x = point(domain, position);
                    const vanishing = reduce(
                        power(x, BigInt(domain.systematic)) - 1n,
                    );
                    const second = secondRows[row];
                    values.set(
                        position,
                        combinedValue(
                            {
                                relation,
                                shape,
                                domain,
                                challenges,
                                coefficients: operator.coefficients.map(
                                    (column) => column[row],
                                ),
                                target: operator.target,
                                lookupWeight: operator.lookupWeight,
                                maskSum: header.maskSum,
                                x,
                                inverseX: inverse(x),
                                inverseVanishing: inverse(vanishing),
                                table: table[position],
                            },
                            {
                                words: firstRows[row].words,
                                multiplicity: firstRows[row].multiplicity,
                                degreeMask: firstRows[row].mask,
                                reciprocals: second.slice(0, shape.lookups),
                                tableReciprocal: second[shape.lookups],
                                sumMask: second[shape.lookups + 1],
                                quotient: value,
                            },
                        ),
                    );
                }
            }
        });
        if (stage >= 2) {
            // Fold this stage's word at the round's challenge.
            const round = stage - 2;
            const folded = positions.filter((value) => value < length / 2);
            const pointInverses = inverses(
                folded.map((position) =>
                    power(point(domain, position), 1n << BigInt(round)),
                ),
            );
            const next = new Map<number, Extension>();
            folded.forEach((position, index) => {
                const value = fold(
                    values.get(position)!,
                    values.get(position + length / 2)!,
                    challenges.folds[round],
                    pointInverses[index],
                );
                if (round === domain.folds - 1) {
                    if (!equal(value, header.terminal))
                        throw new Refused('Relation', stage);
                } else next.set(position, value);
            });
            expected = next;
        }
    }
    if (offset !== proof.length) throw new Refused('Length', stages - 1);
};

// A small-domain reference prover. The statement supplies the affine
// operator's coefficient of every column at every systematic position, its
// target and its lookup weight, as functions of the affine challenge. Its
// hostile modes keep the honest procedure except for one change: a false
// statement proves a witness that misses the affine target, and an excess
// degree raises the degree mask one degree above the largest code degree.
export type WordProofStatement = Readonly<{
    bytes: readonly Uint8Array[];
    operator: (affine: Extension) => Readonly<{
        coefficients: readonly (readonly Extension[])[];
        target: Extension;
        lookupWeight: Extension;
    }>;
}>;
export type WordProverMode = 'honest' | 'false-statement' | 'excess-degree';

// A deterministic stream of field elements and salts from a seed.
const seededStream = (seed: Uint8Array) => {
    let counter = 0;
    const draw = (length: number) =>
        createHash('shake256', { outputLength: length })
            .update(framed([seed, word32(counter++)]))
            .digest();
    const element = () => {
        for (;;) {
            const value = readLittleEndian(draw(16));
            if (value < modulus) return value;
        }
    };
    return {
        bytes: draw,
        element,
        extension: (): Extension => [element(), element(), element()],
    };
};

// A systematic interpolation plus the vanishing polynomial times a mask.
const masked = <Value>(
    interpolated: readonly Value[],
    mask: readonly Value[],
    negate: (value: Value) => Value,
    sum: (left: Value, right: Value) => Value,
): Value[] => {
    const result = [...interpolated, ...mask];
    mask.forEach((value, index) => {
        result[index] = sum(result[index], negate(value));
    });
    return result;
};
const multiplyPolynomials = (
    left: readonly Extension[],
    right: readonly Extension[],
) => {
    const result = Array.from(
        { length: left.length + right.length - 1 },
        () => zero,
    );
    left.forEach((value, first) => {
        if (equal(value, zero)) return;
        right.forEach((other, second) => {
            result[first + second] = add(
                result[first + second],
                multiply(value, other),
            );
        });
    });
    return result;
};

// A Merkle tree over one stage's leaves, numbered as a heap: the root is
// node one and leaf i is node L+i.
const merkleTree = (
    role: Uint8Array,
    stage: number,
    leaves: readonly Uint8Array[],
    salts: readonly Uint8Array[],
) => {
    const length = leaves.length;
    const nodes = new Array<Buffer>(2 * length);
    leaves.forEach((data, index) => {
        nodes[length + index] = merkleLeaf(
            role,
            stage,
            index,
            salts[index],
            data,
        );
    });
    for (let node = length - 1, level = 1, start = length / 2; node >= 1;) {
        nodes[node] = merkleNode(
            role,
            stage,
            level,
            nodes[2 * node],
            nodes[2 * node + 1],
        );
        node--;
        if (node < start) {
            level++;
            start /= 2;
        }
    }
    // Openings of the sorted positions with the sibling labels the verifier
    // does not yet hold.
    const open = (positions: readonly number[]) => {
        const authenticated = new Set<number>();
        const parts: Uint8Array[] = [word32(positions.length)];
        for (const position of positions) {
            parts.push(word32(position), leaves[position], salts[position]);
            for (
                let node = length + position;
                node > 1 && !authenticated.has(node);
                node >>= 1
            ) {
                authenticated.add(node);
                if (!authenticated.has(node ^ 1)) {
                    parts.push(nodes[node ^ 1]);
                    authenticated.add(node ^ 1);
                }
            }
        }
        return Buffer.concat(parts);
    };
    return { root: nodes[1], open };
};

const encodeBase = (value: bigint) => littleEndian(value, 16);

export const proveWordRelation = (
    input: Readonly<{
        relation: WordRelation;
        domain: WordProofDomain;
        role: Uint8Array;
        statement: WordProofStatement;
        statementDigest: Uint8Array;
        // Every column's values on the systematic subgroup.
        columns: readonly (readonly bigint[])[];
        seed: Uint8Array;
        mode: WordProverMode;
    }>,
) => {
    const { relation, domain, role, statement, columns, mode } = input;
    const shape = wordRelationShape(relation, domain);
    const random = seededStream(input.seed);
    const systematic = domain.systematic;
    if (
        columns.length !== shape.columns ||
        columns.some((column) => column.length !== systematic)
    )
        throw new RangeError('The witness does not match its relation.');
    // A false statement may hold an entry outside its table, which no
    // multiplicity counts.
    const counts = new Array<bigint>(systematic).fill(0n);
    for (const { column, factor } of relation.lookups)
        for (const value of columns[column]) {
            const entry = value * factor;
            if (entry < BigInt(systematic)) counts[Number(entry)]++;
            else if (mode !== 'false-statement')
                throw new RangeError('A lookup entry is outside its table.');
        }
    const context = wordStatementContext(
        relation,
        domain,
        role,
        statement.bytes,
    );
    const chain = transcript(role, context, relation.messageBytes);
    const salts = Array.from({ length: domain.folds + 3 }, () =>
        random.bytes(128),
    );
    const leafSalts = (count: number) =>
        Array.from({ length: count }, () => random.bytes(128));
    const points = Array.from({ length: domain.domain }, (_, position) =>
        point(domain, position),
    );

    // First oracle: masked columns and multiplicities, and the degree mask.
    const baseMask = () =>
        Array.from({ length: domain.masks }, () => random.element());
    const negateBase = (value: bigint) => reduce(-value);
    const sumBase = (left: bigint, right: bigint) => reduce(left + right);
    const committedBase = [...columns, counts].map((values) =>
        masked(interpolate(values), baseMask(), negateBase, sumBase),
    );
    const baseValues = committedBase.map((coefficients) =>
        evaluateOnCoset(coefficients, domain),
    );
    const degreeMask = Array.from(
        { length: domain.maximumDegree + (mode === 'excess-degree' ? 2 : 1) },
        () => random.extension(),
    );
    const degreeMaskValues = evaluateExtensionOnCoset(degreeMask, domain);
    const first = merkleTree(
        role,
        0,
        points.map((_, position) =>
            Buffer.concat([
                ...baseValues.map((values) => encodeBase(values[position])),
                encodeExtension(degreeMaskValues[position]),
            ]),
        ),
        leafSalts(domain.domain),
    );
    chain.respond(1, salts[0], [first.root]);

    // Second oracle: every lookup reciprocal, the table reciprocal and the
    // sum mask, whose sum over H the header carries.
    const lookup = sample(chain.message(2), 0, true);
    const extensionMask = () =>
        Array.from({ length: domain.masks }, () => random.extension());
    const negateExtension = (value: Extension) => subtract(zero, value);
    const maskedReciprocal = (values: readonly Extension[]) =>
        masked(
            interpolateExtension(values),
            extensionMask(),
            negateExtension,
            add,
        );
    const reciprocalCoefficients = [
        ...relation.lookups.map(({ column, factor }) =>
            maskedReciprocal(
                columns[column].map((value) =>
                    invertExtension(subtract(lookup, base(value * factor))),
                ),
            ),
        ),
        maskedReciprocal(
            counts.map((count, index) =>
                scale(
                    invertExtension(subtract(lookup, base(BigInt(index)))),
                    count,
                ),
            ),
        ),
    ];
    const reciprocalValues = reciprocalCoefficients.map((coefficients) =>
        evaluateExtensionOnCoset(coefficients, domain),
    );
    const reciprocals = reciprocalValues.slice(0, -1);
    const tableReciprocal = reciprocalValues[reciprocalValues.length - 1];
    const sumMask = Array.from({ length: domain.witnessDegree + 1 }, () =>
        random.extension(),
    );
    const maskSum = scale(
        sumMask
            .filter((_, degree) => degree % systematic === 0)
            .reduce(add, zero),
        BigInt(systematic),
    );
    const sumMaskValues = evaluateExtensionOnCoset(sumMask, domain);
    const second = merkleTree(
        role,
        1,
        points.map((_, position) =>
            Buffer.concat(
                [
                    ...reciprocals.map((values) => values[position]),
                    tableReciprocal[position],
                    sumMaskValues[position],
                ].map(encodeExtension),
            ),
        ),
        leafSalts(domain.domain),
    );
    chain.respond(2, salts[1], [second.root, encodeExtension(maskSum)]);

    // Affine quotient: c*(F + lookup weight * lookup sum) + G divided by the
    // vanishing polynomial; the remainder's constant must be the claimed sum
    // over H.
    const third = chain.message(3);
    const affine = sample(third, 0, false);
    const maskChallenge = sample(third, 1, false);
    const operator = statement.operator(affine);
    const combinedAffine: Extension[] = Array.from(
        { length: systematic + domain.witnessDegree },
        (_, degree) => sumMask[degree] ?? zero,
    );
    const accumulate = (coefficients: readonly Extension[]) =>
        coefficients.forEach((value, degree) => {
            combinedAffine[degree] = add(
                combinedAffine[degree],
                multiply(maskChallenge, value),
            );
        });
    columns.forEach((_, column) =>
        accumulate(
            multiplyPolynomials(
                interpolateExtension(operator.coefficients[column]),
                committedBase[column].map((value) => base(value)),
            ),
        ),
    );
    // The lookup sum: every lookup's reciprocals minus the table's.
    const tableCoefficients =
        reciprocalCoefficients[reciprocalCoefficients.length - 1];
    accumulate(
        tableCoefficients.map((tableValue, degree) =>
            multiply(
                operator.lookupWeight,
                subtract(
                    reciprocalCoefficients
                        .slice(0, -1)
                        .reduce(
                            (sum, values) => add(sum, values[degree]),
                            zero,
                        ),
                    tableValue,
                ),
            ),
        ),
    );
    // Division by X^H - 1: the quotient's coefficient of degree i sums the
    // coefficients of degrees i+H, i+2H, ..., and the remainder's coefficient
    // of degree j < H adds the quotient's coefficient of degree j.
    const remainder = combinedAffine.slice(0, systematic);
    const quotient = combinedAffine.slice(systematic);
    for (let index = quotient.length - 1; index >= systematic; index--)
        quotient[index - systematic] = add(
            quotient[index - systematic],
            quotient[index],
        );
    for (let index = 0; index < Math.min(systematic, quotient.length); index++)
        remainder[index] = add(remainder[index], quotient[index]);
    const claimed = scale(
        add(multiply(maskChallenge, operator.target), maskSum),
        inverse(BigInt(systematic)),
    );
    if (mode !== 'false-statement' && !equal(remainder[0], claimed))
        throw new RangeError('The witness misses the affine target.');
    if (mode === 'false-statement' && equal(remainder[0], claimed))
        throw new RangeError('A false statement meets the affine target.');
    const quotientValues = evaluateExtensionOnCoset(quotient, domain);
    const linear = merkleTree(
        role,
        2,
        quotientValues.map(encodeExtension),
        leafSalts(domain.domain),
    );
    chain.respond(3, salts[2], [linear.root]);

    // The combined word at every point, with the remainder constant the
    // prover's own quotient leaves, then the folds and the terminal.
    const table = tableOnDomain(domain);
    const fourth = chain.message(4);
    const combination = Array.from({ length: 2 * shape.oracles }, (_, index) =>
        sample(fourth, index, false),
    );
    const pointInverses = inverses(points);
    const vanishingInverses = inverses(
        points.map((x) => reduce(power(x, BigInt(systematic)) - 1n)),
    );
    const challenges = { lookup, mask: maskChallenge, combination };
    const coefficientValues = operator.coefficients.map((column) =>
        evaluateExtensionOnCoset(interpolateExtension(column), domain),
    );
    let layer = points.map((x, position) =>
        combinedValue(
            {
                relation,
                shape,
                domain,
                challenges,
                coefficients: coefficientValues.map(
                    (column) => column[position],
                ),
                target: operator.target,
                lookupWeight: operator.lookupWeight,
                maskSum,
                x,
                inverseX: pointInverses[position],
                inverseVanishing: vanishingInverses[position],
                table: table[position],
                remainderConstant: remainder[0],
            },
            {
                words: columns.map((_, column) => baseValues[column][position]),
                multiplicity: baseValues[shape.columns][position],
                degreeMask: degreeMaskValues[position],
                reciprocals: reciprocals.map((values) => values[position]),
                tableReciprocal: tableReciprocal[position],
                sumMask: sumMaskValues[position],
                quotient: quotientValues[position],
            },
        ),
    );
    const foldTrees: ReturnType<typeof merkleTree>[] = [];
    let terminal = zero;
    for (let round = 0; round < domain.folds; round++) {
        const challenge = sample(
            chain.message(4 + round),
            round === 0 ? 2 * shape.oracles : 0,
            false,
        );
        const half = layer.length / 2;
        const foldInverses = inverses(
            Array.from({ length: half }, (_, position) =>
                power(point(domain, position), 1n << BigInt(round)),
            ),
        );
        layer = Array.from({ length: half }, (_, position) =>
            fold(
                layer[position],
                layer[position + half],
                challenge,
                foldInverses[position],
            ),
        );
        if (round === domain.folds - 1) {
            terminal = layer[0];
            chain.respond(4 + round, salts[3 + round], [
                encodeExtension(terminal),
            ]);
        } else {
            const tree = merkleTree(
                role,
                3 + round,
                layer.map(encodeExtension),
                leafSalts(layer.length),
            );
            foldTrees.push(tree);
            chain.respond(4 + round, salts[3 + round], [tree.root]);
        }
    }
    const final = chain.message(domain.folds + 4);
    const queries = Array.from(
        { length: domain.queries },
        (_, index) => final.readUInt32LE(4 * index) % (domain.domain / 2),
    );
    const header = Buffer.concat([
        relation.magic,
        input.statementDigest,
        context,
        first.root,
        second.root,
        linear.root,
        encodeExtension(maskSum),
        ...salts,
        ...foldTrees.map((tree) => tree.root),
        encodeExtension(terminal),
    ]);
    const openings = [first, second, linear].map((tree) =>
        tree.open(requestedPositions(queries, domain.domain)),
    );
    foldTrees.forEach((tree, index) =>
        openings.push(
            tree.open(
                requestedPositions(queries, domain.domain >> (index + 1)),
            ),
        ),
    );
    // Each stage's openings begin at its offset in the proof.
    let start = 0;
    const stages = openings.map((opening) => {
        const offset = start;
        start += opening.length;
        return offset;
    });
    return { header, proof: Buffer.concat(openings), stages };
};
