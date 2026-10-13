import { createHash } from 'node:crypto';

import { compileBallotEncryptionColumnLayout } from '#tests/ballot-encryption-relation-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileLinkedReleaseColumnLayout } from '#tests/linked-release-relation-model.js';
import type { ProofRelationCatalogueEntry } from '#tests/proof-relation-catalogue-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import {
    modulus,
    shift,
    type Extension,
    power,
    zero,
} from '#tests/word-proof-reference/field.js';

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

export const littleEndian = (value: number | bigint, bytes: number) => {
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

export const word32 = (value: number | bigint) => littleEndian(value, 4);

export const readLittleEndian = (bytes: Uint8Array) => {
    let value = 0n;
    for (let index = bytes.length - 1; index >= 0; index--)
        value = (value << 8n) | BigInt(bytes[index]);
    return value;
};

export const framed = (parts: readonly Uint8Array[]) =>
    Buffer.concat(parts.flatMap((part) => [word32(part.length), part]));

// The fixed-length protocol digest: 64 bytes of SHAKE256 after a 64-byte
// domain prefix.
const protocolPrefix = Buffer.alloc(64);

protocolPrefix.write('sealed-lattice/fixed-hash/v1', 'ascii');

export const protocolHash = (domain: string, parts: readonly Uint8Array[]) =>
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
export const contextHash = (
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

export const wordStatementContext = (
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
export const sample = (
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

export class Refused extends Error {
    constructor(
        readonly refusal: WordVerifierRefusal | 'Incomplete',
        readonly stage: WordVerifierStage,
    ) {
        super(refusal);
    }
}

export const canonical = (bytes: Uint8Array, stage: WordVerifierStage) => {
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

export const parseHeader = (
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

export const encodeExtension = (value: Extension) =>
    Buffer.concat(value.map((coordinate) => littleEndian(coordinate, 16)));

// Each round's verifier message hashes the role, context, previous state
// and round; a salted short root commits that round's prover message; and
// the next state is that root followed by a wide hash of the message and
// the root. The prover's responses supply the committed parts of a round.
type Transcript = Readonly<{
    message: (round: number) => Buffer;
    respond: (round: number, salt: Uint8Array, parts: Uint8Array[]) => void;
}>;

export const transcript = (
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

export const deriveWordProofChallenges = (
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
export const requestedPositions = (
    queries: readonly number[],
    length: number,
) =>
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
