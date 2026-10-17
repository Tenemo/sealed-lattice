import {
    merkleLeaf,
    merkleNode,
} from '#tests/word-proof-reference/commitments.js';
import {
    type Extension,
    reduce,
    power,
    inverse,
    inverses,
    equal,
    point,
    tableOnDomain,
    add,
    subtract,
    multiply,
    scale,
    base,
    invertExtension,
} from '#tests/word-proof-reference/field.js';
import {
    combinedValue,
    fold,
} from '#tests/word-proof-reference/relation-evaluation.js';
import {
    type WordProofDomain,
    type WordRelation,
    wordRelationShape,
    readLittleEndian,
    type WordVerifierVerdict,
    Refused,
    canonical,
    parseHeader,
    deriveWordProofChallenges,
    requestedPositions,
    type WordStatementParser,
    protocolHash,
    word32,
} from '#tests/word-proof-reference/transcript.js';

// An independent reading of the bounded word proof from the protocol's
// description: its header, the statement context that binds the declared
// statement digest, the salted wide verifier-message chain, the
// salted Merkle openings of every stage, the combined rational word at
// every queried point, and each fold down to the terminal constant. The
// statement parser is an input: it receives the statement digest the
// header declares, the affine challenge and the queried positions, consumes
// the statement, which must have that digest, and yields the affine operator
// at those positions. A small-domain reference prover exercises the same
// grammar with honest and hostile proofs.

export type WordProofInput = Readonly<{
    relation: WordRelation;
    domain: WordProofDomain;
    role: Uint8Array;
    header: Uint8Array;
    // The statement's complete public input, in chunks.
    statement: Iterable<Uint8Array>;
    // Undefined when the parser refuses the challenge or positions.
    openStatement: (
        statement: Uint8Array,
        affine: Extension,
        positions: readonly number[],
        publicRoot: Uint8Array | undefined,
        evaluations: readonly Extension[],
    ) => WordStatementParser | undefined;
    proof: Uint8Array;
}>;

// Verifies one proof. Refusals follow the order of the stages: the header
// and its statement, the statement's chunks and digest, then the proof's
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

const verifyStages = (input: WordProofInput) => {
    const { relation, domain, role } = input;
    if (role.length === 0 || role.length > 1024)
        throw new Refused('Context', 'open');
    const header = parseHeader(
        input.header,
        domain,
        relation.publicColumns ?? 0,
    );
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
    const parser = input.openStatement(
        header.statement,
        challenges.affine,
        firstPositions,
        header.publicRoot,
        header.evaluations,
    );
    if (parser === undefined) throw new Refused('Context', 'open');
    for (const chunk of input.statement)
        if (!parser.push(chunk)) throw new Refused('Encoding', 'statement');
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
    const publicStages = Number(shape.publicColumns > 0);
    const stages = 3 + publicStages + (domain.folds - 1);
    let wordValues = new Map<number, Extension>();
    for (; stage < stages; stage++) {
        const publicStage = publicStages > 0 && stage === 3;
        const length =
            stage < 3 + publicStages
                ? domain.domain
                : domain.domain >> (stage - 2 - publicStages);
        const width =
            stage === 0
                ? shape.firstWidth
                : stage === 1
                  ? shape.secondWidth
                  : publicStage
                    ? 16 * shape.publicColumns
                    : 48;
        const root =
            stage < 3
                ? header.roots[stage]
                : publicStage
                  ? header.publicRoot!
                  : header.foldRoots[stage - 3 - publicStages];
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
            const saltBytes = publicStage ? 0 : 128;
            const opening = take(4 + width + saltBytes + 64 * missing);
            if (opening.readUInt32LE(0) !== position)
                throw new Refused('Encoding', stage);
            const data = opening.subarray(4, 4 + width);
            const fields = Array.from({ length: width / 16 }, (_, index) =>
                canonical(data.subarray(16 * index, 16 * (index + 1)), stage),
            );
            const salt = opening.subarray(4 + width, 4 + width + saltBytes);
            let sibling = 4 + width + saltBytes;
            let digest = publicStage
                ? protocolHash('committed-key/leaf', [
                      role,
                      word32(position),
                      data,
                  ])
                : merkleLeaf(role, stage, position, salt, data);
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
                const hashNode = (left: Buffer, right: Buffer) =>
                    publicStage
                        ? protocolHash('committed-key/node', [
                              role,
                              word32(level),
                              left,
                              right,
                          ])
                        : merkleNode(role, stage, level, left, right);
                digest =
                    node % 2 === 0
                        ? hashNode(digest, label)
                        : hashNode(label, digest);
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
            else if (publicStage) {
                const x = point(domain, position);
                const denominator = invertExtension(
                    subtract(base(x), challenges.affine),
                );
                let combined = wordValues.get(position)!;
                for (let column = 0; column < shape.publicColumns; column++) {
                    const oracle = shape.wordOracles + 2 * column;
                    const weight = (index: number) =>
                        add(
                            challenges.combination[2 * index],
                            scale(
                                challenges.combination[2 * index + 1],
                                power(
                                    x,
                                    BigInt(
                                        domain.maximumDegree -
                                            shape.degrees[index],
                                    ),
                                ),
                            ),
                        );
                    const quotient = multiply(
                        subtract(
                            base(fields[column]),
                            header.evaluations[column],
                        ),
                        denominator,
                    );
                    combined = add(
                        combined,
                        add(
                            scale(weight(oracle), fields[column]),
                            multiply(weight(oracle + 1), quotient),
                        ),
                    );
                }
                values.set(position, combined);
            } else {
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
        if (stage === 2 && publicStages > 0) wordValues = values;
        if (stage >= 2 + publicStages) {
            // Fold this stage's word at the round's challenge.
            const round = stage - 2 - publicStages;
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
