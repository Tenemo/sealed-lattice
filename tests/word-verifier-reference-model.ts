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
    contextHash,
    type WordVerifierVerdict,
    Refused,
    canonical,
    parseHeader,
    deriveWordProofChallenges,
    requestedPositions,
    type WordStatementParser,
} from '#tests/word-proof-reference/transcript.js';

// An independent reading of the bounded word proof from the protocol's
// description: its header, the salted wide verifier-message chain, the
// salted Merkle openings of every stage, the combined rational word at
// every queried point, and each fold down to the terminal constant. The
// statement parser is an input: it receives the affine challenge and the
// queried positions, consumes the statement, and yields the affine operator
// at those positions. A small-domain reference prover exercises the same
// grammar with honest and hostile proofs.

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
