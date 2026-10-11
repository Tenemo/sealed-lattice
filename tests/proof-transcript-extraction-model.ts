import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import {
    hasProofHashLayout,
    parseProofHashInput,
    type ProofHashInput,
} from '#tests/proof-hash-domain-model.js';
import { resolveProofContext } from '#tests/proof-relation-catalogue-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

// A projection of a consistent full-XOF database. Each challenged record
// supplies its tag prefix; an edge needing a longer prefix checks it below.
// The bad-database argument uses full words, not an incomplete capture.
// Inputs and the original honest-owner set stay fixed while using a result.
// This model neither executes a proof verifier nor supplies a capability.
export type RawProofHashRecord = Readonly<{
    input: Buffer;
    output: Buffer;
}>;

type IndexedRecord = {
    input: Buffer;
    output: Buffer;
    parsed: ProofHashInput;
};

const tagBytes = 64;
const agreement = compileCommonAgreementDegreeCensus();
const fieldModulus = compileSmallLimbProofFieldCensus().modulus;
const folds = Math.log2(agreement.domainSize / 2);

const canonicalFieldWords = (bytes: Buffer) => {
    if (bytes.length % 16 !== 0) return false;
    for (let offset = 0; offset < bytes.length; offset += 16) {
        const value =
            bytes.readBigUInt64LE(offset) +
            (bytes.readBigUInt64LE(offset + 8) << 64n);
        if (value >= fieldModulus) return false;
    }
    return true;
};

// No auxiliary hash is used as an identity: duplicate inputs are compared
// literally. Tag collisions include raw members with unusable typed layouts.
const indexRecords = (
    records: readonly RawProofHashRecord[],
    honestOwners: ReadonlySet<string>,
) => {
    // Literal end bytes only select a bucket. Equality still compares the
    // complete input, including any middle bytes omitted from this key.
    // Adversarial buckets can remain quadratic; no reduction-time bound is
    // inferred from the ordinary captured-trace lookup performance.
    const inputs = new Map<string, IndexedRecord[]>();
    const tags = new Map<string, IndexedRecord>();
    for (const record of records) {
        const parsed = parseProofHashInput(record.input);
        if (parsed === undefined || honestOwners.has(parsed.owner)) continue;
        if (record.output.length < tagBytes)
            throw new RangeError('A challenged record lacks its tag prefix.');
        const bucketKey = `${record.input.length}:${record.input.subarray(0, tagBytes).toString('hex')}:${record.input.subarray(-tagBytes).toString('hex')}`;
        const bucket = inputs.get(bucketKey) ?? [];
        const duplicate = bucket.find((known) =>
            known.input.equals(record.input),
        );
        if (duplicate !== undefined) {
            const common = Math.min(
                duplicate.output.length,
                record.output.length,
            );
            if (
                !duplicate.output
                    .subarray(0, common)
                    .equals(record.output.subarray(0, common))
            )
                throw new RangeError('Inconsistent outputs for one raw input.');
            if (record.output.length > duplicate.output.length)
                duplicate.output = record.output;
            continue;
        }
        const key = `${parsed.role}:${record.output.subarray(0, tagBytes).toString('hex')}`;
        if (tags.has(key)) return undefined;
        const indexed = { ...record, parsed };
        bucket.push(indexed);
        inputs.set(bucketKey, bucket);
        tags.set(key, indexed);
    }
    return (role: string, tag: Buffer) =>
        tag.length === tagBytes
            ? tags.get(`${role}:${tag.toString('hex')}`)
            : undefined;
};

export const rawProofHashHasCollision = (
    records: readonly RawProofHashRecord[],
    honestOwners: ReadonlySet<string>,
) => indexRecords(records, honestOwners) === undefined;

export const extractRawProofPrefix = (
    records: readonly RawProofHashRecord[],
    verifierInput: Buffer,
    honestOwners: ReadonlySet<string>,
) => {
    const query = parseProofHashInput(verifierInput);
    if (
        query?.family !== 'verifier-message' ||
        honestOwners.has(query.owner) ||
        !hasProofHashLayout(query)
    )
        return undefined;
    const find = indexRecords(records, honestOwners);
    if (find === undefined) return undefined;
    const contextTag = query.fields[0];
    const context = find(query.role, contextTag);
    if (context?.parsed.family !== 'statement') return undefined;
    const aliases = resolveProofContext(context.parsed.fields);
    if (
        aliases.length === 0 ||
        new Set(aliases.map((entry) => entry.arithmeticKey)).size !== 1
    )
        return undefined;
    const relation = aliases[0];
    const messageBytes = Number(relation.messageBytes);
    if (
        aliases.some((entry) => entry.messageBytes !== relation.messageBytes) ||
        query.fields[1].length !== messageBytes
    )
        return undefined;
    const sameScope = (record: IndexedRecord | undefined) =>
        record !== undefined &&
        record.parsed.role === query.role &&
        record.parsed.fields[0].equals(contextTag);
    let state = query.fields[1];
    const messages: Buffer[] = [];
    const responseParts: Buffer[][] = [];
    for (let round = query.fields[2].readUInt32LE() - 1; round >= 1; round--) {
        const responseTag = state.subarray(0, tagBytes);
        const tail = state.subarray(tagBytes);
        const chain = find(query.role, tail.subarray(0, tagBytes));
        if (
            chain?.parsed.family !== 'chain-state' ||
            !sameScope(chain) ||
            !chain.parsed.fields[2].equals(responseTag) ||
            chain.parsed.fields[1].length !== messageBytes ||
            chain.output.length < tail.length ||
            !chain.output.subarray(0, tail.length).equals(tail)
        )
            return undefined;
        const previousMessage = chain.parsed.fields[1];
        const previous = find(
            query.role,
            previousMessage.subarray(0, tagBytes),
        );
        if (
            previous?.parsed.family !== 'verifier-message' ||
            !sameScope(previous) ||
            previous.parsed.fields[2].readUInt32LE() !== round ||
            previous.parsed.fields[1].length !== messageBytes ||
            previous.output.length < messageBytes ||
            !previous.output.subarray(0, messageBytes).equals(previousMessage)
        )
            return undefined;
        const response = find(query.role, responseTag);
        if (
            response?.parsed.family !== 'message-root' ||
            !sameScope(response) ||
            response.parsed.fields[1].readUInt32LE() !== round ||
            !hasProofHashLayout(response.parsed)
        )
            return undefined;
        const parts = response.parsed.fields.slice(3);
        const scalar =
            round === 2 ? parts[1] : round === folds + 3 ? parts[0] : undefined;
        if (scalar !== undefined && !canonicalFieldWords(scalar))
            return undefined;
        messages.unshift(previousMessage);
        responseParts.unshift(parts);
        state = previous.parsed.fields[1];
    }
    if (state.some((byte) => byte !== 0)) return undefined;

    // Trees carry role, stage, level and leaf index, but no context field.
    // Reusing identical raw tree inputs across contexts is intentional.
    const oracles = responseParts
        .filter((_, stage) => stage < folds + 2)
        .map((parts, stage) => {
            const length =
                stage < 3
                    ? agreement.domainSize
                    : agreement.domainSize / 2 ** (stage - 2);
            const width = Number(
                stage === 0
                    ? relation.firstWidth
                    : stage === 1
                      ? relation.secondWidth
                      : 48n,
            );
            const root = parts[0];
            return {
                stage,
                length,
                width,
                root,
                leaf: (position: number): Buffer | undefined => {
                    if (
                        !Number.isSafeInteger(position) ||
                        position < 0 ||
                        position >= length
                    )
                        return undefined;
                    let tag = root;
                    for (let level = Math.log2(length); level >= 1; level--) {
                        const node = find(query.role, tag)?.parsed;
                        if (
                            node?.family !== 'node' ||
                            node.fields[0].readUInt32LE() !== stage ||
                            node.fields[1].readUInt32LE() !== level
                        )
                            return undefined;
                        const right =
                            Math.floor(position / 2 ** (level - 1)) % 2;
                        tag = node.fields[2 + right];
                    }
                    const leaf = find(query.role, tag)?.parsed;
                    if (
                        leaf?.family !== 'leaf' ||
                        leaf.fields[0].readUInt32LE() !== stage ||
                        leaf.fields[1].readUInt32LE() !== position ||
                        leaf.fields[3].length !== width ||
                        !canonicalFieldWords(leaf.fields[3])
                    )
                        return undefined;
                    return leaf.fields[3];
                },
            };
        });
    return {
        role: query.role,
        context: context.input,
        // One representative of the effective relation, not a uniquely
        // inferred roster/profile. The complete compatible set is retained.
        relation,
        aliases,
        messages,
        responses: responseParts,
        oracles,
    };
};
