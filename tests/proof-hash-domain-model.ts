import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import {
    framedProofHashBytes,
    saltedProofHashInputs,
} from '#tests/proof-hash-work-model.js';
import {
    proofRelationCatalogue,
    type ProofRelationCatalogueEntry,
} from '#tests/proof-relation-catalogue-model.js';
import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';

// Independent raw-input recognizer for the three fixed proof purposes. It does
// not verify a proof, authenticate an identity or observe native hash calls.
// Source grammar: word-verifier/engine.rs, supported-profile/relation.rs and
// the original-identity role constructors in registration-credentials.
const agreement = compileCommonAgreementDegreeCensus();
const tagBytes = 64;
const saltBytes = 128;
const elementBytes = 48;
const fixedPrefix = Buffer.alloc(64);
fixedPrefix.write('sealed-lattice/fixed-hash/v1');
type Purpose = ProofRelationCatalogueEntry['role'];
const purposeCatalogues = new Map<
    Purpose,
    readonly ProofRelationCatalogueEntry[]
>();
const purposes: Readonly<Record<Purpose, string>> = {
    setup: 'sealed-lattice/setup-contribution/v2',
    ballot: 'sealed-lattice/ballot-proof/v2',
    release: 'sealed-lattice/certified-release/v2',
};
const originalOwner = (bytes: Buffer) =>
    bytes.length === 128 &&
    [...bytes].every(
        (value) =>
            (value >= 48 && value <= 57) || (value >= 97 && value <= 102),
    );
const parseRole = (
    role: Buffer,
): { purpose: Purpose; owner: string } | undefined => {
    if (
        role.length < 8 ||
        role.readUInt16LE(0) !== 1 ||
        role.readUInt16LE(2) !== 1
    )
        return undefined;
    const count = role.readUInt32LE(4);
    if (count !== 6 && count !== 7) return undefined;
    let offset = 8;
    const items: { type: number; bytes: Buffer }[] = [];
    for (let index = 0; index < count; index++) {
        if (offset + 6 > role.length) return undefined;
        const type = role.readUInt16LE(offset),
            length = role.readUInt32LE(offset + 2);
        offset += 6;
        if (length > role.length - offset) return undefined;
        items.push({ type, bytes: role.subarray(offset, offset + length) });
        offset += length;
    }
    if (offset !== role.length) return undefined;
    const ascii = (index: number) => {
        const item = items[index];
        return item.type === 2 &&
            item.bytes.length >= 4 &&
            item.bytes.readUInt32LE(0) === item.bytes.length - 4
            ? item.bytes.subarray(4)
            : undefined;
    };
    const domain = ascii(0),
        owner = ascii(1);
    if (!domain || !owner || !originalOwner(owner)) return undefined;
    const purpose = (Object.keys(purposes) as Purpose[]).find((candidate) =>
        domain.equals(Buffer.from(purposes[candidate])),
    );
    if (
        !purpose ||
        count !== (purpose === 'release' ? 7 : 6) ||
        items
            .slice(2, -1)
            .some((item) => item.type !== 6 || item.bytes.length !== 64) ||
        items[items.length - 1].type !== 3 ||
        items[items.length - 1].bytes.length !== 2
    )
        return undefined;
    return { purpose, owner: owner.toString('ascii') };
};

export type ProofHashInput = {
    family:
        | 'leaf'
        | 'node'
        | 'message-root'
        | 'statement'
        | 'verifier-message'
        | 'chain-state';
    role: string;
    owner: string;
    purpose: Purpose;
    candidates: readonly ProofRelationCatalogueEntry[];
    fields: readonly Buffer[];
    references: readonly Buffer[];
};

export const parseProofHashInput = (
    input: Uint8Array,
): ProofHashInput | undefined => {
    const bytes = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    const fixed = bytes.subarray(0, fixedPrefix.length).equals(fixedPrefix);
    let position = fixed ? fixedPrefix.length : 0;
    const part = () => {
        if (position + 4 > bytes.length) return undefined;
        const length = bytes.readUInt32LE(position);
        position += 4;
        if (length > bytes.length - position) return undefined;
        const value = bytes.subarray(position, position + length);
        position += length;
        return value;
    };
    const domain = part();
    const role = part();
    if (!domain || !role) return undefined;
    const scope = parseRole(role);
    if (!scope) return undefined;
    let candidates = purposeCatalogues.get(scope.purpose);
    if (candidates === undefined) {
        candidates = proofRelationCatalogue().filter(
            (entry) => entry.role === scope.purpose,
        );
        purposeCatalogues.set(scope.purpose, candidates);
    }
    const fields: Buffer[] = [];
    while (position < bytes.length) {
        const field = part();
        if (!field) return undefined;
        fields.push(field);
    }
    const shape = (...lengths: number[]) =>
        fields.length === lengths.length &&
        fields.every((field, index) => field.length === lengths[index]);
    const result = (
        family: ProofHashInput['family'],
        references: readonly Buffer[] = [],
    ): ProofHashInput => ({
        family,
        role: role.toString('hex'),
        ...scope,
        candidates,
        fields,
        references,
    });
    // Full equality avoids ASCII decoding aliases for high-bit domain bytes.
    const named = (name: string) =>
        domain.equals(Buffer.from(`bounded-proof/${name}`));
    if (
        fixed &&
        named('leaf') &&
        candidates.some((entry) =>
            [entry.firstWidth, entry.secondWidth, BigInt(elementBytes)].some(
                (width) => shape(4, 4, saltBytes, Number(width)),
            ),
        )
    )
        return result('leaf');
    if (fixed && named('node') && shape(4, 4, tagBytes, tagBytes))
        return result('node', [fields[2], fields[3]]);
    if (
        fixed &&
        named('message-root') &&
        (shape(tagBytes, 4, saltBytes, tagBytes) ||
            shape(tagBytes, 4, saltBytes, tagBytes, elementBytes) ||
            shape(tagBytes, 4, saltBytes, elementBytes))
    )
        return result('message-root', [
            fields[0],
            ...fields.slice(3, 4).filter((field) => field.length === tagBytes),
        ]);
    if (
        fixed &&
        named('statement') &&
        candidates.some(
            (entry) =>
                shape(
                    entry.relationTag.length,
                    16,
                    16,
                    16,
                    Number(entry.parameterBytes),
                    16,
                    Number(entry.statementBytes),
                ) && fields[0].equals(Buffer.from(entry.relationTag)),
        )
    )
        return result('statement');
    if (
        !fixed &&
        named('verifier-message') &&
        candidates.some((entry) =>
            shape(tagBytes, Number(entry.messageBytes), 4),
        )
    )
        return result('verifier-message', [
            fields[0],
            fields[1].subarray(0, tagBytes),
            fields[1].subarray(tagBytes, 2 * tagBytes),
        ]);
    if (
        !fixed &&
        named('chain-state') &&
        candidates.some((entry) =>
            shape(tagBytes, Number(entry.messageBytes), tagBytes),
        )
    )
        return result('chain-state', [
            fields[0],
            fields[1].subarray(0, tagBytes),
            fields[2],
        ]);
    // All other raw inputs use the complementary function, regardless of API.
    return undefined;
};

export const isProofChallengeInput = (
    input: Uint8Array,
    honestOwners: ReadonlySet<string>,
) => {
    const parsed = parseProofHashInput(input);
    return parsed !== undefined && !honestOwners.has(parsed.owner);
};

// Semantic layouts are separate from raw namespace membership. These checks
// cover stage/round shape only, not field reduction or statement correctness.
export const hasProofHashLayout = (input: ProofHashInput) => {
    const fields = input.fields;
    const integer = (index: number) => fields[index].readUInt32LE();
    const folds = Math.log2(agreement.domainSize / 2);
    const stageLength = (stage: number) =>
        stage < 3
            ? agreement.domainSize
            : agreement.domainSize / 2 ** (stage - 2);
    switch (input.family) {
        case 'leaf': {
            const stage = integer(0);
            return (
                stage < folds + 2 &&
                integer(1) < stageLength(stage) &&
                input.candidates.some(
                    (entry) =>
                        fields[3].length ===
                        Number(
                            stage === 0
                                ? entry.firstWidth
                                : stage === 1
                                  ? entry.secondWidth
                                  : elementBytes,
                        ),
                )
            );
        }
        case 'node': {
            const stage = integer(0),
                level = integer(1);
            return (
                stage < folds + 2 &&
                level >= 1 &&
                level <= Math.log2(stageLength(stage))
            );
        }
        case 'message-root': {
            const round = integer(1);
            return (
                round >= 1 &&
                round <= folds + 3 &&
                (round === 2
                    ? fields.length === 5
                    : round === folds + 3
                      ? fields.length === 4 && fields[3].length === elementBytes
                      : fields.length === 4 && fields[3].length === tagBytes)
            );
        }
        case 'verifier-message':
            return integer(2) >= 1 && integer(2) <= folds + 4;
        case 'chain-state':
        case 'statement':
            return true;
    }
};

export const compileProofHashDomainCensus = () => {
    const descriptors = proofRelationCatalogue();
    const rows = descriptors.map((entry) => {
        const salted = saltedProofHashInputs(entry, entry.roleBytes);
        const frames = [
            ...salted.leaves,
            ...salted.messageRoots,
            64n +
                framedProofHashBytes('bounded-proof/node', [
                    entry.roleBytes,
                    4n,
                    4n,
                    64n,
                    64n,
                ]),
            64n +
                framedProofHashBytes('bounded-proof/statement', [
                    entry.roleBytes,
                    BigInt(entry.relationTag.length),
                    16n,
                    16n,
                    16n,
                    entry.parameterBytes,
                    16n,
                    entry.statementBytes,
                ]),
            framedProofHashBytes('bounded-proof/verifier-message', [
                entry.roleBytes,
                64n,
                entry.messageBytes,
                4n,
            ]),
            framedProofHashBytes('bounded-proof/chain-state', [
                entry.roleBytes,
                64n,
                entry.messageBytes,
                64n,
            ]),
        ];
        return {
            purpose: entry.role,
            profile: entry.profile,
            maximumInputBits:
                8n *
                frames.reduce((maximum, value) =>
                    value > maximum ? value : maximum,
                ),
            messageBits: 8n * entry.messageBytes,
        };
    });
    return {
        rows,
        // W_F counts bits, permitting the deliberately loose union over all
        // tag-width substrings. It does not bound arbitrary auxiliary inputs.
        maximumInputBits: rows.reduce(
            (maximum, row) =>
                row.maximumInputBits > maximum ? row.maximumInputBits : maximum,
            0n,
        ),
        maximumMessageBits: rows.reduce(
            (maximum, row) =>
                row.messageBits > maximum ? row.messageBits : maximum,
            0n,
        ),
        minimumMessageBits: rows.reduce(
            (minimum, row) =>
                row.messageBits < minimum ? row.messageBits : minimum,
            rows[0].messageBits,
        ),
        // The all-zero initial state is the only fixed hash-label sentinel.
        // Missing and malformed preimages resolve to no context/oracle value.
        sentinelCount: 1n,
        maximumAcceptedExpansionQueries: BigInt(
            compileProofVerifierQueryCensus().maximumCoreQueries,
        ),
    };
};

// Reduced-label structural model, independent of cryptographic execution.
// Every database output is a maximumTags-digit word; a resolved context fixes
// its own (at least two) messageTags. Prefix equality includes its entire word,
// while unused maximum-word suffixes are deliberately irrelevant.
type Scope = { role: string };
export type ProofGraphInput = Scope &
    (
        | {
              kind: 'context';
              instance: string;
              canonical: boolean;
              messageTags?: number;
              arithmeticKey?: string;
          }
        | {
              kind: 'verifier';
              context: number;
              state: readonly number[];
              round: number;
          }
        | { kind: 'message'; context: number; round: number; tree: number }
        | { kind: 'chain'; context: number; message: number; root: number }
        | {
              kind: 'node';
              stage: number;
              level: number;
              left: number;
              right: number;
          }
        | {
              kind: 'leaf';
              stage: number;
              index: number;
              value: number;
              canonical: boolean;
          }
    );
export type ProofGraphEntry = {
    input: ProofGraphInput;
    output: number;
};
export type ProofGraphPrefix = {
    instance: string;
    messages: number[];
    oracles: (number | null)[][];
};

export const proofGraphPrefix = (
    word: number,
    alphabet: number,
    maximumTags = 2,
    prefixTags = 1,
) => Math.floor(word / alphabet ** (maximumTags - prefixTags));

export const proofGraphHasCollision = (
    database: readonly ProofGraphEntry[],
    alphabet: number,
    maximumTags = 2,
) => {
    const seen = new Set<string>();
    const inputs = new Map<string, number>();
    for (const entry of database) {
        const input = JSON.stringify(
            entry.input,
            Object.keys(entry.input).sort(),
        );
        const previous = inputs.get(input);
        if (previous !== undefined) {
            if (previous !== entry.output)
                throw new RangeError(
                    'A database input has two different output words.',
                );
            continue;
        }
        inputs.set(input, entry.output);
        const key = `${entry.input.role}:${proofGraphPrefix(entry.output, alphabet, maximumTags)}`;
        if (seen.has(key)) return true;
        seen.add(key);
    }
    return false;
};

export const extractProofGraphPrefix = (
    database: readonly ProofGraphEntry[],
    query: ProofGraphInput,
    alphabet: number,
    maximumTags = 2,
): ProofGraphPrefix | undefined => {
    if (
        query.kind !== 'verifier' ||
        query.round < 1 ||
        query.round > 3 ||
        proofGraphHasCollision(database, alphabet, maximumTags)
    )
        return undefined;
    const find = (tag: number) =>
        database.find(
            (entry) =>
                entry.input.role === query.role &&
                proofGraphPrefix(entry.output, alphabet, maximumTags) === tag,
        );
    const context = find(query.context)?.input;
    if (context?.kind !== 'context' || !context.canonical) return undefined;
    const messageTags = context.messageTags ?? 2;
    if (
        !Number.isInteger(messageTags) ||
        messageTags < 2 ||
        messageTags > maximumTags ||
        query.state.length !== messageTags
    )
        return undefined;
    const encode = (digits: readonly number[]) =>
        digits.reduce((word, digit) => word * alphabet + digit, 0);
    const oracle = (root: number, stage: number): (number | null)[] => {
        const node = find(root)?.input;
        if (node?.kind !== 'node' || node.stage !== stage || node.level !== 1)
            return [null, null];
        return [node.left, node.right].map((tag, index) => {
            const leaf = find(tag)?.input;
            return leaf?.kind === 'leaf' &&
                leaf.stage === stage &&
                leaf.index === index &&
                leaf.canonical
                ? leaf.value
                : null;
        });
    };
    const messages: number[] = [],
        oracles: (number | null)[][] = [];
    let state = query.state;
    for (let round = query.round - 1; round >= 1; round--) {
        const chainEntry = find(state[1]);
        const chain = chainEntry?.input;
        if (
            chain?.kind !== 'chain' ||
            chain.context !== query.context ||
            chain.root !== state[0] ||
            proofGraphPrefix(
                chainEntry!.output,
                alphabet,
                maximumTags,
                messageTags - 1,
            ) !== encode(state.slice(1))
        )
            return undefined;
        const previous = find(
            proofGraphPrefix(chain.message, alphabet, messageTags),
        );
        if (
            previous === undefined ||
            proofGraphPrefix(
                previous.output,
                alphabet,
                maximumTags,
                messageTags,
            ) !== chain.message ||
            previous.input.kind !== 'verifier' ||
            previous.input.context !== query.context ||
            previous.input.round !== round ||
            previous.input.state.length !== messageTags
        )
            return undefined;
        const response = find(state[0])?.input;
        if (
            response?.kind !== 'message' ||
            response.context !== query.context ||
            response.round !== round
        )
            return undefined;
        messages.unshift(chain.message);
        oracles.unshift(oracle(response.tree, round - 1));
        state = previous.input.state;
    }
    if (state.some((tag) => tag !== 0)) return undefined;
    return { instance: context.instance, messages, oracles };
};

export const proofGraphReferences = (
    database: readonly ProofGraphEntry[],
    additional: ProofGraphInput,
    alphabet: number,
    maximumTags = 2,
) => {
    const references = new Set<number>([0]);
    for (const input of [...database.map((entry) => entry.input), additional]) {
        switch (input.kind) {
            case 'verifier':
                references.add(input.context);
                input.state.forEach((tag) => references.add(tag));
                break;
            case 'message':
                references.add(input.context);
                references.add(input.tree);
                break;
            case 'chain':
                references.add(input.context);
                // The context can arrive later. Include every possible
                // embedded-word digit before its relation width is known.
                for (
                    let remaining = input.message;
                    remaining > 0;
                    remaining = Math.floor(remaining / alphabet)
                )
                    references.add(remaining % alphabet);
                references.add(input.root);
                break;
            case 'node':
                references.add(input.left);
                references.add(input.right);
                break;
            case 'context':
            case 'leaf':
                break;
        }
    }
    for (const entry of database)
        references.add(proofGraphPrefix(entry.output, alphabet, maximumTags));
    return references;
};
