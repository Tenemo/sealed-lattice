import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';

// Independent raw-input recognizer for the registration proof graph. It does
// not verify a proof, authenticate an identity or observe native hash calls.
// Source grammar: word-verifier/engine.rs and registration-credentials/lib.rs.
const registration = compileRegistrationKeyRelationCensus();
const agreement = compileCommonAgreementDegreeCensus();
const tagBytes = 64;
const saltBytes = 128;
const elementBytes = 48;
const messageBytes = 262_144;
const rolePrefix = Buffer.from('registered-recipient-key/1');
const fixedPrefix = Buffer.alloc(64);
fixedPrefix.write('sealed-lattice/fixed-hash/v1');
const relationTag = Buffer.from('recipient-registration-key/1');
const parameterBytes =
    4 * (15 + registration.originalOracles + registration.virtualOracles) +
    8 * registration.lookups;
const stageWidths = [
    Number(registration.firstLeafBytes),
    Number(registration.secondLeafBytes),
    elementBytes,
];

export type RegistrationHashInput = {
    family:
        | 'leaf'
        | 'node'
        | 'message-root'
        | 'statement'
        | 'verifier-message'
        | 'chain-state';
    role: string;
    owner: string;
    fields: readonly Buffer[];
    references: readonly Buffer[];
};

export const parseRegistrationHashInput = (
    input: Uint8Array,
): RegistrationHashInput | undefined => {
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
    if (
        !domain ||
        !role ||
        role.length !== rolePrefix.length + 4 * tagBytes ||
        !role.subarray(0, rolePrefix.length).equals(rolePrefix)
    )
        return undefined;
    const owner = role.subarray(rolePrefix.length + 2 * tagBytes);
    if (
        [...owner].some(
            (value) => !'0123456789abcdef'.includes(String.fromCharCode(value)),
        )
    )
        return undefined;
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
        family: RegistrationHashInput['family'],
        references: readonly Buffer[] = [],
    ): RegistrationHashInput => ({
        family,
        role: role.toString('hex'),
        owner: owner.toString('ascii'),
        fields,
        references,
    });
    // Full equality avoids ASCII decoding aliases for high-bit domain bytes.
    const named = (name: string) =>
        domain.equals(Buffer.from(`bounded-proof/${name}`));
    if (
        fixed &&
        named('leaf') &&
        stageWidths.some((width) => shape(4, 4, saltBytes, width))
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
        shape(
            relationTag.length,
            16,
            16,
            16,
            parameterBytes,
            16,
            Number(registration.statementBytes),
        ) &&
        fields[0].equals(relationTag)
    )
        return result('statement');
    if (!fixed && named('verifier-message') && shape(tagBytes, messageBytes, 4))
        return result('verifier-message', [
            fields[0],
            fields[1].subarray(0, tagBytes),
            fields[1].subarray(tagBytes, 2 * tagBytes),
        ]);
    if (
        !fixed &&
        named('chain-state') &&
        shape(tagBytes, messageBytes, tagBytes)
    )
        return result('chain-state', [
            fields[0],
            fields[1].subarray(0, tagBytes),
            fields[2],
        ]);
    // All other raw inputs use the complementary function, regardless of API.
    return undefined;
};

export const isRegistrationChallengeInput = (
    input: Uint8Array,
    honestOwners: ReadonlySet<string>,
) => {
    const parsed = parseRegistrationHashInput(input);
    return parsed !== undefined && !honestOwners.has(parsed.owner);
};

// Semantic layouts are separate from raw namespace membership. These checks
// cover stage/round shape only, not field reduction or statement correctness.
export const hasRegistrationHashLayout = (input: RegistrationHashInput) => {
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
                fields[3].length === stageWidths[Math.min(stage, 2)]
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

// Reduced-label structural model of the backward graph. A word comprises two
// tags, matching the minimum lambda=2*kappa case. It supplies no IOP error or
// cryptographic assumption and is not the native parser above.
type Scope = { role: string };
export type RegistrationGraphInput = Scope &
    (
        | { kind: 'context'; instance: string; canonical: boolean }
        | {
              kind: 'verifier';
              context: number;
              state: readonly [number, number];
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
export type RegistrationGraphEntry = {
    input: RegistrationGraphInput;
    output: number;
};
export type RegistrationGraphPrefix = {
    instance: string;
    messages: number[];
    oracles: (number | null)[][];
};

export const registrationGraphPrefix = (word: number, alphabet: number) =>
    Math.floor(word / alphabet);

export const registrationGraphHasCollision = (
    database: readonly RegistrationGraphEntry[],
    alphabet: number,
) => {
    const seen = new Set<string>();
    for (const entry of database) {
        const key = `${entry.input.role}:${registrationGraphPrefix(entry.output, alphabet)}`;
        if (seen.has(key)) return true;
        seen.add(key);
    }
    return false;
};

export const extractRegistrationGraphPrefix = (
    database: readonly RegistrationGraphEntry[],
    query: RegistrationGraphInput,
    alphabet: number,
): RegistrationGraphPrefix | undefined => {
    if (
        query.kind !== 'verifier' ||
        query.round < 1 ||
        query.round > 3 ||
        registrationGraphHasCollision(database, alphabet)
    )
        return undefined;
    const find = (tag: number) =>
        database.find(
            (entry) =>
                entry.input.role === query.role &&
                registrationGraphPrefix(entry.output, alphabet) === tag,
        );
    const context = find(query.context)?.input;
    if (context?.kind !== 'context' || !context.canonical) return undefined;
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
        const chain = find(state[1])?.input;
        if (
            chain?.kind !== 'chain' ||
            chain.context !== query.context ||
            chain.root !== state[0]
        )
            return undefined;
        const previous = find(registrationGraphPrefix(chain.message, alphabet));
        if (
            previous?.output !== chain.message ||
            previous.input.kind !== 'verifier' ||
            previous.input.context !== query.context ||
            previous.input.round !== round
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
    if (state[0] !== 0 || state[1] !== 0) return undefined;
    return { instance: context.instance, messages, oracles };
};

export const registrationGraphReferences = (
    database: readonly RegistrationGraphEntry[],
    additional: RegistrationGraphInput,
    alphabet: number,
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
                references.add(
                    registrationGraphPrefix(input.message, alphabet),
                );
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
        references.add(registrationGraphPrefix(entry.output, alphabet));
    return references;
};
