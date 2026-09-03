import type { IndependentPaddedTallyModel } from './padded-tally-transcript-model.js';

const participantCount = 10;
const identityByteLength = 64;
const domainByteLength = 32;
const localRecordDomain = 'sealed-lattice/local-record/v3';
const noPeerPosition = 0xffff;
const privatePreparationOperationOrdinal = 1n;
const preparationAttempt = 7n;

export const localRecordContextByteLength =
    domainByteLength + 6 * identityByteLength + 2 + 2 + 8 + 2 + 8;

export const localRecordObjectKinds = {
    action: 1,
    preparation: 2,
    privatePreparationSlot: 3,
    source: 4,
    finality: 5,
    noResult: 8,
    tallyGeneration: 10,
    tallyEvaluation: 11,
} as const;

export type IndependentLocalRecordContext = Readonly<{
    runtimeIdentity: Uint8Array;
    candidateBuildIdentity: Uint8Array;
    actionProposalIdentity: Uint8Array;
    actionDefinitionIdentity: Uint8Array;
    rosterIdentity: Uint8Array;
    predecessorIdentity: Uint8Array;
    participantPosition: number;
    objectKind: number;
    generation: bigint;
    peerPosition: number;
    operationOrdinal: bigint;
}>;

export type IndependentLocalRecordSeal = Readonly<{
    context: IndependentLocalRecordContext;
    contextBytes: Uint8Array;
    inventoryGeneration: bigint;
}>;

export type IndependentLocalRecordCensus = Readonly<{
    storageVisibleSealCount: number;
    distinctDerivationInputCount: number;
    inventoryCommitCount: number;
    retainedRecordCount: number;
    maximumSealsPerExactContext: number;
    sameContextSealPairCount: bigint;
    objectKindCounts: Readonly<Record<number, number>>;
    retainedObjectKindCounts: Readonly<Record<number, number>>;
}>;

const identities = {
    runtimeIdentity: new Uint8Array(identityByteLength).fill(0x11),
    candidateBuildIdentity: new Uint8Array(identityByteLength).fill(0x22),
    actionProposalIdentity: new Uint8Array(identityByteLength).fill(0x33),
    actionDefinitionIdentity: new Uint8Array(identityByteLength).fill(0x34),
    rosterIdentity: new Uint8Array(identityByteLength).fill(0x55),
    predecessorIdentity: new Uint8Array(identityByteLength).fill(0x44),
} as const;

const requireIdentity = (value: Uint8Array, name: string): void => {
    if (value.byteLength !== identityByteLength) {
        throw new RangeError(`${name} must contain exactly 64 bytes.`);
    }
};

const requireUnsigned16 = (value: number, name: string): void => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new RangeError(`${name} must be an unsigned 16-bit integer.`);
    }
};

const requireUnsigned64 = (value: bigint, name: string): void => {
    if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
        throw new RangeError(`${name} must be an unsigned 64-bit integer.`);
    }
};

export const encodeIndependentLocalRecordContext = (
    context: IndependentLocalRecordContext,
): Uint8Array => {
    for (const [name, value] of [
        ['runtimeIdentity', context.runtimeIdentity],
        ['candidateBuildIdentity', context.candidateBuildIdentity],
        ['actionProposalIdentity', context.actionProposalIdentity],
        ['actionDefinitionIdentity', context.actionDefinitionIdentity],
        ['rosterIdentity', context.rosterIdentity],
        ['predecessorIdentity', context.predecessorIdentity],
    ] as const) {
        requireIdentity(value, name);
    }
    requireUnsigned16(context.participantPosition, 'participantPosition');
    requireUnsigned16(context.objectKind, 'objectKind');
    requireUnsigned64(context.generation, 'generation');
    requireUnsigned16(context.peerPosition, 'peerPosition');
    requireUnsigned64(context.operationOrdinal, 'operationOrdinal');

    const bytes = new Uint8Array(localRecordContextByteLength);
    const domain = new TextEncoder().encode(localRecordDomain);
    if (domain.byteLength > domainByteLength) {
        throw new Error('The independent local-record domain is too long.');
    }
    bytes.set(domain, 0);
    let offset = domainByteLength;
    for (const identity of [
        context.runtimeIdentity,
        context.candidateBuildIdentity,
        context.actionProposalIdentity,
        context.actionDefinitionIdentity,
        context.rosterIdentity,
        context.predecessorIdentity,
    ]) {
        bytes.set(identity, offset);
        offset += identityByteLength;
    }
    const view = new DataView(bytes.buffer);
    view.setUint16(offset, context.participantPosition, true);
    offset += 2;
    view.setUint16(offset, context.objectKind, true);
    offset += 2;
    view.setBigUint64(offset, context.generation, true);
    offset += 8;
    view.setUint16(offset, context.peerPosition, true);
    offset += 2;
    view.setBigUint64(offset, context.operationOrdinal, true);
    offset += 8;
    if (offset !== bytes.byteLength) {
        throw new Error('The independent local-record context is incomplete.');
    }
    return bytes;
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
    left.byteLength === right.byteLength &&
    left.every((value, index) => value === right[index]);

export const parseIndependentLocalRecordContext = (
    bytes: Uint8Array,
): IndependentLocalRecordContext => {
    if (bytes.byteLength !== localRecordContextByteLength) {
        throw new RangeError('The local-record context has the wrong length.');
    }
    const expectedDomain = new Uint8Array(domainByteLength);
    expectedDomain.set(new TextEncoder().encode(localRecordDomain));
    if (!bytesEqual(bytes.subarray(0, domainByteLength), expectedDomain)) {
        throw new Error('The local-record context has the wrong domain.');
    }
    let offset = domainByteLength;
    const readIdentity = (): Uint8Array => {
        const identity = Uint8Array.from(
            bytes.subarray(offset, offset + identityByteLength),
        );
        offset += identityByteLength;
        return identity;
    };
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const runtimeIdentity = readIdentity();
    const candidateBuildIdentity = readIdentity();
    const actionProposalIdentity = readIdentity();
    const actionDefinitionIdentity = readIdentity();
    const rosterIdentity = readIdentity();
    const predecessorIdentity = readIdentity();
    const participantPosition = view.getUint16(offset, true);
    offset += 2;
    const objectKind = view.getUint16(offset, true);
    offset += 2;
    const generation = view.getBigUint64(offset, true);
    offset += 8;
    const peerPosition = view.getUint16(offset, true);
    offset += 2;
    const operationOrdinal = view.getBigUint64(offset, true);
    offset += 8;
    if (offset !== bytes.byteLength) {
        throw new Error('The local-record context has trailing bytes.');
    }
    return {
        runtimeIdentity,
        candidateBuildIdentity,
        actionProposalIdentity,
        actionDefinitionIdentity,
        rosterIdentity,
        predecessorIdentity,
        participantPosition,
        objectKind,
        generation,
        peerPosition,
        operationOrdinal,
    };
};

export const localRecordContextKey = (bytes: Uint8Array): string =>
    Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');

const appendSeal = (
    seals: IndependentLocalRecordSeal[],
    participantPosition: number,
    objectKind: number,
    generation: bigint,
    peerPosition = noPeerPosition,
    operationOrdinal = 0n,
): void => {
    const context = {
        ...identities,
        participantPosition,
        objectKind,
        generation,
        peerPosition,
        operationOrdinal,
    };
    seals.push({
        context,
        contextBytes: encodeIndependentLocalRecordContext(context),
        inventoryGeneration: 0n,
    });
};

const appendFoundationCeremonySeals = (
    seals: IndependentLocalRecordSeal[],
    participantPosition: number,
): bigint => {
    let actionGeneration = 1n;
    appendSeal(
        seals,
        participantPosition,
        localRecordObjectKinds.action,
        actionGeneration,
    );

    appendSeal(
        seals,
        participantPosition,
        localRecordObjectKinds.preparation,
        1n,
        noPeerPosition,
        preparationAttempt,
    );
    actionGeneration += 1n;
    appendSeal(
        seals,
        participantPosition,
        localRecordObjectKinds.action,
        actionGeneration,
    );
    appendSeal(
        seals,
        participantPosition,
        localRecordObjectKinds.preparation,
        2n,
        noPeerPosition,
        preparationAttempt,
    );

    for (
        let senderPosition = 0;
        senderPosition < participantCount;
        senderPosition += 1
    ) {
        if (senderPosition === participantPosition) continue;
        appendSeal(
            seals,
            participantPosition,
            localRecordObjectKinds.privatePreparationSlot,
            1n,
            senderPosition,
            privatePreparationOperationOrdinal,
        );
        appendSeal(
            seals,
            participantPosition,
            localRecordObjectKinds.privatePreparationSlot,
            2n,
            senderPosition,
            privatePreparationOperationOrdinal,
        );
    }

    appendSeal(seals, participantPosition, localRecordObjectKinds.source, 1n);
    actionGeneration += 1n;
    appendSeal(
        seals,
        participantPosition,
        localRecordObjectKinds.action,
        actionGeneration,
    );
    appendSeal(seals, participantPosition, localRecordObjectKinds.source, 2n);

    appendSeal(seals, participantPosition, localRecordObjectKinds.finality, 1n);
    actionGeneration += 1n;
    appendSeal(
        seals,
        participantPosition,
        localRecordObjectKinds.action,
        actionGeneration,
    );
    appendSeal(seals, participantPosition, localRecordObjectKinds.finality, 2n);
    return actionGeneration;
};

const foundationTransitionRecordCounts = [
    1,
    2,
    1,
    ...Array.from({ length: 2 * (participantCount - 1) }, () => 1),
    2,
    1,
    2,
    1,
] as const;

const resealCompleteInventory = (
    logicalSeals: readonly IndependentLocalRecordSeal[],
    transitionRecordCounts: readonly number[],
): IndependentLocalRecordSeal[] => {
    const retained = new Map<string, IndependentLocalRecordSeal>();
    const physicalSeals: IndependentLocalRecordSeal[] = [];
    let logicalOffset = 0;
    let inventoryGeneration = 0n;
    for (const transitionRecordCount of transitionRecordCounts) {
        if (
            !Number.isSafeInteger(transitionRecordCount) ||
            transitionRecordCount < 1
        ) {
            throw new Error('The local inventory transition is invalid.');
        }
        const transitionEnd = logicalOffset + transitionRecordCount;
        const replacements = logicalSeals.slice(logicalOffset, transitionEnd);
        if (replacements.length !== transitionRecordCount) {
            throw new Error('The local inventory transition is truncated.');
        }
        for (const replacement of replacements) {
            retained.set(stableRecordKey(replacement), replacement);
        }
        inventoryGeneration += 1n;
        for (const retainedSeal of Array.from(retained.values()).sort(
            (left, right) =>
                stableRecordKey(left).localeCompare(stableRecordKey(right)),
        )) {
            physicalSeals.push({
                ...retainedSeal,
                inventoryGeneration,
            });
        }
        logicalOffset = transitionEnd;
    }
    if (logicalOffset !== logicalSeals.length) {
        throw new Error(
            'The local inventory transition map has trailing seals.',
        );
    }
    return physicalSeals;
};

export const enumerateFullTallyLocalRecordSeals = (
    tally: IndependentPaddedTallyModel,
): readonly IndependentLocalRecordSeal[] => {
    const seals: IndependentLocalRecordSeal[] = [];
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        const participantSeals: IndependentLocalRecordSeal[] = [];
        let actionGeneration = appendFoundationCeremonySeals(
            participantSeals,
            participantPosition,
        );
        appendSeal(
            participantSeals,
            participantPosition,
            localRecordObjectKinds.tallyGeneration,
            1n,
        );
        actionGeneration += 1n;
        appendSeal(
            participantSeals,
            participantPosition,
            localRecordObjectKinds.action,
            actionGeneration,
        );
        for (
            let chunkOrdinal = 0;
            chunkOrdinal < tally.descriptors.length;
            chunkOrdinal += 1
        ) {
            appendSeal(
                participantSeals,
                participantPosition,
                localRecordObjectKinds.tallyGeneration,
                BigInt(chunkOrdinal) + 2n,
            );
            actionGeneration += 1n;
            appendSeal(
                participantSeals,
                participantPosition,
                localRecordObjectKinds.action,
                actionGeneration,
            );
        }

        appendSeal(
            participantSeals,
            participantPosition,
            localRecordObjectKinds.tallyEvaluation,
            1n,
        );
        actionGeneration += 1n;
        appendSeal(
            participantSeals,
            participantPosition,
            localRecordObjectKinds.action,
            actionGeneration,
        );
        for (
            let chunkOrdinal = 0;
            chunkOrdinal < tally.descriptors.length;
            chunkOrdinal += 1
        ) {
            appendSeal(
                participantSeals,
                participantPosition,
                localRecordObjectKinds.tallyEvaluation,
                BigInt(chunkOrdinal) + 2n,
            );
            actionGeneration += 1n;
            appendSeal(
                participantSeals,
                participantPosition,
                localRecordObjectKinds.action,
                actionGeneration,
            );
        }
        const pairedTransitionRecordCounts = Array.from(
            { length: 2 + 2 * tally.descriptors.length },
            () => 2,
        );
        seals.push(
            ...resealCompleteInventory(participantSeals, [
                ...foundationTransitionRecordCounts,
                ...pairedTransitionRecordCounts,
            ]),
        );
    }
    return seals;
};

export const enumerateAllAbstainLocalRecordSeals =
    (): readonly IndependentLocalRecordSeal[] => {
        const seals: IndependentLocalRecordSeal[] = [];
        for (
            let participantPosition = 0;
            participantPosition < participantCount;
            participantPosition += 1
        ) {
            const participantSeals: IndependentLocalRecordSeal[] = [];
            let actionGeneration = appendFoundationCeremonySeals(
                participantSeals,
                participantPosition,
            );
            appendSeal(
                participantSeals,
                participantPosition,
                localRecordObjectKinds.finality,
                3n,
            );
            actionGeneration += 1n;
            appendSeal(
                participantSeals,
                participantPosition,
                localRecordObjectKinds.action,
                actionGeneration,
            );
            if (participantPosition === 0) {
                appendSeal(
                    participantSeals,
                    participantPosition,
                    localRecordObjectKinds.noResult,
                    1n,
                );
                appendSeal(
                    participantSeals,
                    participantPosition,
                    localRecordObjectKinds.action,
                    actionGeneration + 1n,
                );
            }
            seals.push(
                ...resealCompleteInventory(participantSeals, [
                    ...foundationTransitionRecordCounts,
                    2,
                    ...(participantPosition === 0 ? [2] : []),
                ]),
            );
        }
        return seals;
    };

const stableRecordKey = (seal: IndependentLocalRecordSeal): string => {
    const { context } = seal;
    return [
        context.participantPosition,
        context.objectKind,
        context.peerPosition,
        context.operationOrdinal,
    ].join(':');
};

const countsByObjectKind = (
    seals: readonly IndependentLocalRecordSeal[],
): Readonly<Record<number, number>> => {
    const counts: Record<number, number> = {};
    for (const { context } of seals) {
        counts[context.objectKind] = (counts[context.objectKind] ?? 0) + 1;
    }
    return counts;
};

export const compileIndependentLocalRecordCensus = (
    seals: readonly IndependentLocalRecordSeal[],
): IndependentLocalRecordCensus => {
    const exactContextCounts = new Map<string, number>();
    const inventoryCommitKeys = new Set<string>();
    const retained = new Map<string, IndependentLocalRecordSeal>();
    for (const seal of seals) {
        const contextKey = localRecordContextKey(seal.contextBytes);
        exactContextCounts.set(
            contextKey,
            (exactContextCounts.get(contextKey) ?? 0) + 1,
        );
        inventoryCommitKeys.add(
            `${String(seal.context.participantPosition)}:${String(
                seal.inventoryGeneration,
            )}`,
        );
        const stableKey = stableRecordKey(seal);
        const prior = retained.get(stableKey);
        if (
            prior === undefined ||
            prior.context.generation < seal.context.generation
        ) {
            retained.set(stableKey, seal);
        }
    }
    return {
        storageVisibleSealCount: seals.length,
        distinctDerivationInputCount: exactContextCounts.size,
        inventoryCommitCount: inventoryCommitKeys.size,
        retainedRecordCount: retained.size,
        maximumSealsPerExactContext: Math.max(
            0,
            ...exactContextCounts.values(),
        ),
        sameContextSealPairCount: Array.from(
            exactContextCounts.values(),
            (count) => (BigInt(count) * BigInt(count - 1)) / 2n,
        ).reduce((sum, count) => sum + count, 0n),
        objectKindCounts: countsByObjectKind(seals),
        retainedObjectKindCounts: countsByObjectKind(
            Array.from(retained.values()),
        ),
    };
};
