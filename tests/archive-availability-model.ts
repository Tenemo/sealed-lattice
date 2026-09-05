import { createHash } from 'node:crypto';

// Content custody only. The root must separately be authorized by the protocol;
// storage receipts are never signatures over the voting decision.
export type ArchiveStore = ReadonlyMap<string, Uint8Array>;

const hash = (bytes: Uint8Array): string =>
    createHash('sha3-512').update(bytes).digest('hex');

export const createArchiveRecord = (
    purpose: string,
    dependencies: readonly string[],
    payload: string,
) => {
    const bytes = Buffer.from(JSON.stringify([purpose, dependencies, payload]));
    return { identity: hash(bytes), bytes: Uint8Array.from(bytes) };
};

export const readArchiveClosure = (
    root: string,
    stores: readonly ArchiveStore[],
): ReadonlyMap<string, Uint8Array> | undefined => {
    const records = new Map<string, Uint8Array>();
    const pending = [root];
    for (let cursor = 0; cursor < pending.length; cursor++) {
        const identity = pending[cursor];
        if (records.has(identity)) continue;
        // A bad replica cannot hide another replica's correct copy.
        const bytes = stores
            .map((store) => store.get(identity))
            .find(
                (candidate) =>
                    candidate !== undefined && hash(candidate) === identity,
            );
        if (bytes === undefined) return;
        const parsed: unknown = JSON.parse(Buffer.from(bytes).toString('utf8'));
        if (
            !Array.isArray(parsed) ||
            parsed.length !== 3 ||
            typeof parsed[0] !== 'string' ||
            !Array.isArray(parsed[1]) ||
            !parsed[1].every(
                (dependency: unknown) =>
                    typeof dependency === 'string' &&
                    /^[0-9a-f]{128}$/u.test(dependency),
            ) ||
            typeof parsed[2] !== 'string' ||
            !Buffer.from(JSON.stringify(parsed)).equals(bytes)
        )
            return;
        records.set(identity, Uint8Array.from(bytes));
        pending.push(...(parsed[1] as string[]));
    }
    return records;
};

export const hasArchiveWriteQuorum = (
    replicaCount: number,
    unavailableReplicaBound: number,
    authenticatedAcknowledgements: readonly number[],
): boolean => {
    if (
        !Number.isInteger(replicaCount) ||
        !Number.isInteger(unavailableReplicaBound) ||
        unavailableReplicaBound < 0 ||
        replicaCount < 2 * unavailableReplicaBound + 1
    )
        throw new RangeError('Invalid archive availability profile.');
    const distinct = new Set(authenticatedAcknowledgements);
    return (
        distinct.size === authenticatedAcknowledgements.length &&
        [...distinct].every(
            (replica) =>
                Number.isInteger(replica) &&
                replica >= 0 &&
                replica < replicaCount,
        ) &&
        distinct.size > unavailableReplicaBound
    );
};

export const archiveHolderRequirements = (
    participantCount: number,
    corruptionBound: number,
    disappearanceBound: number,
    fragmentThreshold: number,
) => {
    for (const value of [
        participantCount,
        corruptionBound,
        disappearanceBound,
        fragmentThreshold,
    ])
        if (!Number.isInteger(value) || value < 0)
            throw new RangeError('Invalid archive holder count.');
    if (fragmentThreshold === 0 || participantCount === 0)
        throw new RangeError(
            'Archive recovery requires a nonempty holder set.',
        );
    const requiredHolders =
        corruptionBound + disappearanceBound + fragmentThreshold;
    return {
        requiredHolders,
        possible: requiredHolders <= participantCount,
    };
};
