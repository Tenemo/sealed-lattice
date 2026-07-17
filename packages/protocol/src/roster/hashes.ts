import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { isProtocolHash, type ProtocolHash } from '@sealed-lattice/types';

export type CollectiveBgvSetupRosterEntryInput = Readonly<{
    readonly rosterPosition: number;
    readonly trusteeIdentity: string;
    readonly signingPublicKeyHash: ProtocolHash;
}>;

export const deriveCollectiveBgvSetupRosterHash = (
    entries: readonly CollectiveBgvSetupRosterEntryInput[],
): ProtocolHash => {
    if (!Array.isArray(entries)) {
        throw new TypeError(
            'Collective BGV setup roster entries must be an array.',
        );
    }

    const inputEntries: readonly CollectiveBgvSetupRosterEntryInput[] = entries;
    const rosterEntries = inputEntries
        .map((entry) => {
            if (typeof entry !== 'object' || entry === null) {
                throw new TypeError(
                    'Collective BGV setup roster entry must be an object.',
                );
            }
            if (
                !Number.isSafeInteger(entry.rosterPosition) ||
                entry.rosterPosition < 0
            ) {
                throw new TypeError(
                    'rosterPosition must be a non-negative safe integer.',
                );
            }
            if (
                typeof entry.trusteeIdentity !== 'string' ||
                entry.trusteeIdentity.length === 0
            ) {
                throw new TypeError('trusteeIdentity must be non-empty.');
            }
            if (!isProtocolHash(entry.signingPublicKeyHash)) {
                throw new TypeError(
                    'signingPublicKeyHash must be a protocol hash.',
                );
            }

            return {
                objectType: 'CollectiveBgvSetupRosterEntry',
                rosterPosition: entry.rosterPosition,
                trusteeIdentity: entry.trusteeIdentity,
                signingPublicKeyHash: entry.signingPublicKeyHash,
            };
        })
        .sort((left, right) => left.rosterPosition - right.rosterPosition);
    for (
        let entryIndex = 1;
        entryIndex < rosterEntries.length;
        entryIndex += 1
    ) {
        if (
            rosterEntries[entryIndex]?.rosterPosition ===
            rosterEntries[entryIndex - 1]?.rosterPosition
        ) {
            throw new TypeError(
                'Collective BGV setup roster entries must have distinct roster positions.',
            );
        }
    }

    return deriveCanonicalObjectHash({
        objectType: 'CollectiveBgvSetupRoster',
        rosterEntries,
    });
};
