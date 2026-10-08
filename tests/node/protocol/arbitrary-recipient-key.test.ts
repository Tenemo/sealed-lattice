import { describe, expect, it } from 'vitest';

// Finite channel check after the separate honest-row and proof hybrids.
// This checks the joint sharing view and arbitrary-key postprocessing, not
// Ring-LWE hardness. Two corrupt positions require a degree-two polynomial.
const modulus = 5;
const residues = [0, 1, 2, 3, 4];
const reduce = (value: number) => ((value % modulus) + modulus) % modulus;
type Distribution = Map<string, number>;
const record = (distribution: Distribution, values: readonly number[]) => {
    const key = values.join(',');
    distribution.set(key, (distribution.get(key) ?? 0) + 1);
};
const sorted = (distribution: Distribution) =>
    [...distribution].sort(([left], [right]) => left.localeCompare(right));

const sharingViews = (secret: number, degree: 1 | 2) => {
    const distribution: Distribution = new Map();
    for (const linear of residues)
        for (const quadratic of degree === 2 ? residues : [0])
            record(distribution, [
                reduce(secret + linear + quadratic),
                reduce(secret + 2 * linear + 4 * quadratic),
            ]);
    return distribution;
};

// Independent coins for every addressed row; a key is any ring element.
// This deliberately gives zero and copied keys no special treatment.
const ciphertextRows = (key: number, share: number) => {
    const rows: number[][] = [];
    for (const ephemeral of [0, 1])
        for (const linearError of [0, 1])
            for (const constantError of [0, 1])
                rows.push([
                    reduce(3 * ephemeral + linearError),
                    reduce(key * ephemeral + constantError + share),
                ]);
    return rows;
};
const encryptedView = (
    shares: Distribution,
    firstKey: number,
    secondKey: number,
) => {
    const distribution: Distribution = new Map();
    for (const [encoded, count] of shares) {
        const [first, second] = encoded.split(',').map(Number);
        for (const left of ciphertextRows(firstKey, first))
            for (const right of ciphertextRows(secondKey, second)) {
                const key = [...left, ...right].join(',');
                distribution.set(key, (distribution.get(key) ?? 0) + count);
            }
    }
    return distribution;
};

describe('arbitrary canonical recipient-key channel', () => {
    it('preserves the complete two-position projection for every pair of keys', () => {
        const expectedShares = residues.flatMap((first) =>
            residues.map((second) => [`${first},${second}`, 1] as const),
        );
        for (const secret of residues)
            expect(sorted(sharingViews(secret, 2))).toEqual(expectedShares);
        // Exhaust all key pairs, including zero, equal, and keys chosen as
        // arbitrary functions of a previously fixed public history.
        for (const firstKey of residues)
            for (const secondKey of residues) {
                const reference = encryptedView(
                    sharingViews(0, 2),
                    firstKey,
                    secondKey,
                );
                // Each linear component has four possible values, each
                // constant component five. Both constant errors have two
                // preimages, giving four tapes for every joint ciphertext.
                expect(reference.size).toBe(4 * 4 * 5 * 5);
                expect(
                    [...reference.values()].every((count) => count === 4),
                ).toBe(true);
                for (const secret of residues.slice(1))
                    expect(
                        sorted(
                            encryptedView(
                                sharingViews(secret, 2),
                                firstKey,
                                secondKey,
                            ),
                        ),
                    ).toEqual(sorted(reference));
            }
    });

    it('rejects extending the argument beyond the allowed sharing threshold', () => {
        // Marginals are still uniform when only one mask remains, but the
        // joint view can distinguish secrets. Per-recipient checks alone
        // would miss this invalid threshold change.
        const views = [0, 1].map((secret) => sharingViews(secret, 1));
        const marginal = (view: Distribution, index: number) => {
            const distribution: Distribution = new Map();
            for (const [encoded, count] of view) {
                const key = encoded.split(',')[index];
                distribution.set(key, (distribution.get(key) ?? 0) + count);
            }
            return sorted(distribution);
        };
        for (const index of [0, 1])
            expect(marginal(views[0], index)).toEqual(
                marginal(views[1], index),
            );
        expect(sorted(encryptedView(views[0], 0, 0))).not.toEqual(
            sorted(encryptedView(views[1], 0, 0)),
        );
    });
});
