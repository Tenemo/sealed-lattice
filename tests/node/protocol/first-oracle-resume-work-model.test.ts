import assert from 'node:assert/strict';

import { describe, expect, it } from 'vitest';

import {
    compileClassicalReaderOracleBudget,
    shakePermutationGateCharge,
} from '#tests/oracle-budget-model.js';
import {
    firstOracleResumeHashWork,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

// Independent byte traversal of the actual first-leaf framing, every base
// column and final extension column. No closed permutation formula is used.
const checkEveryCut = (firstWidth: bigint, roleBytes: bigint) => {
    const prefix = [
        64,
        4 + Buffer.byteLength('bounded-proof/leaf'),
        4 + Number(roleBytes),
        4 + 4,
        4 + 4,
        4 + 128,
        4,
    ].reduce((sum, bytes) => sum + bytes, 0);
    const columns = (Number(firstWidth) - 48) / 16;
    let cursor = 0;
    let permutations = 0;
    const absorb = (bytes: number) => {
        for (let byte = 0; byte < bytes; byte++) {
            cursor++;
            if (cursor === 136) {
                cursor = 0;
                permutations++;
            }
        }
    };
    absorb(prefix);
    const cuts = [{ cursor, permutations }];
    for (let column = 0; column < columns; column++) {
        absorb(16);
        cuts.push({ cursor, permutations });
    }
    absorb(48);
    // ProtocolHash returns 64 bytes, so only the padded final block remains.
    permutations++;
    const latest = firstOracleResumeHashWork(
        firstWidth,
        roleBytes,
        BigInt(columns),
    );
    for (const [column, cut] of cuts.entries()) {
        const work = firstOracleResumeHashWork(
            firstWidth,
            roleBytes,
            BigInt(column),
        );
        const remaining = BigInt(permutations - cut.permutations);
        assert.equal(work.baseColumns, BigInt(columns));
        assert.equal(work.completeInputPermutations, BigInt(permutations));
        assert.equal(work.resumedPermutations, remaining);
        assert.equal(work.retainedPrefixBytes, BigInt(prefix + 16 * column));
        assert.equal(work.retainedPrefixBytes % 136n, BigInt(cut.cursor));
        assert.equal(
            work.remainingInputBytes,
            firstWidth - 16n * BigInt(column),
        );
        assert.ok(
            work.completeInputPermutations <=
                latest.completeInputFactor * remaining,
        );
    }
    return latest;
};

describe('first-oracle hash resume work', () => {
    it('bounds every permitted checkpoint column at every supported profile', () => {
        for (let participants = 3; participants <= 20; participants++)
            for (let options = 2; options <= 20; options++) {
                const profile = deriveSupportedProfile(participants, options);
                const setup = proofHashProfiles(profile).find(
                    (value) => value.role === 'setup',
                )!;
                expect(
                    checkEveryCut(setup.firstWidth, setup.roleBytes)
                        .remainingInputBytes,
                ).toBe(48n);
            }
    });

    it('covers role-length boundaries and repeated completed resumes without recharging old absorption', () => {
        const setup = proofHashProfiles(deriveSupportedProfile(20, 20)).find(
            (value) => value.role === 'setup',
        )!;
        for (const role of [1n, 135n, 136n, 137n, 410n, 1024n]) {
            const latest = checkEveryCut(setup.firstWidth, role);
            expect(latest.completeInputFactor).toBeGreaterThan(5n);
            for (const resumes of [1n, 2n, 17n]) {
                const charged = resumes * latest.resumedPermutations;
                const expanded = resumes * latest.completeInputPermutations;
                const budget = compileClassicalReaderOracleBudget(
                    charged * shakePermutationGateCharge,
                    512n,
                    0n,
                    0n,
                    latest.completeInputFactor,
                );
                expect(expanded).toBeLessThanOrEqual(
                    budget.maximumLengthPermutations,
                );
                expect(expanded).toBeGreaterThan(5n * charged);
            }
        }
    });

    it('rejects checkpoint cuts and widths the original first oracle cannot have', () => {
        for (const [width, role, column] of [
            [48n, 410n, 0n],
            [65n, 410n, 0n],
            [64n, 0n, 0n],
            [64n, 1025n, 0n],
            [64n, 410n, -1n],
            [64n, 410n, 2n],
        ])
            expect(() =>
                firstOracleResumeHashWork(width, role, column),
            ).toThrow();
        expect(() =>
            compileClassicalReaderOracleBudget(0n, 512n, 0n, 0n, 4n),
        ).toThrow();
    });
});
