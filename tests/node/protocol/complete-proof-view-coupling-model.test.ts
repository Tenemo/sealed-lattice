import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { completeProofViewCoupling } from '#tests/complete-proof-view-coupling-model.js';

const digest = (value: unknown) =>
    createHash('sha512').update(JSON.stringify(value)).digest('hex');
type View = ReturnType<typeof completeProofViewCoupling>['realView'];
const verifiesDisclosure = (view: View): boolean =>
    view.trees.every((tree, group) =>
        tree.openings.every((opening) => {
            const message =
                Number.parseInt(
                    digest([group, opening.index, opening.payload]).slice(0, 6),
                    16,
                ) % 97;
            let node = digest(['leaf-label', (message + opening.salt) % 97]);
            let index = opening.index;
            for (const sibling of opening.path) {
                node = digest([
                    'inner',
                    ...(index % 2 === 0 ? [node, sibling] : [sibling, node]),
                ]);
                index = Math.floor(index / 2);
            }
            return node === tree.root;
        }),
    );

describe('complete encoded proof view coupling', () => {
    it.each([1, 2, 3, 8, 17, 32])(
        'preserves all disclosures and reverses every mask for tape %i',
        (seed) => {
            for (const zeroMask of [false, true]) {
                const result = completeProofViewCoupling(seed, zeroMask);
                expect(result.realView).toEqual(result.simulatedView);
                expect(result.realCombinedPolynomial).toEqual(
                    result.simulatedCombinedPolynomial,
                );
                expect(result.realFolding).toEqual(result.simulatedFolding);
                expect(result.recoveredMasks).toEqual(result.originalMasks);
                expect(result.affineControlRejected).toBe(!zeroMask);
                expect(verifiesDisclosure(result.realView)).toBe(true);
                expect(verifiesDisclosure(result.simulatedView)).toBe(true);
            }
        },
    );

    it('authenticates the actual opened toy leaf and its complete path', () => {
        const { realView } = completeProofViewCoupling(5);
        const changedSalt = structuredClone(realView);
        const opening = changedSalt.trees[0].openings[0];
        opening.salt = (opening.salt + 1) % 97;
        expect(verifiesDisclosure(changedSalt)).toBe(false);
        const changedPath = structuredClone(realView);
        changedPath.trees[1].openings[0].path[0] = digest('another-node');
        expect(verifiesDisclosure(changedPath)).toBe(false);
    });
});
