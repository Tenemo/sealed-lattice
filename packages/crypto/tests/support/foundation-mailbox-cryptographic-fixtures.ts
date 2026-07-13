import { kmac256 } from '@noble/hashes/sha3-addons.js';

const textEncoder = new TextEncoder();
const actionKeyHierarchyCustomization = textEncoder.encode(
    'sealed-lattice/private-randomness/action-key-hierarchy/v1',
);

export const deriveFoundationMailboxCommitmentPreimageFixture = (
    actionRandomnessRoot: Uint8Array,
    canonicalActionRandomnessDerivationInput: Uint8Array,
): Uint8Array => {
    if (
        actionRandomnessRoot.byteLength !== 64 ||
        canonicalActionRandomnessDerivationInput.byteLength !== 296
    ) {
        throw new Error(
            'The foundation mailbox fixture has malformed action-randomness input.',
        );
    }
    const keyMaterial = kmac256(
        actionRandomnessRoot,
        canonicalActionRandomnessDerivationInput,
        {
            dkLen: 192,
            personalization: actionKeyHierarchyCustomization,
        },
    );
    try {
        return keyMaterial.slice(0, 64);
    } finally {
        keyMaterial.fill(0);
    }
};
