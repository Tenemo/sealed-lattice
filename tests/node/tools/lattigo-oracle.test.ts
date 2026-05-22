import { describe, expect, it } from 'vitest';

import {
    loadPinnedReference,
    verifyPinnedReference,
} from '#tools/lattigo-oracle/verify-lattigo-oracle';

describe('Lattigo oracle boundary tooling', () => {
    it('pins the reference while keeping it outside runtime evidence', async () => {
        const pinnedReference = await loadPinnedReference();
        const verification = await verifyPinnedReference();

        expect(pinnedReference.pinnedCommit).toBe(
            '5dbffbdea05394de2ca3a432ed5318aa832e3f40',
        );
        expect(pinnedReference.runtimeUse).toBe('forbidden');
        expect(pinnedReference.protocolEvidenceUse).toBe('forbidden');
        expect(verification.commandDigest).toMatch(/^[a-f0-9]{64}$/u);
        expect(verification.dockerfileDigest).toMatch(/^[a-f0-9]{64}$/u);
    });
});
