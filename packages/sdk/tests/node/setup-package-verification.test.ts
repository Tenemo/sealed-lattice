import { describe, expect, it } from 'vitest';

import { verifySetupPackage } from '../../dist/index.js';

describe('setup package verification in Node', () => {
    it('refuses a passive setup package through the built public API', async () => {
        const verification = await verifySetupPackage({
            setupPackage: { objectType: 'BgvPassiveSetupPackage' },
            expectedManifestHash: '1'.repeat(128),
            expectedRosterHash: '2'.repeat(128),
        });

        expect(verification).toMatchObject({
            isValid: false,
            refusedObjects: [
                {
                    objectPath: 'setupPackage.objectType',
                    reasonCode: 'outsideCollectiveBgvSetupParameters',
                },
            ],
        });
    });
});
