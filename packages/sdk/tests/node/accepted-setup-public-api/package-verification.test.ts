import { describe, expect, it } from 'vitest';

import { publicSetupApi } from './support.js';

describe('accepted setup public package API in Node', () => {
    it('exposes setup package verification without accepting passive setup packages', async () => {
        const verification = await publicSetupApi.verifySetupPackage({
            setupPackage: {
                objectType: 'BgvPassiveSetupPackage',
            },
            expectedManifestHash: '1'.repeat(128),
            expectedRosterHash: '2'.repeat(128),
        });

        expect(verification).toMatchObject({
            isValid: false,
        });
    });
});
