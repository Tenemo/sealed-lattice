import { describe, expect, it } from 'vitest';

import { transpileBridgeSource } from '../../../tools/ci/build-sdk-bridge';

describe('SDK bridge build helpers', () => {
    it('removes type-only workspace imports from the published bridge copy', () => {
        const outputText = transpileBridgeSource(`
            import type { TranscriptCoreFixture } from '@sealed-lattice/protocol';

            export const acceptsFixture = (_fixture: TranscriptCoreFixture): boolean => true;
        `);

        expect(outputText).toContain('export const acceptsFixture');
        expect(outputText).not.toContain('@sealed-lattice/protocol');
    });
});
