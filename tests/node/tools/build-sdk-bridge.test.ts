import { describe, expect, it } from 'vitest';

import {
    transpileBridgeSource,
    transpileSdkInternalSource,
} from '../../../tools/ci/build-sdk-bridge';

describe('SDK bridge build helpers', () => {
    it('removes type-only workspace imports from the published bridge copy', () => {
        const outputText = transpileBridgeSource(`
            import type { TranscriptCoreFixture } from '@sealed-lattice/protocol';

            export const acceptsFixture = (_fixture: TranscriptCoreFixture): boolean => true;
        `);

        expect(outputText).toContain('export const acceptsFixture');
        expect(outputText).not.toContain('@sealed-lattice/protocol');
    });

    it('transpiles selected protocol runtime modules for SDK vendoring', () => {
        const outputText = transpileSdkInternalSource(
            `
                import type { ThresholdProfile } from './types.js';

                export const isMandatory = (profile: ThresholdProfile): boolean =>
                    profile.rosterProfileKind === 'MandatoryN20';
            `,
            'packages/protocol/src/protocol-shell/thresholds.ts',
        );

        expect(outputText).toContain('export const isMandatory');
        expect(outputText).not.toContain('ThresholdProfile');
    });
});
