import { describe, expect, it } from 'vitest';

import {
    RecentOutputBuffer,
    formatProgressDuration,
} from '#tools/ci/check-progress-reporter';

describe('check progress output buffers', () => {
    it('keeps recent complete and partial lines without ANSI control noise', () => {
        const recentOutput = new RecentOutputBuffer(3);

        recentOutput.append('Lint', '\u001B[32mfirst\u001B[39m\nsecond');
        recentOutput.append('Lint', ' continued\rthird\nfourth\n');

        expect(recentOutput.snapshot()).toEqual([
            'Lint > second continued',
            'Lint > third',
            'Lint > fourth',
        ]);
    });

    it('formats elapsed durations without fake precision for longer runs', () => {
        expect(formatProgressDuration(1_234)).toBe('1.2s');
        expect(formatProgressDuration(125_400)).toBe('2m05s');
    });
});
