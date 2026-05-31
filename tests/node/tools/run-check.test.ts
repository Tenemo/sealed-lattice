import { describe, expect, it } from 'vitest';

import {
    parseCheckArguments,
    redrawEnabledForProgressMode,
} from '#tools/ci/run-check';

describe('check runner arguments', () => {
    it('uses automatic progress rendering by default', () => {
        expect(parseCheckArguments([])).toEqual({
            progressMode: 'auto',
        });
    });

    it('accepts explicit progress rendering modes', () => {
        expect(parseCheckArguments(['--progress=always'])).toEqual({
            progressMode: 'always',
        });
        expect(parseCheckArguments(['--progress', 'never'])).toEqual({
            progressMode: 'never',
        });
    });

    it('rejects unknown check arguments and progress modes', () => {
        expect(() => parseCheckArguments(['--progress=sometimes'])).toThrow(
            'Usage: run-check.ts [--no-run-log] [--progress=auto|always|never].',
        );
        expect(() => parseCheckArguments(['--unknown'])).toThrow(
            'Usage: run-check.ts [--no-run-log] [--progress=auto|always|never].',
        );
    });

    it('does not redraw forced progress on a non-terminal stream', () => {
        expect(redrawEnabledForProgressMode('always', true)).toBe(true);
        expect(redrawEnabledForProgressMode('always', false)).toBe(false);
        expect(redrawEnabledForProgressMode('auto', false)).toBeUndefined();
        expect(redrawEnabledForProgressMode('never', true)).toBe(false);
    });
});
