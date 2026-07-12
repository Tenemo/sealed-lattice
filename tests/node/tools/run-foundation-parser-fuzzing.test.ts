import { describe, expect, it } from 'vitest';

import {
    foundationParserFuzzToolchain,
    parseFuzzDurationSeconds,
    requireExpectedCargoFuzzVersion,
} from '#tools/ci/run-foundation-parser-fuzzing';

describe('foundation parser fuzz runner', () => {
    it('pins the manual toolchain and accepts the default or one positive duration', () => {
        expect(foundationParserFuzzToolchain).toEqual({
            cargoFuzzVersion: '0.13.2',
            rustToolchain: 'nightly-2026-06-15',
        });
        expect(parseFuzzDurationSeconds([])).toBe(60);
        expect(parseFuzzDurationSeconds(['--', '3600'])).toBe(3600);
    });

    it.each([
        ['0'],
        ['-1'],
        ['1.5'],
        ['one'],
        ['1', '2'],
        ['999999999999999999999999999999999999'],
    ])('refuses invalid duration arguments %j', (...arguments_) => {
        expect(() => parseFuzzDurationSeconds(arguments_)).toThrow();
    });

    it('requires the exact cargo-fuzz version', () => {
        expect(() =>
            requireExpectedCargoFuzzVersion('cargo-fuzz 0.13.2\n'),
        ).not.toThrow();
        expect(() =>
            requireExpectedCargoFuzzVersion('cargo-fuzz 0.13.1\n'),
        ).toThrow(/requires cargo-fuzz 0\.13\.2/u);
        expect(() => requireExpectedCargoFuzzVersion('')).toThrow(
            /no version output/u,
        );
    });
});
