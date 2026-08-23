import { describe, expect, it } from 'vitest';

import {
    assertCanonicalGeneratedJson,
    parseCompactPublicKeyCatalogRegenerationArguments,
} from '#tools/ci/regenerate-compact-public-key-catalogs.js';

describe('compact public-key catalog regeneration', () => {
    it('accepts only update mode or the explicit check mode', () => {
        expect(parseCompactPublicKeyCatalogRegenerationArguments([])).toEqual({
            check: false,
        });
        expect(
            parseCompactPublicKeyCatalogRegenerationArguments(['--check']),
        ).toEqual({ check: true });
        expect(() =>
            parseCompactPublicKeyCatalogRegenerationArguments([
                '--check',
                '--check',
            ]),
        ).toThrow(/Usage/u);
        expect(() =>
            parseCompactPublicKeyCatalogRegenerationArguments(['--write']),
        ).toThrow(/Usage/u);
    });

    it('requires canonical single-line JSON with one source-file newline', () => {
        expect(() =>
            assertCanonicalGeneratedJson(
                Buffer.from('{"schema_version":1,"values":[3,2,1]}\n'),
                'test catalog',
            ),
        ).not.toThrow();
        expect(() =>
            assertCanonicalGeneratedJson(
                Buffer.from('{\n  "schema_version": 1\n}\n'),
                'test catalog',
            ),
        ).toThrow(/canonical single-line JSON/u);
        expect(() =>
            assertCanonicalGeneratedJson(
                Buffer.from('{"schema_version":1}'),
                'test catalog',
            ),
        ).toThrow(/exactly one newline/u);
        expect(() =>
            assertCanonicalGeneratedJson(
                Buffer.from('{"schema_version":1}\n\n'),
                'test catalog',
            ),
        ).toThrow(/exactly one newline/u);
    });
});
