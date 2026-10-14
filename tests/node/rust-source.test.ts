import { describe, expect, it } from 'vitest';

import {
    rustFunctionBody,
    stripRustComments,
} from '#tests/node/rust-source.js';

describe('Rust source reader', () => {
    it('removes line and nested block comments and keeps every literal', () => {
        const source = [
            'let a = "// kept"; // removed',
            'let b = \'/\'; /* removed /* nested */ removed */ let c = r#"/* kept */"#;',
            'let d = b"//"; let e = \'\\\'\'; let f = \'"\'; let g = "\\" // kept";',
        ].join('\n');
        expect(stripRustComments(source)).toBe(
            [
                'let a = "// kept";  ',
                'let b = \'/\';   let c = r#"/* kept */"#;',
                'let d = b"//"; let e = \'\\\'\'; let f = \'"\'; let g = "\\" // kept";',
            ].join('\n'),
        );
    });

    it('reads one function body past braces in literals and lifetimes', () => {
        const source = stripRustComments(
            [
                '// fn target() { decoy(); }',
                "fn target(x: char) -> &'static str {",
                '    if x == \'{\' { return "}"; }',
                '    let raw = r"{";',
                '    /* } */ "done"',
                '}',
                'fn after() {}',
            ].join('\n'),
        );
        expect(rustFunctionBody(source, 'target')).toBe(
            [
                '{',
                '    if x == \'{\' { return "}"; }',
                '    let raw = r"{";',
                '      "done"',
                '}',
            ].join('\n'),
        );
    });

    it('refuses a missing, commented-out, repeated or unclosed function', () => {
        expect(() =>
            rustFunctionBody(stripRustComments('// fn a() {}\nfn b() {}'), 'a'),
        ).toThrow('Expected one function a, found 0.');
        expect(() => rustFunctionBody('fn a() {} fn a() {}', 'a')).toThrow(
            'Expected one function a, found 2.',
        );
        expect(() => rustFunctionBody('fn a() { "}" ', 'a')).toThrow(
            'The function a does not close.',
        );
        expect(() => stripRustComments('let a = 1; /* /* */')).toThrow(
            'An unterminated block comment.',
        );
        expect(() => stripRustComments('let a = "open')).toThrow(
            'An unterminated string.',
        );
    });
});
