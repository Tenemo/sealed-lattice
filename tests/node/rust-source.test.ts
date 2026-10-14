import { describe, expect, it } from 'vitest';

import {
    rustEnumCodes,
    rustFunctionBody,
    rustIntegerConstant,
    rustStringConstant,
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

    it('reads integer, string and enum constants defined exactly once', () => {
        const source = stripRustComments(
            [
                '// const LIMIT: usize = 7;',
                'pub(crate) const LIMIT: usize = 16_384;',
                'const SHIFTED: usize = 1 << 14;',
                'const MASK: u64 = 0xFF_FFu64;',
                'const TABLE: [u8; 2] = [1, 2];',
                'const PURPOSE: &[u8] = b"sealed-lattice/offer";',
                'pub enum Step {',
                '    /// The first step.',
                '    Begin = 1,',
                '    End = 0x10,',
                '}',
            ].join('\n'),
        );
        expect(rustIntegerConstant(source, 'LIMIT')).toBe(16_384n);
        expect(rustIntegerConstant(source, 'SHIFTED')).toBe(16_384n);
        expect(rustIntegerConstant(source, 'MASK')).toBe(0xffffn);
        expect(rustStringConstant(source, 'PURPOSE')).toBe(
            'sealed-lattice/offer',
        );
        expect(rustEnumCodes(source, 'Step')).toEqual({ Begin: 1, End: 16 });
    });

    it('refuses an absent, repeated or computed constant and an enum variant without a code', () => {
        expect(() => rustIntegerConstant('const A: u8 = 1;', 'B')).toThrow(
            'Expected one constant B, found 0.',
        );
        expect(() =>
            rustIntegerConstant('const A: u8 = 1; const A: u8 = 1;', 'A'),
        ).toThrow('Expected one constant A, found 2.');
        expect(() =>
            rustIntegerConstant('const A: usize = B * 2;', 'A'),
        ).toThrow('A is not an integer literal: B * 2');
        expect(() =>
            rustIntegerConstant('const A: [u8; 2] = [1, 2];', 'A'),
        ).toThrow('A is not an integer literal');
        expect(() =>
            rustStringConstant('const A: &str = "tab\\t";', 'A'),
        ).toThrow('A is not a plain string literal');
        expect(() => rustEnumCodes('enum E { A = 1, B }', 'E')).toThrow(
            'The variant B of E states no discriminant.',
        );
        expect(() => rustEnumCodes('enum F { A = 1 }', 'E')).toThrow(
            'Expected one enum E, found 0.',
        );
    });
});
