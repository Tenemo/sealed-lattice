import { readFile } from 'node:fs/promises';

// Reads Rust source for tests that pin code in it. Comments are removed by a
// reader that keeps string and character literals intact, so commented-out
// code never satisfies a check.

// The index just past the string or character literal that starts at
// `index`, or the next index when none starts there.
const literalEnd = (source: string, index: number): number => {
    const character = source[index];
    const preceding = source[index - 1] ?? '';
    if ((character === 'r' || character === 'b') && /\w/u.test(preceding))
        return index + 1;
    const raw = /^b?r(#*)"/u.exec(source.slice(index, index + 260));
    if (raw !== null) {
        const terminator = '"' + raw[1];
        const end = source.indexOf(terminator, index + raw[0].length);
        if (end === -1) throw new Error('An unterminated raw string.');
        return end + terminator.length;
    }
    const start =
        character === 'b' &&
        (source[index + 1] === '"' || source[index + 1] === "'")
            ? index + 1
            : index;
    if (source[start] === '"') {
        let position = start + 1;
        while (source[position] !== '"') {
            if (position >= source.length)
                throw new Error('An unterminated string.');
            position += source[position] === '\\' ? 2 : 1;
        }
        return position + 1;
    }
    if (source[start] === "'") {
        // A character literal closes after one character or escape; any
        // other quote starts a lifetime or a loop label.
        const literal =
            /^'(?:\\(?:u\{[0-9a-fA-F]{1,6}\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'/u.exec(
                source.slice(start, start + 12),
            );
        if (literal !== null) return start + literal[0].length;
    }
    return index + 1;
};

const startsLiteral = (character: string) =>
    character === '"' ||
    character === "'" ||
    character === 'r' ||
    character === 'b';

// The source with every line and block comment replaced by one space. Block
// comments nest, as in Rust.
export const stripRustComments = (source: string): string => {
    let output = '';
    let index = 0;
    while (index < source.length) {
        if (source.startsWith('//', index)) {
            const end = source.indexOf('\n', index);
            index = end === -1 ? source.length : end;
            output += ' ';
        } else if (source.startsWith('/*', index)) {
            let depth = 1;
            index += 2;
            while (depth > 0) {
                if (index >= source.length)
                    throw new Error('An unterminated block comment.');
                if (source.startsWith('/*', index)) {
                    depth++;
                    index += 2;
                } else if (source.startsWith('*/', index)) {
                    depth--;
                    index += 2;
                } else index++;
            }
            output += ' ';
        } else {
            const end = startsLiteral(source[index])
                ? literalEnd(source, index)
                : index + 1;
            output += source.slice(index, end);
            index = end;
        }
    }
    return output;
};

// A repository Rust file without its comments.
export const readRustSource = async (repositoryPath: string) =>
    stripRustComments(
        await readFile(
            new URL('../../' + repositoryPath, import.meta.url),
            'utf8',
        ),
    );

// The initializer of the one constant with this name in comment-free
// source.
const constantInitializer = (source: string, name: string): string => {
    const definitions = [
        ...source.matchAll(
            new RegExp(`\\bconst\\s+${name}\\s*:[^=]+?=\\s*([^;]+);`, 'gu'),
        ),
    ];
    if (definitions.length !== 1)
        throw new Error(
            `Expected one constant ${name}, found ${String(definitions.length)}.`,
        );
    return definitions[0][1].trim();
};

const integerLiteral = (text: string, name: string): bigint => {
    const literal =
        /^(0x[0-9a-fA-F][0-9a-fA-F_]*|0o[0-7][0-7_]*|0b[01][01_]*|[0-9][0-9_]*)(?:[iu](?:8|16|32|64|128|size))?$/u.exec(
            text,
        );
    if (literal === null)
        throw new Error(`${name} is not an integer literal: ${text}`);
    return BigInt(literal[1].replace(/_/gu, ''));
};

// The value of the one integer constant with this name: a decimal,
// hexadecimal, octal or binary literal, or one such literal shifted left by
// another. Any other initializer is refused.
export const rustIntegerConstant = (source: string, name: string): bigint => {
    const initializer = constantInitializer(source, name);
    const shift = /^(\S+)\s*<<\s*(\S+)$/u.exec(initializer);
    return shift === null
        ? integerLiteral(initializer, name)
        : integerLiteral(shift[1], name) << integerLiteral(shift[2], name);
};

// The text of the one string or byte-string constant with this name. A
// literal with an escape is refused rather than interpreted.
export const rustStringConstant = (source: string, name: string): string => {
    const initializer = constantInitializer(source, name);
    const literal = /^b?"([^"\\]*)"$/u.exec(initializer);
    if (literal === null)
        throw new Error(
            `${name} is not a plain string literal: ${initializer}`,
        );
    return literal[1];
};

// The discriminants of the one enum with this name, by variant. Every variant
// must state its discriminant as an integer literal.
export const rustEnumCodes = (
    source: string,
    name: string,
): Readonly<Record<string, number>> => {
    const bodies = [
        ...source.matchAll(
            new RegExp(`\\benum\\s+${name}\\s*\\{([^}]*)\\}`, 'gu'),
        ),
    ];
    if (bodies.length !== 1)
        throw new Error(
            `Expected one enum ${name}, found ${String(bodies.length)}.`,
        );
    return Object.fromEntries(
        bodies[0][1]
            .split(',')
            .map((variant) => variant.trim())
            .filter((variant) => variant !== '')
            .map((variant) => {
                const parts = /^(\w+)\s*=\s*(\S+)$/u.exec(variant);
                if (parts === null)
                    throw new Error(
                        `The variant ${variant} of ${name} states no discriminant.`,
                    );
                return [
                    parts[1],
                    Number(integerLiteral(parts[2], `${name}::${parts[1]}`)),
                ];
            }),
    );
};

// The braced body of the one function with this name in comment-free
// source.
export const rustFunctionBody = (source: string, name: string): string => {
    const definitions = [
        ...source.matchAll(new RegExp('\\bfn\\s+' + name + '\\b', 'gu')),
    ];
    if (definitions.length !== 1)
        throw new Error(
            `Expected one function ${name}, found ${String(definitions.length)}.`,
        );
    const open = source.indexOf('{', definitions[0].index);
    let depth = 0;
    for (let index = open; index !== -1 && index < source.length;) {
        const character = source[index];
        if (character === '{') depth++;
        else if (character === '}' && --depth === 0)
            return source.slice(open, index + 1);
        index = startsLiteral(character)
            ? literalEnd(source, index)
            : index + 1;
    }
    throw new Error(`The function ${name} does not close.`);
};
