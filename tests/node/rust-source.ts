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
