import { readdir, readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
    rustEnumCodes,
    rustIntegerConstant,
    stripRustComments,
} from '#tests/node/rust-source.js';

type Codes = Readonly<Record<string, number>>;

const repositoryRoot = new URL('../../../../../', import.meta.url);

// The texts of the files with the extension below a directory.
const sourceTexts = async (
    directory: URL,
    extension: string,
): Promise<string[]> => {
    const texts: string[] = [];
    for (const entry of await readdir(directory, { withFileTypes: true }))
        if (entry.isDirectory())
            texts.push(
                ...(await sourceTexts(
                    new URL(entry.name + '/', directory),
                    extension,
                )),
            );
        else if (entry.name.endsWith(extension))
            texts.push(await readFile(new URL(entry.name, directory), 'utf8'));
    return texts;
};

// Every crate's own Rust sources, without comments, as one text.
const moduleSource = async (): Promise<string> => {
    const crates = new URL('crates/protocol-research/', repositoryRoot);
    const texts: string[] = [];
    for (const entry of await readdir(crates, { withFileTypes: true }))
        if (entry.isDirectory())
            try {
                texts.push(
                    ...(await sourceTexts(
                        new URL(entry.name + '/src/', crates),
                        '.rs',
                    )),
                );
            } catch (error) {
                if ((error as NodeJS.ErrnoException).code !== 'ENOENT')
                    throw error;
            }
    return texts.map(stripRustComments).join('\n');
};

const workerTexts = () =>
    sourceTexts(
        new URL('packages/sdk/src/participant/worker/', repositoryRoot),
        '.ts',
    );

const withoutComments = (text: string) => text.replace(/\/\/.*$/gm, '');

const lowerFirst = (name: string) => name[0].toLowerCase() + name.slice(1);

// The codes of a worker table body whose every entry names its code.
const tableCodes = (body: string): Codes =>
    Object.fromEntries(
        withoutComments(body)
            .split(',')
            .map((part) => part.trim())
            .filter((part) => part.length > 0)
            .map((part) => {
                const match = /^(\w+): (\d+)$/.exec(part);
                if (match === null)
                    throw new Error('An entry names no code: ' + part);
                return [match[1], Number(match[2])];
            }),
    );

// The codes of a module enum, by the worker's name for each variant.
const enumCodes = (source: string, name: string): Codes =>
    Object.fromEntries(
        Object.entries(rustEnumCodes(source, name)).map(([variant, code]) => [
            lowerFirst(variant),
            code,
        ]),
    );

// The single match of a pattern across the texts.
const onlyMatch = (texts: readonly string[], pattern: RegExp) => {
    const matches = texts.flatMap((text) => [...text.matchAll(pattern)]);
    expect(matches, pattern.source).toHaveLength(1);
    return matches[0];
};

const camelCase = (name: string) =>
    name
        .toLowerCase()
        .replace(/_(\w)/g, (_, letter: string) => letter.toUpperCase());

describe('participant module operation codes', () => {
    it('gives every worker code table the names and codes of its module enum', async () => {
        const source = await moduleSource();
        // Every enum the module declares with its operation-codes macro.
        const operations = new Map(
            [
                ...source.matchAll(
                    /\boperation_codes!\s*\{\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?enum\s+(\w+)/gu,
                ),
            ].map(([, name]) => [name, enumCodes(source, name)] as const),
        );
        expect(operations.size).toBe(
            source.match(/\boperation_codes!/gu)?.length,
        );
        // Every worker table of a module command's operations or steps or
        // of the module's purposes.
        const texts = await workerTexts();
        const tables = new Map(
            texts.flatMap((text) =>
                [
                    ...text.matchAll(
                        /^(?:export )?const (\w+(?:Operation|Step|Purpose)) = \{([^}]*)\} as const;/gm,
                    ),
                ].map(([, table, body]) => [table, tableCodes(body)] as const),
            ),
        );
        expect(tables.size).toBe(
            texts.flatMap((text) => [
                ...text.matchAll(
                    /^(?:export )?const \w+(?:Operation|Step|Purpose) = \{/gmu,
                ),
            ]).length,
        );
        expect(operations.size).toBeGreaterThan(0);
        for (const name of operations.keys())
            expect(tables.has(lowerFirst(name)), name).toBe(true);
        for (const [table, codes] of tables) {
            const name = table[0].toUpperCase() + table.slice(1);
            expect(codes, table).toEqual(
                operations.get(name) ?? enumCodes(source, name),
            );
        }
    });

    it('stages every enrollment record under the worker data kind of its name', async () => {
        const source = await moduleSource();
        const texts = await workerTexts();
        const moduleKinds = Object.fromEntries(
            [
                ...onlyMatch(
                    [source],
                    /pub mod data_kind \{([^}]*)\}/g,
                )[1].matchAll(/pub const (\w+): u32 = (\d+);/g),
            ].map((match) => [camelCase(match[1]), Number(match[2])]),
        );
        const workerKinds = tableCodes(
            onlyMatch(
                texts,
                /^export const dataKind = \{([^}]*)\} as const;/gm,
            )[1],
        );
        expect(Object.keys(moduleKinds).length).toBeGreaterThan(0);
        for (const [name, kind] of Object.entries(moduleKinds))
            expect(workerKinds[name], name).toBe(kind);
        // The worker routes the staged capsule keys by their own kind, which
        // no record shares.
        const stagedDataKeys = Number(
            onlyMatch(texts, /const stagedDataKeys = (\d+);/g)[1],
        );
        expect(rustIntegerConstant(source, 'DATA_KEYS')).toBe(
            BigInt(stagedDataKeys),
        );
        expect(Object.values(workerKinds)).not.toContain(stagedDataKeys);
    });
});
